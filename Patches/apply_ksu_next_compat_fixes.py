#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import sys


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def insert_after(text: str, marker: str, block: str) -> str:
    if block.strip() in text:
        return text
    idx = text.find(marker)
    if idx == -1:
        return text
    return text[: idx + len(marker)] + block + text[idx + len(marker) :]


def replace_block(text: str, pattern: str, replacement: str) -> str:
    new_text, count = re.subn(
        pattern, lambda _m: replacement, text, count=1, flags=re.S
    )
    return new_text if count else text


def edit_file(path: Path, editor) -> bool:
    if not path.exists():
        print(f"skip: {path} not found")
        return False
    before = read_text(path)
    after = editor(before)
    if after != before:
        write_text(path, after)
        print(f"updated: {path}")
        return True
    print(f"nochange: {path}")
    return False


def edit_util_h(text: str) -> str:
    text = insert_after(
        text,
        "#include <linux/types.h>\n",
        "#include <linux/uaccess.h>\n#include <linux/version.h>\n",
    )
    text = insert_after(
        text,
        "#include <linux/version.h>\n",
        "\n#ifndef TWA_RESUME\n#define TWA_RESUME true\n#endif\n",
    )
    shim = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
static inline long strncpy_from_user_nofault(char *dst,
                                             const char __user *src,
                                             long count)
{
    return strncpy_from_user(dst, src, count);
}

static inline size_t copy_from_user_nofault(void *dst,
                                            const void __user *src,
                                            size_t size)
{
    return copy_from_user(dst, src, size);
}

static inline size_t copy_to_user_nofault(void __user *dst,
                                          const void *src,
                                          size_t size)
{
    return copy_to_user(dst, src, size);
}
#endif
"""
    if "strncpy_from_user_nofault" not in text:
        text = re.sub(
            r"(?m)^(bool try_set_access_flag\(unsigned long addr\);)",
            shim + "\n\\1",
            text,
            count=1,
        )
    return text


def edit_ksu_h(text: str) -> str:
    return insert_after(
        text,
        "#define EVENT_MODULE_MOUNTED 3\n",
        "\n#ifndef TWA_RESUME\n#define TWA_RESUME true\n#endif\n",
    )


def edit_allowlist_c(text: str) -> str:
    text = insert_after(
        text,
        "#include <linux/compiler_types.h>\n",
        "#include <linux/sched/task.h>\n",
    )
    text = insert_after(
        text,
        "#include <linux/sched/task.h>\n",
        "\n#ifndef TWA_RESUME\n#define TWA_RESUME true\n#endif\n",
    )
    return text


def edit_setuid_hook_c(text: str) -> str:
    return insert_after(
        text,
        '#include "kernel_umount.h"\n',
        "\n#ifndef TWA_RESUME\n#define TWA_RESUME true\n#endif\n",
    )


def edit_sucompat_c(text: str) -> str:
    return text.replace("#include <linux/pgtable.h>", "#include <asm/pgtable.h>")


def edit_util_c(text: str) -> str:
    return text.replace("#include <linux/pgtable.h>", "#include <asm/pgtable.h>")


def edit_pkg_observer_c(text: str) -> str:
    if "ksu_handle_inode_event" in text and "ksu_handle_event" not in text:
        new_sig = (
            "static int ksu_handle_event(struct fsnotify_group *group, struct inode *inode,\n"
            "                            u32 mask, const void *data, int data_is,\n"
            "                            const struct qstr *file_name, u32 cookie,\n"
            "                            struct fsnotify_iter_info *iter_info)\n"
            "{"
        )
        text = re.sub(
            r"static int ksu_handle_inode_event\s*\([\s\S]*?\)\n\{",
            new_sig,
            text,
            count=1,
        )
        text = text.replace("ksu_handle_inode_event", "ksu_handle_event")
        if "ksu_handle_event" in text and "(void)group;" not in text:
            text = text.replace(
                new_sig,
                new_sig
                + "\n    (void)group;\n"
                  "    (void)inode;\n"
                  "    (void)data;\n"
                  "    (void)data_is;\n"
                  "    (void)cookie;\n"
                  "    (void)iter_info;\n",
            )
    text = text.replace(
        ".handle_inode_event = ksu_handle_event,", ".handle_event = ksu_handle_event,"
    )
    text = text.replace(
        ".handle_inode_event = ksu_handle_inode_event,",
        ".handle_event = ksu_handle_event,",
    )
    text = text.replace(
        ".handle_inode_event = ksu_handle_event", ".handle_event = ksu_handle_event"
    )
    return text


def edit_app_profile_c(text: str) -> str:
    text = text.replace(
        "void seccomp_filter_release(struct task_struct *tsk);\n",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)\n"
        "void seccomp_filter_release(struct task_struct *tsk);\n"
        "#endif\n",
    )
    text = re.sub(
        r"^(\s*)atomic_set\(&current->seccomp\.filter_count, 0\);\s*$",
        r"\1#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)\n"
        r"\1atomic_set(&current->seccomp.filter_count, 0);\n"
        r"\1#endif",
        text,
        flags=re.M,
    )
    text = text.replace(
        "    seccomp_filter_release(fake);\n",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)\n"
        "    seccomp_filter_release(fake);\n"
        "#else\n"
        "    put_seccomp_filter(fake);\n"
        "#endif\n",
    )
    return text


def edit_seccomp_cache_c(text: str) -> str:
    text = insert_after(text, "#include <linux/seccomp.h>\n", "#include <asm/unistd.h>\n")
    return insert_after(
        text,
        '#include "seccomp_cache.h"\n',
        "\n#ifndef SECCOMP_ARCH_NATIVE_NR\n#define SECCOMP_ARCH_NATIVE_NR NR_syscalls\n#endif\n",
    )


def edit_file_wrapper_c(text: str) -> str:
    stub = (
        "\n#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)\n"
        "static inline int security_inode_init_security_anon(struct inode *inode,\n"
        "                                                    struct qstr *name,\n"
        "                                                    const struct inode *dir)\n"
        "{\n"
        "    return 0;\n"
        "}\n"
        "#endif\n"
    )
    return insert_after(text, '#include "objsec.h"\n', stub)


def edit_rules_c(text: str) -> str:
    pattern = r"static struct policydb \*get_policydb\([^)]*\)\n\{\n.*?\n\}"
    replacement = (
        "static struct policydb *get_policydb(void)\n"
        "{\n"
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)\n"
        "    struct selinux_policy *policy = selinux_state.policy;\n"
        "    return &policy->policydb;\n"
        "#else\n"
        "    return &selinux_state.ss->policydb;\n"
        "#endif\n"
        "}"
    )
    return replace_block(text, pattern, replacement)


def edit_sepolicy_c(text: str) -> str:
    text = text.replace(
        "#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)\n"
        "#define symtab_search(s, name) hashtab_search((s)->table, name)\n"
        "#define symtab_insert(s, name, datum) hashtab_insert((s)->table, name, datum)\n"
        "#endif\n",
        "#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)\n"
        "#ifndef symtab_search\n"
        "#define symtab_search(s, name) hashtab_search((s)->table, name)\n"
        "#define symtab_insert(s, name, datum) hashtab_insert((s)->table, name, datum)\n"
        "#endif\n"
        "#endif\n",
    )

    replacement = r"""// 5.9.0 : static inline int hashtab_insert(struct hashtab *h, void *key, void
// *datum, struct hashtab_key_params key_params) 5.8.0: int
// hashtab_insert(struct hashtab *h, void *k, void *d);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
static u32 filenametr_hash(const void *k)
{
    const struct filename_trans_key *ft = k;
    unsigned long hash;
    unsigned int byte_num;
    unsigned char focus;

    hash = ft->ttype ^ ft->tclass;

    byte_num = 0;
    while ((focus = ft->name[byte_num++]))
        hash = partial_name_hash(focus, hash);
    return hash;
}

static int filenametr_cmp(const void *k1, const void *k2)
{
    const struct filename_trans_key *ft1 = k1;
    const struct filename_trans_key *ft2 = k2;
    int v;

    v = ft1->ttype - ft2->ttype;
    if (v)
        return v;

    v = ft1->tclass - ft2->tclass;
    if (v)
        return v;

    return strcmp(ft1->name, ft2->name);
}

static const struct hashtab_key_params filenametr_key_params = {
    .hash = filenametr_hash,
    .cmp = filenametr_cmp,
};
#endif

static bool add_filename_trans(struct policydb *db, const char *s,
                               const char *t, const char *c, const char *d,
                               const char *o)
{
    struct type_datum *src, *tgt, *def;
    struct class_datum *cls;

    src = symtab_search(&db->p_types, s);
    if (src == NULL) {
        pr_warn("source type %s does not exist\n", s);
        return false;
    }
    tgt = symtab_search(&db->p_types, t);
    if (tgt == NULL) {
        pr_warn("target type %s does not exist\n", t);
        return false;
    }
    cls = symtab_search(&db->p_classes, c);
    if (cls == NULL) {
        pr_warn("class %s does not exist\n", c);
        return false;
    }
    def = symtab_search(&db->p_types, d);
    if (def == NULL) {
        pr_warn("default type %s does not exist\n", d);
        return false;
    }

    struct filename_trans_key key;
    key.ttype = tgt->value;
    key.tclass = cls->value;
    key.name = (char *)o;

    struct filename_trans_datum *last = NULL;

    struct filename_trans_datum *trans = policydb_filenametr_search(db, &key);
    while (trans) {
        if (ebitmap_get_bit(&trans->stypes, src->value - 1)) {
            // Duplicate, overwrite existing data and return
            trans->otype = def->value;
            return true;
        }
        if (trans->otype == def->value)
            break;
        last = trans;
        trans = trans->next;
    }

    if (trans == NULL) {
        trans = (struct filename_trans_datum *)kcalloc(1, sizeof(*trans),
                                                       GFP_ATOMIC);
        struct filename_trans_key *new_key =
            (struct filename_trans_key *)kzalloc(sizeof(*new_key), GFP_ATOMIC);
        *new_key = key;
        new_key->name = kstrdup(key.name, GFP_ATOMIC);
        trans->next = last;
        trans->otype = def->value;
        hashtab_insert(&db->filename_trans, new_key, trans,
                       filenametr_key_params);
    }

    db->compat_filename_trans_count++;
    return ebitmap_set_bit(&trans->stypes, src->value - 1, 1) == 0;
}
#else
static bool add_filename_trans(struct policydb *db, const char *s,
                               const char *t, const char *c, const char *d,
                               const char *o)
{
    struct type_datum *src, *tgt, *def;
    struct class_datum *cls;
    struct filename_trans key;
    struct filename_trans_datum *trans;
    struct filename_trans *new_key;

    src = symtab_search(&db->p_types, s);
    if (src == NULL) {
        pr_warn("source type %s does not exist\n", s);
        return false;
    }
    tgt = symtab_search(&db->p_types, t);
    if (tgt == NULL) {
        pr_warn("target type %s does not exist\n", t);
        return false;
    }
    cls = symtab_search(&db->p_classes, c);
    if (cls == NULL) {
        pr_warn("class %s does not exist\n", c);
        return false;
    }
    def = symtab_search(&db->p_types, d);
    if (def == NULL) {
        pr_warn("default type %s does not exist\n", d);
        return false;
    }

    key.stype = src->value;
    key.ttype = tgt->value;
    key.tclass = cls->value;
    key.name = (char *)o;

    trans = hashtab_search(db->filename_trans, &key);
    if (trans) {
        trans->otype = def->value;
        return true;
    }

    trans = (struct filename_trans_datum *)kzalloc(sizeof(*trans), GFP_ATOMIC);
    if (!trans) {
        pr_err("alloc filename_trans_datum failed.\n");
        return false;
    }
    trans->otype = def->value;

    new_key = (struct filename_trans *)kzalloc(sizeof(*new_key), GFP_ATOMIC);
    if (!new_key) {
        kfree(trans);
        return false;
    }
    new_key->stype = key.stype;
    new_key->ttype = key.ttype;
    new_key->tclass = key.tclass;
    new_key->name = kstrdup(key.name, GFP_ATOMIC);
    if (!new_key->name) {
        kfree(new_key);
        kfree(trans);
        return false;
    }

    if (hashtab_insert(db->filename_trans, new_key, trans)) {
        kfree((char *)new_key->name);
        kfree(new_key);
        kfree(trans);
        return false;
    }

    if (ebitmap_set_bit(&db->filename_trans_ttypes, new_key->ttype, 1))
        return false;

    return true;
}
#endif

static bool add_genfscon"""

    pattern = r"// 5\.9\.0[\s\S]*?static bool add_genfscon"
    text = replace_block(text, pattern, replacement)
    return text


def edit_kernel_umount_h(text: str) -> str:
    return insert_after(
        text,
        "int ksu_handle_umount(uid_t old_uid, uid_t new_uid);\n",
        "void ksu_try_umount(const char *mnt, bool check_uid, int flags, uid_t uid);\n",
    )


def edit_kernel_umount_c(text: str) -> str:
    text = insert_after(text, "#include <linux/types.h>\n", "#include <linux/limits.h>\n#include <linux/uaccess.h>\n")
    text = insert_after(
        text,
        "#include <linux/uaccess.h>\n",
        "\n#ifndef TWA_RESUME\n#define TWA_RESUME true\n#endif\n",
    )
    text = text.replace(
        "extern int path_umount(struct path *path, int flags);\n",
        "extern int ksys_umount(char __user *name, int flags);\n",
    )
    old_func = r"static void ksu_umount_mnt\([\s\S]*?\n}\n"
    new_func = (
        "static void ksu_umount_mnt(struct path *path, int flags)\n"
        "{\n"
        "    char *buf;\n"
        "    char *p;\n"
        "    mm_segment_t old_fs;\n"
        "    int err;\n\n"
        "    buf = kmalloc(PATH_MAX, GFP_ATOMIC);\n"
        "    if (!buf)\n"
        "        return;\n\n"
        "    p = d_path(path, buf, PATH_MAX);\n"
        "    if (IS_ERR(p)) {\n"
        "        kfree(buf);\n"
        "        return;\n"
        "    }\n\n"
        "    old_fs = get_fs();\n"
        "    set_fs(KERNEL_DS);\n"
        "    err = ksys_umount((char __user *)p, flags);\n"
        "    set_fs(old_fs);\n"
        "    if (err) {\n"
        "        pr_info(\"umount %s failed: %d\\n\", p, err);\n"
        "    }\n"
        "    kfree(buf);\n"
        "}\n"
    )
    text = replace_block(text, old_func, new_func)
    if "void ksu_try_umount(" not in text:
        add_func = (
            "void ksu_try_umount(const char *mnt, bool check_uid, int flags, uid_t uid)\n"
            "{\n"
            "    if (check_uid && !ksu_uid_should_umount(uid))\n"
            "        return;\n"
            "    try_umount(mnt, flags);\n"
            "}\n\n"
        )
        text = text.replace("struct umount_tw {", add_func + "struct umount_tw {", 1)
    return text


def edit_su_mount_ns_c(text: str) -> str:
    text = insert_after(text, "#include <linux/task_work.h>\n", "#include <linux/uaccess.h>\n")
    text = text.replace(
        "extern int path_mount(const char *dev_name, struct path *path,\n"
        "                      const char *type_page, unsigned long flags,\n"
        "                      void *data_page);\n",
        "extern long ksys_mount(const char __user *dev_name,\n"
        "                       const char __user *dir_name,\n"
        "                       const char __user *type,\n"
        "                       unsigned long flags,\n"
        "                       const void __user *data);\n",
    )
    old_func = r"static void ksu_mnt_ns_individual\([\s\S]*?\n}\n"
    new_func = (
        "static void ksu_mnt_ns_individual(void)\n"
        "{\n"
        "    long ret = ksys_unshare(CLONE_NEWNS);\n"
        "    if (ret) {\n"
        "        pr_warn(\"call ksys_unshare failed: %ld\\n\", ret);\n"
        "        return;\n"
        "    }\n\n"
        "    // make root mount private\n"
        "    struct path root_path;\n"
        "    char *root_buf = NULL;\n"
        "    char *root = NULL;\n"
        "    mm_segment_t old_fs;\n\n"
        "    get_fs_root(current->fs, &root_path);\n"
        "    root_buf = kmalloc(PATH_MAX, GFP_KERNEL);\n"
        "    if (root_buf) {\n"
        "        root = d_path(&root_path, root_buf, PATH_MAX);\n"
        "        if (IS_ERR(root))\n"
        "            root = NULL;\n"
        "    }\n\n"
        "    old_fs = get_fs();\n"
        "    set_fs(KERNEL_DS);\n"
        "    int pm_ret = ksys_mount(NULL, root ? root : \"/\", NULL,\n"
        "                            MS_PRIVATE | MS_REC, NULL);\n"
        "    set_fs(old_fs);\n\n"
        "    kfree(root_buf);\n"
        "    path_put(&root_path);\n\n"
        "    if (pm_ret < 0) {\n"
        "        pr_err(\"failed to make root private, err: %d\\n\", pm_ret);\n"
        "    }\n"
        "}\n"
    )
    return replace_block(text, old_func, new_func)


def edit_susfs_c(text: str) -> str:
    if "void susfs_try_umount_all" in text:
        return text
    pattern = r"(void susfs_try_umount\(uid_t target_uid\)[\s\S]*?\n}\n)"
    def repl(match: re.Match) -> str:
        return match.group(1) + "\nvoid susfs_try_umount_all(uid_t uid)\n{\n    susfs_try_umount(uid);\n}\n"
    new_text, count = re.subn(pattern, repl, text, count=1, flags=re.S)
    return new_text if count else text


def edit_cvp_hfi(text: str) -> str:
    return text.replace(
        "inst = cvp_get_inst_from_id(core, (unsigned int)session_id);",
        "inst = cvp_get_inst_from_id(core, (unsigned int)(uintptr_t)session_id);",
    )


def edit_read_write_c(text: str) -> str:
    if "ksu_vfs_read_hook" not in text:
        return text
    text = text.replace("\\n__attribute__", "\n__attribute__")
    text = insert_after(
        text,
        "#include <linux/fs.h>\n",
        "#include <linux/kconfig.h>\n",
    )
    text = re.sub(
        r"(?m)^\\s*#ifdef\\s+CONFIG_KSU\\s*$",
        "#if IS_BUILTIN(CONFIG_KSU)",
        text,
    )
    text = text.replace(
        "#if defined(CONFIG_KSU) && !defined(CONFIG_KSU_MODULE)",
        "#if IS_BUILTIN(CONFIG_KSU)",
    )
    text = text.replace(
        "extern bool ksu_vfs_read_hook __read_mostly;",
        "__attribute__((weak)) bool ksu_vfs_read_hook __read_mostly;",
    )
    text = re.sub(
        r"extern int ksu_handle_vfs_read\\(([\\s\\S]*?)\\);",
        "__attribute__((weak)) int ksu_handle_vfs_read(\\1)\n{\n\treturn 0;\n}",
        text,
        count=1,
        flags=re.S,
    )
    if "ksu_handle_vfs_read(" in text and "__attribute__((weak)) int ksu_handle_vfs_read" not in text:
        text = insert_after(
            text,
            "#include <linux/kconfig.h>\n",
            "\n__attribute__((weak)) int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,\n"
            "\t\t\t  size_t *count_ptr, loff_t **pos)\n"
            "{\n"
            "\treturn 0;\n"
            "}\n",
        )
    return text


def edit_input_c(text: str) -> str:
    if "ksu_input_hook" not in text:
        return text
    text = text.replace("\\n__attribute__", "\n__attribute__")
    text = insert_after(
        text,
        "#include <linux/module.h>\n",
        "#include <linux/kconfig.h>\n",
    )
    text = re.sub(
        r"(?m)^\\s*#ifdef\\s+CONFIG_KSU\\s*$",
        "#if IS_BUILTIN(CONFIG_KSU)",
        text,
    )
    text = text.replace(
        "#if defined(CONFIG_KSU) && !defined(CONFIG_KSU_MODULE)",
        "#if IS_BUILTIN(CONFIG_KSU)",
    )
    text = text.replace(
        "extern bool ksu_input_hook __read_mostly;",
        "__attribute__((weak)) bool ksu_input_hook __read_mostly;",
    )
    text = re.sub(
        r"extern int ksu_handle_input_handle_event\\(([\\s\\S]*?)\\);",
        "__attribute__((weak)) int ksu_handle_input_handle_event(\\1)\n{\n\treturn 0;\n}",
        text,
        count=1,
        flags=re.S,
    )
    return text


def edit_supercalls_c(text: str) -> str:
    compat = (
        "\n#ifndef anon_inode_getfd_secure\n"
        "#define anon_inode_getfd_secure(name, fops, priv, flags, ctx) \\\n"
        "    anon_inode_getfd(name, fops, priv, flags)\n"
        "#endif\n"
        "#ifndef getfd_secure\n"
        "#define getfd_secure anon_inode_getfd_secure\n"
        "#endif\n"
    )
    return insert_after(text, "#include <linux/anon_inodes.h>\n", compat)


def edit_sia8152(text: str) -> str:
    text = insert_after(text, "#include <linux/device.h>\n", "#include <linux/slab.h>\n")
    marker = "\n\nconst struct sia81xx_opt_if"
    start = text.find("static void sia8152_check_trimming")
    end = text.find(marker, start) if start != -1 else -1
    if start == -1 or end == -1:
        return text
    func = text[start:end]
    func = func.replace("uint8_t vals[reg_num] = {0};", "uint8_t *vals = NULL;")
    if "kcalloc(" not in func:
        func = func.replace(
            "uint8_t crc = 0;\n",
            "uint8_t crc = 0;\n\n\tvals = kcalloc(reg_num, sizeof(*vals), GFP_KERNEL);\n\tif (!vals)\n\t\treturn;\n",
        )
    func = re.sub(r"\breturn\s*;\s*", "goto out_free;\n", func)
    func = func.replace("if (!vals)\n\t\tgoto out_free;\n", "if (!vals)\n\t\treturn;\n")
    if "out_free:" not in func:
        insert_at = func.rfind("\n}")
        if insert_at != -1:
            func = func[:insert_at] + "\n\nout_free:\n\tkfree(vals);\n" + func[insert_at:]
    return text[:start] + func + text[end:]


def edit_sia8152s(text: str) -> str:
    text = insert_after(text, "#include <linux/device.h>\n", "#include <linux/slab.h>\n")
    marker = "\n\nconst struct sia81xx_opt_if"
    start = text.find("void sia8152s_check_trimming")
    end = text.find(marker, start) if start != -1 else -1
    if start == -1 or end == -1:
        return text
    func = text[start:end]
    func = func.replace("uint8_t vals[reg_num] = {0};", "uint8_t *vals = NULL;")
    if "kcalloc(" not in func:
        func = func.replace(
            "uint8_t crc = 0;\n",
            "uint8_t crc = 0;\n\n\tvals = kcalloc(reg_num, sizeof(*vals), GFP_KERNEL);\n\tif (!vals)\n\t\treturn;\n",
        )
    func = re.sub(r"\breturn\s*;\s*", "goto out_free;\n", func)
    func = func.replace("if (!vals)\n\t\tgoto out_free;\n", "if (!vals)\n\t\treturn;\n")
    if "out_free:" not in func:
        insert_at = func.rfind("\n}")
        if insert_at != -1:
            func = func[:insert_at] + "\n\nout_free:\n\tkfree(vals);\n" + func[insert_at:]
    return text[:start] + func + text[end:]


def edit_sia8159(text: str) -> str:
    if "SIA8159_TRIMMING_REG_NUM" not in text:
        text = text.replace(
            "#define SIA8159_WRITEABLE_REG_NUM\t\t\t(10)\n",
            "#define SIA8159_WRITEABLE_REG_NUM\t\t\t(10)\n"
            "#define SIA8159_TRIMMING_REG_NUM\t\t\t\\\n"
            "\t(SIA8159_REG_TRIMMING_END - SIA8159_REG_TRIMMING_BEGIN + 1)\n",
        )
    text = text.replace(
        "static const uint32_t reg_num = \n\t\tSIA8159_REG_TRIMMING_END - SIA8159_REG_TRIMMING_BEGIN + 1;\n"
        "static const char defaults[reg_num] = {0x76, 0x66, 0x70};\n"
        "uint8_t vals[reg_num] = {0};\n",
        "const uint32_t reg_num = SIA8159_TRIMMING_REG_NUM;\n"
        "static const char defaults[SIA8159_TRIMMING_REG_NUM] = {0x76, 0x66, 0x70};\n"
        "uint8_t vals[SIA8159_TRIMMING_REG_NUM] = {0};\n",
    )
    return text


def edit_tfa98xx(text: str) -> str:
    return text.replace(
        "const int size = 1024;\n\tchar buffer[size];",
        "char buffer[1024];\n\tconst int size = sizeof(buffer);",
    )


def edit_uboot_log(text: str) -> str:
    text = text.replace("int ubootback_thread_fn()", "int ubootback_thread_fn(void *data)")
    if "(void)data;" not in text:
        text = text.replace(
            "u64 seq =0;\n",
            "u64 seq =0;\n\n\t(void)data;\n",
        )
    return text


def edit_oplus_display_panel(text: str) -> str:
    return text.replace(
        "void __exit oplus_display_panel_exit()",
        "void __exit oplus_display_panel_exit(void)",
    )


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")

    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/util.h", edit_util_h)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/ksu.h", edit_ksu_h)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/allowlist.c", edit_allowlist_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/setuid_hook.c", edit_setuid_hook_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/sucompat.c", edit_sucompat_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/util.c", edit_util_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/pkg_observer.c", edit_pkg_observer_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/app_profile.c", edit_app_profile_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/seccomp_cache.c", edit_seccomp_cache_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/file_wrapper.c", edit_file_wrapper_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/selinux/rules.c", edit_rules_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/selinux/sepolicy.c", edit_sepolicy_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/kernel_umount.h", edit_kernel_umount_h)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/kernel_umount.c", edit_kernel_umount_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/su_mount_ns.c", edit_su_mount_ns_c)
    edit_file(root / "kernel/msm-5.4/fs/susfs.c", edit_susfs_c)
    edit_file(root / "kernel/msm-5.4/drivers/kernelsu/supercalls.c", edit_supercalls_c)
    edit_file(root / "kernel/msm-5.4/fs/read_write.c", edit_read_write_c)
    edit_file(root / "kernel/msm-5.4/drivers/input/input.c", edit_input_c)

    edit_file(
        root / "kernel/msm-5.4/drivers/media/platform/msm/cvp/hfi_response_handler.c",
        edit_cvp_hfi,
    )

    for rel in (
        "kernel/msm-5.4/techpack/audio/asoc/codecs/sia81xx/sia8152_regs.c",
        "techpack/audio/asoc/codecs/sia81xx/sia8152_regs.c",
        "oneplus-modules/kernel/msm-5.4/techpack/audio/asoc/codecs/sia81xx/sia8152_regs.c",
    ):
        edit_file(root / rel, edit_sia8152)

    for rel in (
        "kernel/msm-5.4/techpack/audio/asoc/codecs/sia81xx/sia8152s_regs.c",
        "techpack/audio/asoc/codecs/sia81xx/sia8152s_regs.c",
        "oneplus-modules/kernel/msm-5.4/techpack/audio/asoc/codecs/sia81xx/sia8152s_regs.c",
    ):
        edit_file(root / rel, edit_sia8152s)

    for rel in (
        "kernel/msm-5.4/techpack/audio/asoc/codecs/sia81xx/sia8159_regs.c",
        "techpack/audio/asoc/codecs/sia81xx/sia8159_regs.c",
        "oneplus-modules/kernel/msm-5.4/techpack/audio/asoc/codecs/sia81xx/sia8159_regs.c",
    ):
        edit_file(root / rel, edit_sia8159)

    for rel in (
        "kernel/msm-5.4/techpack/audio/asoc/codecs/tfa98xx-v6/tfa98xx_v6.c",
        "techpack/audio/asoc/codecs/tfa98xx-v6/tfa98xx_v6.c",
        "oneplus-modules/kernel/msm-5.4/techpack/audio/asoc/codecs/tfa98xx-v6/tfa98xx_v6.c",
    ):
        edit_file(root / rel, edit_tfa98xx)

    for rel in (
        "vendor/oplus/kernel/system/uboot_log/uboot_log.c",
        "vendor/oplus/kernel/system/uboot_log/uboot_log.c",
        "oneplus-modules/vendor/oplus/kernel/system/uboot_log/uboot_log.c",
    ):
        edit_file(root / rel, edit_uboot_log)

    for rel in (
        "oneplus-modules/kernel/msm-5.4/techpack/display/oplus/oplus_display_panel.c",
    ):
        edit_file(root / rel, edit_oplus_display_panel)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
