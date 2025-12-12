#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/dirent.h>
#include <linux/miscdevice.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

#include "hymofs.h"
#include "hymofs_ioctl.h"

#ifdef CONFIG_HYMOFS

/* HymoFS God Mode - Advanced Path Manipulation */
#define HYMO_HASH_BITS 10

struct hymo_entry {
    char *src;
    char *target;
    unsigned char type;
    struct hlist_node node;
};
struct hymo_hide_entry {
    char *path;
    struct hlist_node node;
};

struct hymo_inject_entry {
    char *dir;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(hymo_paths, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_hide_paths, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_inject_dirs, HYMO_HASH_BITS);
static DEFINE_SPINLOCK(hymo_lock);
atomic_t hymo_version = ATOMIC_INIT(0);
EXPORT_SYMBOL(hymo_version);

static void hymo_cleanup(void) {
    struct hymo_entry *entry;
    struct hymo_hide_entry *hide_entry;
    struct hymo_inject_entry *inject_entry;
    struct hlist_node *tmp;
    int bkt;
    hash_for_each_safe(hymo_paths, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry->src);
        kfree(entry->target);
        kfree(entry);
    }
    hash_for_each_safe(hymo_hide_paths, bkt, tmp, hide_entry, node) {
        hash_del(&hide_entry->node);
        kfree(hide_entry->path);
        kfree(hide_entry);
    }
    hash_for_each_safe(hymo_inject_dirs, bkt, tmp, inject_entry, node) {
        hash_del(&inject_entry->node);
        kfree(inject_entry->dir);
        kfree(inject_entry);
    }
}

static long hymo_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct hymo_ioctl_arg req;
    struct hymo_entry *entry;
    struct hymo_hide_entry *hide_entry;
    struct hymo_inject_entry *inject_entry;
    char *src = NULL, *target = NULL;
    u32 hash;
    unsigned long flags;
    bool found = false;
    int ret = 0;

    if (cmd == HYMO_IOC_CLEAR_ALL) {
        spin_lock_irqsave(&hymo_lock, flags);
        hymo_cleanup();
        atomic_inc(&hymo_version);
        spin_unlock_irqrestore(&hymo_lock, flags);
        return 0;
    }
    
    if (cmd == HYMO_IOC_GET_VERSION) {
        return atomic_read(&hymo_version);
    }

    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

    if (req.src) {
        src = strndup_user(req.src, PAGE_SIZE);
        if (IS_ERR(src)) return PTR_ERR(src);
    }
    if (req.target) {
        target = strndup_user(req.target, PAGE_SIZE);
        if (IS_ERR(target)) {
            kfree(src);
            return PTR_ERR(target);
        }
    }

    switch (cmd) {
        case HYMO_IOC_ADD_RULE:
            if (!src || !target) { ret = -EINVAL; break; }
            hash = full_name_hash(NULL, src, strlen(src));
            spin_lock_irqsave(&hymo_lock, flags);
            hash_for_each_possible(hymo_paths, entry, node, hash) {
                if (strcmp(entry->src, src) == 0) {
                    kfree(entry->target);
                    entry->target = kstrdup(target, GFP_ATOMIC);
                    entry->type = req.type;
                    found = true;
                    break;
                }
            }
            if (!found) {
                entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
                if (entry) {
                    entry->src = kstrdup(src, GFP_ATOMIC);
                    entry->target = kstrdup(target, GFP_ATOMIC);
                    entry->type = req.type;
                    if (entry->src && entry->target)
                        hash_add(hymo_paths, &entry->node, hash);
                    else {
                        kfree(entry->src);
                        kfree(entry->target);
                        kfree(entry);
                    }
                }
            }
            atomic_inc(&hymo_version);
            spin_unlock_irqrestore(&hymo_lock, flags);
            break;

        case HYMO_IOC_HIDE_RULE:
            if (!src) { ret = -EINVAL; break; }
            hash = full_name_hash(NULL, src, strlen(src));
            spin_lock_irqsave(&hymo_lock, flags);
            hash_for_each_possible(hymo_hide_paths, hide_entry, node, hash) {
                if (strcmp(hide_entry->path, src) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                hide_entry = kmalloc(sizeof(*hide_entry), GFP_ATOMIC);
                if (hide_entry) {
                    hide_entry->path = kstrdup(src, GFP_ATOMIC);
                    if (hide_entry->path)
                        hash_add(hymo_hide_paths, &hide_entry->node, hash);
                    else
                        kfree(hide_entry);
                }
            }
            atomic_inc(&hymo_version);
            spin_unlock_irqrestore(&hymo_lock, flags);
            break;

        case HYMO_IOC_INJECT_RULE:
            if (!src) { ret = -EINVAL; break; }
            hash = full_name_hash(NULL, src, strlen(src));
            spin_lock_irqsave(&hymo_lock, flags);
            hash_for_each_possible(hymo_inject_dirs, inject_entry, node, hash) {
                if (strcmp(inject_entry->dir, src) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                inject_entry = kmalloc(sizeof(*inject_entry), GFP_ATOMIC);
                if (inject_entry) {
                    inject_entry->dir = kstrdup(src, GFP_ATOMIC);
                    if (inject_entry->dir)
                        hash_add(hymo_inject_dirs, &inject_entry->node, hash);
                    else
                        kfree(inject_entry);
                }
            }
            atomic_inc(&hymo_version);
            spin_unlock_irqrestore(&hymo_lock, flags);
            break;

        case HYMO_IOC_DEL_RULE:
            if (!src) { ret = -EINVAL; break; }
            hash = full_name_hash(NULL, src, strlen(src));
            spin_lock_irqsave(&hymo_lock, flags);
            
            hash_for_each_possible(hymo_paths, entry, node, hash) {
                if (strcmp(entry->src, src) == 0) {
                    hash_del(&entry->node);
                    kfree(entry->src);
                    kfree(entry->target);
                    kfree(entry);
                    goto out_delete;
                }
            }
            hash_for_each_possible(hymo_hide_paths, hide_entry, node, hash) {
                if (strcmp(hide_entry->path, src) == 0) {
                    hash_del(&hide_entry->node);
                    kfree(hide_entry->path);
                    kfree(hide_entry);
                    goto out_delete;
                }
            }
            hash_for_each_possible(hymo_inject_dirs, inject_entry, node, hash) {
                if (strcmp(inject_entry->dir, src) == 0) {
                    hash_del(&inject_entry->node);
                    kfree(inject_entry->dir);
                    kfree(inject_entry);
                    goto out_delete;
                }
            }
    out_delete:
            atomic_inc(&hymo_version);
            spin_unlock_irqrestore(&hymo_lock, flags);
            break;

        case HYMO_IOC_LIST_RULES: {
            struct hymo_ioctl_list_arg list_arg;
            char *kbuf;
            size_t buf_size;
            size_t written = 0;
            int bkt;

            if (copy_from_user(&list_arg, (void __user *)arg, sizeof(list_arg))) {
                ret = -EFAULT;
                break;
            }

            buf_size = list_arg.size;
            if (buf_size > 128 * 1024) buf_size = 128 * 1024; // Limit max buffer
            
            kbuf = kzalloc(buf_size, GFP_KERNEL);
            if (!kbuf) {
                ret = -ENOMEM;
                break;
            }

            spin_lock_irqsave(&hymo_lock, flags);
            
            // Header
            written += scnprintf(kbuf + written, buf_size - written, "HymoFS Protocol: %d\n", HYMO_PROTOCOL_VERSION);
            written += scnprintf(kbuf + written, buf_size - written, "HymoFS Config Version: %d\n", atomic_read(&hymo_version));

            hash_for_each(hymo_paths, bkt, entry, node) {
                if (written >= buf_size) break;
                written += scnprintf(kbuf + written, buf_size - written, "add %s %s %d\n", entry->src, entry->target, entry->type);
            }
            hash_for_each(hymo_hide_paths, bkt, hide_entry, node) {
                if (written >= buf_size) break;
                written += scnprintf(kbuf + written, buf_size - written, "hide %s\n", hide_entry->path);
            }
            hash_for_each(hymo_inject_dirs, bkt, inject_entry, node) {
                if (written >= buf_size) break;
                written += scnprintf(kbuf + written, buf_size - written, "inject %s\n", inject_entry->dir);
            }
            spin_unlock_irqrestore(&hymo_lock, flags);

            if (copy_to_user(list_arg.buf, kbuf, written)) {
                ret = -EFAULT;
            } else {
                // Update size to actual written bytes
                list_arg.size = written;
                if (copy_to_user((void __user *)arg, &list_arg, sizeof(list_arg))) {
                    ret = -EFAULT;
                }
            }
            
            kfree(kbuf);
            break;
        }

        default:
            ret = -EINVAL;
            break;
    }

    kfree(src);
    kfree(target);
    return ret;
}

static const struct file_operations hymo_misc_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = hymo_ioctl,
};

static struct miscdevice hymo_misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "hymo_ctl",
    .fops = &hymo_misc_fops,
};

static int __init hymofs_init(void)
{
    spin_lock_init(&hymo_lock);
    hash_init(hymo_paths);
    hash_init(hymo_hide_paths);
    hash_init(hymo_inject_dirs);
    
    misc_register(&hymo_misc_dev);
    
    pr_info("HymoFS: initialized (IOCTL Mode)\n");
    return 0;
}
fs_initcall(hymofs_init);

/* Returns kstrdup'd target if found, NULL otherwise. Caller must kfree. */
char *__hymofs_resolve_target(const char *pathname)
{
    unsigned long flags;
    struct hymo_entry *entry;
    u32 hash;
    char *target = NULL;

    if (atomic_read(&hymo_version) == 0) return NULL;
    if (!pathname) return NULL;
    hash = full_name_hash(NULL, pathname, strlen(pathname));

    spin_lock_irqsave(&hymo_lock, flags);
    hash_for_each_possible(hymo_paths, entry, node, hash) {
        if (strcmp(entry->src, pathname) == 0) {
            target = kstrdup(entry->target, GFP_ATOMIC);
            break;
        }
    }
    spin_unlock_irqrestore(&hymo_lock, flags);
    return target;
}
EXPORT_SYMBOL(__hymofs_resolve_target);

bool __hymofs_should_hide(const char *pathname)
{
    unsigned long flags;
    struct hymo_hide_entry *entry;
    u32 hash;
    bool found = false;

    if (atomic_read(&hymo_version) == 0) return false;
    if (!pathname) return false;

    /* Root sees everything */
    if (uid_eq(current_uid(), GLOBAL_ROOT_UID)) return false;

    /* Hide control interface from non-root */
    if (strcmp(pathname, "hymo_ctl") == 0 || strcmp(pathname, "/dev/hymo_ctl") == 0) return true;

    hash = full_name_hash(NULL, pathname, strlen(pathname));
    spin_lock_irqsave(&hymo_lock, flags);
    hash_for_each_possible(hymo_hide_paths, entry, node, hash) {
        if (strcmp(entry->path, pathname) == 0) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&hymo_lock, flags);
    return found;
}
EXPORT_SYMBOL(__hymofs_should_hide);

bool __hymofs_should_spoof_mtime(const char *pathname)
{
    unsigned long flags;
    struct hymo_inject_entry *entry;
    u32 hash;
    bool found = false;

    if (atomic_read(&hymo_version) == 0) return false;
    if (!pathname) return false;

    hash = full_name_hash(NULL, pathname, strlen(pathname));

    spin_lock_irqsave(&hymo_lock, flags);
    hash_for_each_possible(hymo_inject_dirs, entry, node, hash) {
        if (strcmp(entry->dir, pathname) == 0) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&hymo_lock, flags);
    return found;
}
EXPORT_SYMBOL(__hymofs_should_spoof_mtime);

static bool __hymofs_should_replace(const char *pathname)
{
    unsigned long flags;
    struct hymo_entry *entry;
    u32 hash;
    bool found = false;

    if (atomic_read(&hymo_version) == 0) return false;
    if (!pathname) return false;

    hash = full_name_hash(NULL, pathname, strlen(pathname));

    spin_lock_irqsave(&hymo_lock, flags);
    hash_for_each_possible(hymo_paths, entry, node, hash) {
        if (strcmp(entry->src, pathname) == 0) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&hymo_lock, flags);
    return found;
}

int hymofs_populate_injected_list(const char *dir_path, struct dentry *parent, struct list_head *head)
{
    unsigned long flags;
    struct hymo_entry *entry;
    struct hymo_inject_entry *inject_entry;
    struct hymo_name_list *item;
    u32 hash;
    int bkt;
    bool should_inject = false;
    size_t dir_len;
    if (atomic_read(&hymo_version) == 0) return 0;
    if (!dir_path) return 0;

    dir_len = strlen(dir_path);
    hash = full_name_hash(NULL, dir_path, dir_len);

    spin_lock_irqsave(&hymo_lock, flags);
    
    hash_for_each_possible(hymo_inject_dirs, inject_entry, node, hash) {
        if (strcmp(inject_entry->dir, dir_path) == 0) {
            should_inject = true;
            break;
        }
    }
    if (should_inject) {
        hash_for_each(hymo_paths, bkt, entry, node) {
            if (strncmp(entry->src, dir_path, dir_len) == 0) {
                char *name = NULL;
                if (dir_len == 1 && dir_path[0] == '/') {
                    name = entry->src + 1;
                } else if (entry->src[dir_len] == '/') {
                    name = entry->src + dir_len + 1;
                }

                if (name && *name && strchr(name, '/') == NULL) {
                    item = kmalloc(sizeof(*item), GFP_ATOMIC);
                    if (item) {
                        item->name = kstrdup(name, GFP_ATOMIC);
                        item->type = entry->type;
                        if (item->name) list_add(&item->list, head);
                        else kfree(item);
                    }
                }
            }
        }
    }

    spin_unlock_irqrestore(&hymo_lock, flags);
    return 0;
}
EXPORT_SYMBOL(hymofs_populate_injected_list);

struct filename *hymofs_handle_getname(struct filename *result)
{
    char *target;

    if (IS_ERR(result)) return result;

    /* HymoFS God Mode Hook */
    if (hymofs_should_hide(result->name)) {
        putname(result);
        /* Return ENOENT directly */
        return ERR_PTR(-ENOENT);
    } else {
        target = hymofs_resolve_target(result->name);
        if (target) {
            putname(result);
            result = getname_kernel(target);
            kfree(target);
        }
    }
    return result;
}
EXPORT_SYMBOL(hymofs_handle_getname);

void __hymofs_prepare_readdir(struct hymo_readdir_context *ctx, struct file *file)
{
    ctx->file = file;
    ctx->path_buf = NULL;
    ctx->dir_path = NULL;
    ctx->dir_path_len = 0;

    ctx->path_buf = (char *)__get_free_page(GFP_KERNEL);
    if (ctx->path_buf && file && file->f_path.dentry) {
        char *p = d_path(&file->f_path, ctx->path_buf, PAGE_SIZE);
        if (!IS_ERR(p)) {
            int len = strlen(p);
            memmove(ctx->path_buf, p, len + 1);
            ctx->dir_path = ctx->path_buf;
            ctx->dir_path_len = len;
        } else {
            free_page((unsigned long)ctx->path_buf);
            ctx->path_buf = NULL;
        }
    }
}
EXPORT_SYMBOL(__hymofs_prepare_readdir);

void __hymofs_cleanup_readdir(struct hymo_readdir_context *ctx)
{
    if (ctx->path_buf) free_page((unsigned long)ctx->path_buf);
}
EXPORT_SYMBOL(__hymofs_cleanup_readdir);

bool __hymofs_check_filldir(struct hymo_readdir_context *ctx, const char *name, int namlen)
{
    if (ctx->dir_path) {
        if (ctx->dir_path_len + 1 + namlen < PAGE_SIZE) {
            char *p = ctx->path_buf + ctx->dir_path_len;
            if (p > ctx->path_buf && p[-1] != '/') *p++ = '/';
            memcpy(p, name, namlen);
            p[namlen] = '\0';
            if (hymofs_should_hide(ctx->path_buf)) return true;
            if (__hymofs_should_replace(ctx->path_buf)) return true;
        }
    }
    return false;
}
EXPORT_SYMBOL(__hymofs_check_filldir);

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[];
};

int hymofs_inject_entries(struct hymo_readdir_context *ctx, void __user **dir_ptr, int *count, loff_t *pos)
{
    struct linux_dirent __user *current_dir = *dir_ptr;
    struct list_head head;
    struct hymo_name_list *item, *tmp;
    loff_t current_idx = 0;
    loff_t start_idx;
    int injected = 0;
    int error = 0;
    int initial_count = *count;
    bool is_transition = (*pos < HYMO_MAGIC_POS);
    struct dentry *parent;

    if (!ctx->file) return 0;
    parent = ctx->file->f_path.dentry;

    if (is_transition) {
        start_idx = 0;
    } else {
        start_idx = *pos - HYMO_MAGIC_POS;
    }

    INIT_LIST_HEAD(&head);
    hymofs_populate_injected_list(ctx->dir_path, parent, &head);

    list_for_each_entry_safe(item, tmp, &head, list) {
        if (current_idx >= start_idx) {
            int name_len = strlen(item->name);
            int reclen = ALIGN(offsetof(struct linux_dirent, d_name) + name_len + 2, sizeof(long));
            if (*count >= reclen) {
                struct linux_dirent d;
                d.d_ino = 1;
                d.d_off = HYMO_MAGIC_POS + current_idx + 1;
                d.d_reclen = reclen;
                if (copy_to_user(current_dir, &d, offsetof(struct linux_dirent, d_name)) ||
                    copy_to_user(current_dir->d_name, item->name, name_len) ||
                    put_user(0, current_dir->d_name + name_len) ||
                    put_user(item->type, (char __user *)current_dir + reclen - 1)) {
                        error = -EFAULT;
                        break;
                }
                current_dir = (struct linux_dirent __user *)((char __user *)current_dir + reclen);
                *count -= reclen;
                injected++;
            } else {
                break;
            }
        }
        current_idx++;
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }
    
    list_for_each_entry_safe(item, tmp, &head, list) {
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }

    if (error == 0) {
        if (injected > 0) {
            if (is_transition) {
                *pos = HYMO_MAGIC_POS + injected;
            } else {
                *pos += injected;
            }
        }
        error = initial_count - *count;
    }
    
    *dir_ptr = current_dir;
    return error;
}
EXPORT_SYMBOL(hymofs_inject_entries);

int hymofs_inject_entries64(struct hymo_readdir_context *ctx, void __user **dir_ptr, int *count, loff_t *pos)
{
    struct linux_dirent64 __user *current_dir = *dir_ptr;
    struct list_head head;
    struct hymo_name_list *item, *tmp;
    loff_t current_idx = 0;
    loff_t start_idx;
    int injected = 0;
    int error = 0;
    int initial_count = *count;
    bool is_transition = (*pos < HYMO_MAGIC_POS);
    struct dentry *parent;

    if (!ctx->file) return 0;
    parent = ctx->file->f_path.dentry;

    if (is_transition) {
        start_idx = 0;
    } else {
        start_idx = *pos - HYMO_MAGIC_POS;
    }

    INIT_LIST_HEAD(&head);
    hymofs_populate_injected_list(ctx->dir_path, parent, &head);

    list_for_each_entry_safe(item, tmp, &head, list) {
        if (current_idx >= start_idx) {
            int name_len = strlen(item->name);
            int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + name_len + 1, sizeof(u64));
            if (*count >= reclen) {
                struct linux_dirent64 d;
                d.d_ino = 1;
                d.d_off = HYMO_MAGIC_POS + current_idx + 1;
                d.d_reclen = reclen;
                d.d_type = item->type;
                if (copy_to_user(current_dir, &d, offsetof(struct linux_dirent64, d_name)) ||
                    copy_to_user(current_dir->d_name, item->name, name_len) ||
                    put_user(0, current_dir->d_name + name_len)) {
                        error = -EFAULT;
                        break;
                }
                current_dir = (struct linux_dirent64 __user *)((char __user *)current_dir + reclen);
                *count -= reclen;
                injected++;
            } else {
                break;
            }
        }
        current_idx++;
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }
    
    list_for_each_entry_safe(item, tmp, &head, list) {
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }

    if (error == 0) {
        if (injected > 0) {
            if (is_transition) {
                *pos = HYMO_MAGIC_POS + injected;
            } else {
                *pos += injected;
            }
        }
        error = initial_count - *count;
    }
    
    *dir_ptr = current_dir;
    return error;
}
EXPORT_SYMBOL(hymofs_inject_entries64);

void hymofs_spoof_stat(const struct path *path, struct kstat *stat)
{
    char *buf = (char *)__get_free_page(GFP_KERNEL);
    if (buf && path && path->dentry) {
        char *p = d_path(path, buf, PAGE_SIZE);
        if (!IS_ERR(p)) {
            if (hymofs_should_spoof_mtime(p)) {
                ktime_get_real_ts64(&stat->mtime);
                stat->ctime = stat->mtime;
            }
        }
        free_page((unsigned long)buf);
    }
}
EXPORT_SYMBOL(hymofs_spoof_stat);

#endif /* CONFIG_HYMOFS */
