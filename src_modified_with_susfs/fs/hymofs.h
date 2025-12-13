#ifndef _LINUX_HYMOFS_H
#define _LINUX_HYMOFS_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/atomic.h>

#ifdef CONFIG_HYMOFS

#define HYMO_MAGIC_POS 0x7000000000000000ULL

struct hymo_readdir_context {
    struct file *file;
    char *path_buf;
    char *dir_path;
    int dir_path_len;
};

extern atomic_t hymo_version;

void __hymofs_prepare_readdir(struct hymo_readdir_context *ctx, struct file *file);
void __hymofs_cleanup_readdir(struct hymo_readdir_context *ctx);
bool __hymofs_check_filldir(struct hymo_readdir_context *ctx, const char *name, int namlen);
int hymofs_inject_entries(struct hymo_readdir_context *ctx, void __user **dir_ptr, int *count, loff_t *pos);
int hymofs_inject_entries64(struct hymo_readdir_context *ctx, void __user **dir_ptr, int *count, loff_t *pos);
void hymofs_spoof_stat(const struct path *path, struct kstat *stat);

struct hymo_name_list {
    char *name;
    unsigned char type;
    struct list_head list;
};

struct filename;
struct filename *hymofs_handle_getname(struct filename *result);

char *__hymofs_resolve_target(const char *pathname);
bool __hymofs_should_hide(const char *pathname);
bool __hymofs_should_spoof_mtime(const char *pathname);
int hymofs_populate_injected_list(const char *dir_path, struct dentry *parent, struct list_head *head);

static inline void hymofs_prepare_readdir(struct hymo_readdir_context *ctx, struct file *file)
{
    ctx->path_buf = NULL;
    ctx->file = file;
    if (atomic_read(&hymo_version) == 0) return;
    __hymofs_prepare_readdir(ctx, file);
}

static inline void hymofs_cleanup_readdir(struct hymo_readdir_context *ctx)
{
    if (ctx->path_buf) __hymofs_cleanup_readdir(ctx);
}

static inline bool hymofs_check_filldir(struct hymo_readdir_context *ctx, const char *name, int namlen)
{
    if (!ctx->path_buf) return false;
    return __hymofs_check_filldir(ctx, name, namlen);
}

static inline char *hymofs_resolve_target(const char *pathname)
{
    if (atomic_read(&hymo_version) == 0) return NULL;
    return __hymofs_resolve_target(pathname);
}

static inline bool hymofs_should_hide(const char *pathname)
{
    if (atomic_read(&hymo_version) == 0) return false;
    return __hymofs_should_hide(pathname);
}

static inline bool hymofs_should_spoof_mtime(const char *pathname)
{
    if (atomic_read(&hymo_version) == 0) return false;
    return __hymofs_should_spoof_mtime(pathname);
}

#else

struct hymo_readdir_context {};
static inline void hymofs_prepare_readdir(struct hymo_readdir_context *ctx, struct file *file) {}
static inline void hymofs_cleanup_readdir(struct hymo_readdir_context *ctx) {}
static inline bool hymofs_check_filldir(struct hymo_readdir_context *ctx, const char *name, int namlen) { return false; }
static inline int hymofs_inject_entries(struct hymo_readdir_context *ctx, void __user **dir_ptr, int *count, loff_t *pos) { return 0; }
static inline int hymofs_inject_entries64(struct hymo_readdir_context *ctx, void __user **dir_ptr, int *count, loff_t *pos) { return 0; }
static inline void hymofs_spoof_stat(const struct path *path, struct kstat *stat) {}

static inline struct filename *hymofs_handle_getname(struct filename *result) { return result; }
static inline char *hymofs_resolve_target(const char *pathname) { return NULL; }
static inline bool hymofs_should_hide(const char *pathname) { return false; }
static inline bool hymofs_should_spoof_mtime(const char *pathname) { return false; }
static inline int hymofs_populate_injected_list(const char *dir_path, struct dentry *parent, struct list_head *head) { return 0; }

#endif /* CONFIG_HYMOFS */

#endif /* _LINUX_HYMOFS_H */
