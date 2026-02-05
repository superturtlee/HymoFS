# HymoFS 单源 (Single Source)

本目录为 **dev 分支** 上的单源代码，用于通过 `scripts/sync-and-push-all.sh` 同步到各内核版本的 `patch_workspace/*/common/fs/hymofs.c`。

## 文件说明

- **hymofs.c** — 唯一单源，通过 `LINUX_VERSION_CODE` 兼容 5.10 / 5.15 / 6.1 / 6.6 / 6.12。已包含 5.15/6.1 相关修复（C89 声明顺序、`filldir` 返回类型等）。

## 6.1 专用修改（非单源）

以下修改仅针对 **6.1** 内核，在 `patch_workspace/android14-6.1/common/fs/` 中维护，不会从单源同步：

### open.c

在 `#include "internal.h"` 与第一个函数之间增加：

```c
#ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
extern struct filename *hymofs_handle_getname(struct filename *result);
#endif
```

### d_path.c

在 `#include "mount.h"` 与 `struct prepend_buffer` 之间增加：

```c
#ifdef CONFIG_HYMOFS_REVERSE_LOOKUP
extern char *hymofs_process_d_path(char *res, char *buf, int buflen);
#endif
```

生成或应用 6.1 补丁时需包含上述声明，否则会出现未声明函数与类型转换错误。
