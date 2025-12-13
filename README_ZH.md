# HymoFS 内核模块 (God Mode v3) 技术文档

## 概述
HymoFS 是一个内核级的路径操控和隐藏框架，专为 Android 上的高级覆盖和修改功能而设计。与传统的 OverlayFS 不同，它通过直接 Hook Linux 内核的 VFS（虚拟文件系统）层来工作，从而对用户空间应用程序透明地拦截和修改文件操作。

## 控制接口
与内核模块的通信通过 procfs 节点进行处理：
`/proc/hymo_ctl`

### 命令

#### 1. Clear (清除)
重置所有规则并使内部缓存失效。
```bash
echo "clear" > /proc/hymo_ctl
```
*   **效果**: 清空所有哈希表（重定向、隐藏、注入）并增加内部版本计数器 (`hymo_version`)。

#### 2. Add (重定向)
将源路径的访问重定向到目标路径。
```bash
echo "add /source/path /target/path [type]" > /proc/hymo_ctl
```
*   **机制**: Hook 了 `fs/namei.c` 中的 `getname_flags`。当进程请求 `/source/path` 时，内核会透明地将其替换为 `/target/path`。
*   **Type 参数**: 可选整数（例如 `4` 代表目录，`8` 代表文件）。用于在目录列表注入期间提供正确的 `d_type` 提示，这样 `ls` 就能知道这个“幽灵文件”是目录还是普通文件，而无需对目标进行 `stat` 操作。

#### 3. Hide (隐藏)
从系统中彻底隐藏一个路径。
```bash
echo "hide /path/to/hide" > /proc/hymo_ctl
```
*   **效果**:
    *   **访问**: 通过 `open`、`access` 等方式访问时，返回 `-ENOENT` (No such file or directory)。
    *   **列表**: 在 `readdir` 操作期间过滤掉该条目，使其对 `ls` 不可见。

#### 4. Auto-Injection (自动注入 - 内部机制)
当为不存在的文件添加重定向规则时，自动在目录列表中启用“幽灵”文件。
*   **机制**:
    *   **触发**: 当调用 `add` 时，如果源路径不存在，HymoFS 会自动识别父目录并将其添加到内部注入列表中。
    *   **列表**: Hook 了 `getdents/getdents64`。在真实的目录条目列出之后，HymoFS 会人为地追加那些位于该目录下且由 `add` 规则定义的条目。
    *   **Mtime 伪装**: Hook 了 `fs/stat.c` 中的 `vfs_getattr`。强制将目录的修改时间 (`mtime`) 和改变时间 (`ctime`) 报告为当前系统时间。这可以防止缓存问题，并避免因添加“幽灵”文件而被检测到。

#### 5. Delete (删除)
根据键路径删除特定的规则（重定向或隐藏）。
```bash
echo "delete /path/key" > /proc/hymo_ctl
```
*   **效果**: 在所有哈希表（`hymo_paths`、`hymo_hide_paths`、`hymo_inject_dirs`）中搜索给定的键，如果找到则删除该条目。
*   **键路径**:
    *   对于 **Add (重定向)** 规则: 使用 *源* 路径 (例如 `/system/app/YouTube`)。
    *   对于 **Hide (隐藏)** 规则: 使用 *目标* 路径 (例如 `/system/app/Bloatware`)。
    *   **注意**: 注入规则由系统自动管理，当相应的重定向规则被删除时会自动清理。

## 实现细节

### 1. 路径解析 Hook (`fs/namei.c`)
*   **函数**: `getname_flags`
*   **逻辑**:
    1.  **隐藏检查**: 检查解析出的文件名是否在 `hymo_hide_paths` 哈希表中。如果存在，立即返回 `ERR_PTR(-ENOENT)`。
    2.  **重定向检查**: 检查文件名是否在 `hymo_paths` 哈希表中。如果存在，解析目标路径并使用新路径重新开始查找 (`getname_kernel`)。

### 2. 目录列表 Hook (`fs/readdir.c`)
*   **函数**: `filldir`, `filldir64`, `getdents`, `getdents64`
*   **隐藏**: 在 `filldir` 回调内部，检查当前条目名称（结合目录路径）是否匹配隐藏路径。如果匹配，则返回 `true` 而不将数据复制到用户缓冲区，从而有效地跳过该条目。
*   **注入**:
    *   使用一个“魔法位置”常量：`HYMO_MAGIC_POS` (`0x7000000000000000ULL`)。
    *   当标准目录列表完成时（或者如果偏移量已经处于魔法位置），HymoFS 接管操作。
    *   它调用 `hymofs_populate_injected_list` 扫描 `add` 规则。如果某个 `add` 规则的源路径是当前目录的子项（例如，在列出 `/system/bin` 时存在 `add /system/bin/su ...`），它会构建一个合成的 `linux_dirent` 结构并将其复制到用户空间。

### 3. 属性 Hook (`fs/stat.c`)
*   **函数**: `vfs_getattr_nosec`
*   **逻辑**:
    *   在返回属性之前，检查 `hymofs_should_spoof_mtime`。
    *   如果目录在 **注入列表 (Inject List)** 中，内核会用 `ktime_get_real_ts64()` 覆盖返回的 `mtime` 和 `ctime`。
    *   **目的**: 标准文件系统仅在添加/删除物理文件时更新目录的 mtime。由于 HymoFS 是虚拟地注入文件，物理 mtime 不会改变。伪装它可以确保应用程序（以及 Android 框架）意识到目录内容已经“改变”。

## 数据结构
*   **哈希表**: 使用 10 位（1024 个桶）的 `DEFINE_HASHTABLE` 进行快速查找：
    *   `hymo_paths`: 存储重定向规则。
    *   `hymo_hide_paths`: 存储隐藏规则。
    *   `hymo_inject_dirs`: 存储需要注入/伪装的目录。
*   **并发**: 由全局自旋锁 `hymo_lock` 保护。
*   **原子版本控制**: 使用 `hymo_version` 原子计数器。如果版本为 0（未初始化）或未更改，可能会走一些快速路径（尽管当前的补丁检查版本 > 0 才会进行任何活动）。
