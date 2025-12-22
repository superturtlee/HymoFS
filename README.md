# HymoFS Technical Documentation

## Overview
HymoFS is a kernel-level path manipulation and hiding framework designed for advanced overlay and modification capabilities on Android. Unlike traditional overlay filesystems, it operates by hooking directly into the Linux kernel's VFS (Virtual File System) layer to intercept and modify file operations transparently to userspace applications.

## Installation & Integration

HymoFS provides a smart `setup.sh` script for easy integration into your kernel source.

### One-Line Setup
```bash
curl -LSs https://raw.githubusercontent.com/Anatdx/HymoFS/main/setup.sh | bash -s defconfig arch/arm64/configs/gki_defconfig
```

### Features
*   **Auto-Branch Selection**: Automatically detects your kernel version (6.1 or 6.6) and switches to the appropriate branch (`android14_6.1` or `android15_6.6`).
*   **KernelSU Detection**: Automatically detects KernelSU and configures `CONFIG_HYMOFS_USE_KSU`.
*   **SUSFS Integration**: Automatically detects SUSFS and applies the compatible patch if found (or if `with-susfs` is specified).

### Manual Options
*   `kernel-dir <path>`: Specify kernel source directory.
*   `branch <name>`: Force a specific git branch.
*   `with-susfs`: Force enable SUSFS compatibility.

## Control Interface
Communication with the kernel module is handled via a hijacked `reboot` system call. This design avoids creating a visible character device node (like `/dev/hymo_ctl`), improving stealth.

### Mechanism
*   **Syscall**: `sys_reboot`
*   **Magic Numbers**: `HYMO_MAGIC1` (0x48594D4F "HYMO") and `HYMO_MAGIC2` (0x524F4F54 "ROOT")
*   **Invocation**: `syscall(SYS_reboot, HYMO_MAGIC1, HYMO_MAGIC2, CMD, ARG)`

### Commands

All commands are sent via the `cmd` argument of the `reboot` syscall.

#### 1. Clear
Resets all rules and invalidates internal caches.
*   **CMD**: `HYMO_CMD_CLEAR_ALL` (0x48005)
*   **Argument**: None (0)
*   **Effect**: Clears all hash tables (redirects, hides, injections) and increments the internal version counter (`hymo_version`).

#### 2. Add (Redirect)
Redirects access from a source path to a target path.
*   **CMD**: `HYMO_CMD_ADD_RULE` (0x48001)
*   **Argument**: Pointer to `struct hymo_syscall_arg`
    *   `src`: Source path string pointer
    *   `target`: Target path string pointer
    *   `type`: File type (DT_DIR=4, DT_REG=8, etc.)
*   **Mechanism**: Hooks `getname_flags` in `fs/namei.c`. When a process requests `/source/path`, the kernel transparently swaps it for `/target/path`.

#### 3. Hide
Completely hides a path from the system.
*   **CMD**: `HYMO_CMD_HIDE_RULE` (0x48003)
*   **Argument**: Pointer to `struct hymo_syscall_arg`
    *   `src`: Path to hide
*   **Effect**:
    *   **Access**: Returns `-ENOENT` (No such file or directory) when accessed via `open`, `access`, etc.
    *   **Listing**: Filters the entry out during `readdir` operations, making it invisible to `ls`.

#### 4. Auto-Injection (Internal)
Automatically enables "Ghost" files in a directory listing when a redirect rule is added for a non-existent file.
*   **Mechanism**:
    *   **Trigger**: When `add` is called, if the source path does not exist, HymoFS automatically identifies the parent directory and adds it to an internal injection list.
    *   **Listing**: Hooks `getdents/getdents64`. After the real directory entries are listed, HymoFS artificially appends entries defined by `add` rules that reside within this directory.
    *   **Mtime Spoofing**: Hooks `vfs_getattr` in `fs/stat.c`. Forces the directory's modification time (`mtime`) and change time (`ctime`) to report the current system time.

#### 5. Delete
Removes a specific rule (redirect or hide) by its key path.

*   **Effect**: Searches all hash tables (`hymo_paths`, `hymo_hide_paths`, `hymo_inject_dirs`) for the given key and removes the entry if found.
*   **Key Path**:
    *   For **Add** rules: Use the *source* path (e.g., `/system/app/YouTube`).
    *   For **Hide** rules: Use the *target* path (e.g., `/system/app/Bloatware`).
    *   **Note**: Injection rules are managed automatically and cleaned up when the corresponding redirect rule is deleted.
*   **CMD**: `HYMO_CMD_DEL_RULE` (0x48002)
*   **Argument**: Pointer to `struct hymo_syscall_arg`
    *   `src`: Key path of the rule
*   **Effect**: Searches all hash tables for the given key and removes the entry.

#### 6. List (List Rules)
Retrieves a list of all currently active rules.
*   **CMD**: `HYMO_CMD_LIST_RULES` (0x48007)
*   **Argument**: Pointer to `struct hymo_syscall_list_arg`
    *   `buf`: User buffer pointer
    *   `size`: Buffer size
*   **Mechanism**: The kernel writes text-formatted data containing all rules into the user buffer.
*   **Format**:
    ```text
    HymoFS Protocol: 7
    HymoFS Config Version: 123
    add /source /target 8
    hide /path/to/hide
    inject /path/to/inject
    merge /source /target
    ```

#### 7. Merge (Merge Mode)
Merges the contents of a target directory into a source directory, allowing the source directory to show both its original files and files from the target directory.
*   **CMD**: `HYMO_CMD_ADD_MERGE_RULE` (0x48012)
*   **Argument**: Pointer to `struct hymo_syscall_arg`
    *   `src`: Source directory path
    *   `target`: Target directory path
*   **Mechanism**:
    *   **Injection**: Automatically adds the source directory to the injection list. During `readdir`, it reads entries from the target directory and injects them into the listing alongside original entries.
    *   **Redirection**: Access to merged files is automatically redirected to the target path.
    *   **Attribute Preservation**: Access to the source directory itself (e.g., `ls -ld /source`) is not redirected, preserving original attributes.

#### 8. Stealth & Debug
*   **Set Debug**: `HYMO_CMD_SET_DEBUG` (0x48008) - Enable/Disable kernel debug logging.
*   **Set Stealth**: `HYMO_CMD_SET_STEALTH` (0x48010) - Enable stealth mode, spoofing mount point device names.
*   **Reorder Mount ID**: `HYMO_CMD_REORDER_MNT_ID` (0x48009) - Reorder mount IDs to prevent detection via ID sequence.
*   **Hide Overlay Xattrs**: `HYMO_CMD_HIDE_OVERLAY_XATTRS` (0x48011) - Hide specific extended attributes (like `trusted.overlay.*`) to prevent OverlayFS detection.
*   **AVC Log Spoofing**: `HYMO_CMD_SET_AVC_LOG_SPOOFING` (0x48013) - Enable/Disable AVC denial log spoofing.

## Implementation Details

### 1. Architecture Design
*   **linux/hymo_magic.h**: Defines the User API (UAPI), including Magic numbers, Command codes, and data structures.
*   **hymofs.h**: Kernel module internal implementation header, containing kernel data structures and function declarations.
*   **hymofs.c**: Core logic implementation, including syscall hook, hash table management, etc.
*   **Atomic Config**: Uses `atomic_t hymo_atomiconfig` as a global configuration version counter.
    *   **Performance Optimization**: Checked at the beginning of all hooks. If 0 (no rules), hooks return immediately, ensuring zero overhead.
    *   **Atomic Updates**: Any rule change (add, delete, clear) atomically increments this counter, ensuring configuration consistency across multi-core environments.

### 2. Path Resolution Hook (`fs/namei.c`)
*   **Function**: `getname_flags`
*   **Logic**:
    1.  **Relative Path Handling**: If the path is relative (does not start with `/`), it automatically retrieves the current working directory (CWD) of the process and prepends it to form an absolute path, ensuring accurate rule matching.
    2.  **Hide Check**: Checks if the resolved filename is in the `hymo_hide_paths` hash table. If found, it immediately returns `ERR_PTR(-ENOENT)`.
    3.  **Redirect Check**: Checks if the filename is in the `hymo_paths` hash table.
        *   **Merge Mode Support**: If the path ends with `/.` or `/..`, redirection is skipped. This allows tools like `ls` to read the attributes of the original directory, enabling the "merging" of original and injected files and preventing original files from disappearing.
        *   **Redirect Execution**: If matched and not one of the special cases above, it resolves the target path and restarts the lookup with the new path (`getname_kernel`).
    4.  **Recursion Prevention**: Uses the `current->hymofs_recursion` flag to prevent infinite loops when resolving target paths.

### 3. Directory Listing Hook (`fs/readdir.c`)
*   **Functions**: `filldir`, `filldir64`, `getdents`, `getdents64`
*   **Hiding**: Inside the `filldir` callback, it checks if the current entry name (combined with the directory path) matches a hidden path. If so, it returns `true` without copying data to the user buffer.
*   **Injection**:
    *   Uses a "Magic Position" constant: `HYMO_MAGIC_POS` (`0x7000000000000000ULL`).
    *   When the standard directory listing finishes, HymoFS takes over, calling `hymofs_populate_injected_list` to scan and inject "ghost" entries.

### 4. Attribute Hook (`fs/stat.c`)
*   **Function**: `vfs_getattr_nosec`
*   **Logic**: If the directory is in the **Inject List**, the kernel overwrites the returned `mtime` and `ctime` with `ktime_get_real_ts64()` to ensure applications perceive the directory content change.

## Data Structures
*   **Hash Tables**: Uses `DEFINE_HASHTABLE` with 10 bits (1024 buckets) for fast lookups.
*   **Concurrency**: Protected by a global spinlock `hymo_lock`.
*   **Memory Management**: Uses `vmalloc` for large buffer allocations (e.g., for `read` operations) to ensure stability.

