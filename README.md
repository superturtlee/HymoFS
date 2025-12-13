# HymoFS Kernel Module (God Mode v3) Technical Documentation

## Overview
HymoFS is a kernel-level path manipulation and hiding framework designed for advanced overlay and modification capabilities on Android. Unlike traditional overlay filesystems, it operates by hooking directly into the Linux kernel's VFS (Virtual File System) layer to intercept and modify file operations transparently to userspace applications.

## Control Interface
Communication with the kernel module is handled via the procfs node:
`/proc/hymo_ctl`

### Commands

#### 1. Clear
Resets all rules and invalidates internal caches.
```bash
echo "clear" > /proc/hymo_ctl
```
*   **Effect**: Clears all hash tables (redirects, hides, injections) and increments the internal version counter (`hymo_version`).

#### 2. Add (Redirect)
Redirects access from a source path to a target path.
```bash
echo "add /source/path /target/path [type]" > /proc/hymo_ctl
```
*   **Mechanism**: Hooks `getname_flags` in `fs/namei.c`. When a process requests `/source/path`, the kernel transparently swaps it for `/target/path`.
*   **Type Argument**: Optional integer (e.g., `4` for directory, `8` for file). This is used to provide the correct `d_type` hint during directory listing injection, so `ls` knows if the ghost file is a directory or a regular file without needing to `stat` the target.

#### 3. Hide
Completely hides a path from the system.
```bash
echo "hide /path/to/hide" > /proc/hymo_ctl
```
*   **Effect**:
    *   **Access**: Returns `-ENOENT` (No such file or directory) when accessed via `open`, `access`, etc.
    *   **Listing**: Filters the entry out during `readdir` operations, making it invisible to `ls`.

#### 4. Auto-Injection (Internal)
Automatically enables "Ghost" files in a directory listing when a redirect rule is added for a non-existent file.
*   **Mechanism**:
    *   **Trigger**: When `add` is called, if the source path does not exist, HymoFS automatically identifies the parent directory and adds it to an internal injection list.
    *   **Listing**: Hooks `getdents/getdents64`. After the real directory entries are listed, HymoFS artificially appends entries defined by `add` rules that reside within this directory.
    *   **Mtime Spoofing**: Hooks `vfs_getattr` in `fs/stat.c`. Forces the directory's modification time (`mtime`) and change time (`ctime`) to report the current system time. This prevents caching issues and detection when "ghost" files are added.

#### 5. Delete
Removes a specific rule (redirect or hide) by its key path.
```bash
echo "delete /path/key" > /proc/hymo_ctl
```
*   **Effect**: Searches all hash tables (`hymo_paths`, `hymo_hide_paths`, `hymo_inject_dirs`) for the given key and removes the entry if found.
*   **Key Path**:
    *   For **Add** rules: Use the *source* path (e.g., `/system/app/YouTube`).
    *   For **Hide** rules: Use the *target* path (e.g., `/system/app/Bloatware`).
    *   **Note**: Injection rules are managed automatically and cleaned up when the corresponding redirect rule is deleted.

## Implementation Details

### 1. Path Resolution Hook (`fs/namei.c`)
*   **Function**: `getname_flags`
*   **Logic**:
    1.  **Hide Check**: Checks if the resolved filename is in the `hymo_hide_paths` hash table. If found, it immediately returns `ERR_PTR(-ENOENT)`.
    2.  **Redirect Check**: Checks if the filename is in the `hymo_paths` hash table. If found, it resolves the target path and restarts the lookup with the new path (`getname_kernel`).

### 2. Directory Listing Hook (`fs/readdir.c`)
*   **Functions**: `filldir`, `filldir64`, `getdents`, `getdents64`
*   **Hiding**: Inside the `filldir` callback, it checks if the current entry name (combined with the directory path) matches a hidden path. If so, it returns `true` without copying data to the user buffer, effectively skipping the entry.
*   **Injection**:
    *   Uses a "Magic Position" constant: `HYMO_MAGIC_POS` (`0x7000000000000000ULL`).
    *   When the standard directory listing finishes (or if the offset is already at the magic position), HymoFS takes over.
    *   It calls `hymofs_populate_injected_list` to scan the `add` rules. If an `add` rule's source path is a child of the current directory (e.g., `add /system/bin/su ...` when listing `/system/bin`), it constructs a synthetic `linux_dirent` structure and copies it to userspace.

### 3. Attribute Hook (`fs/stat.c`)
*   **Function**: `vfs_getattr_nosec`
*   **Logic**:
    *   Before returning attributes, it checks `hymofs_should_spoof_mtime`.
    *   If the directory is in the **Inject List**, the kernel overwrites the returned `mtime` and `ctime` with `ktime_get_real_ts64()`.
    *   **Purpose**: Standard filesystems update directory mtime only when physical files are added/removed. Since HymoFS injects files virtually, the physical mtime doesn't change. Spoofing it ensures that apps (and the Android framework) realize the directory content has "changed".

## Data Structures
*   **Hash Tables**: Uses `DEFINE_HASHTABLE` with 10 bits (1024 buckets) for fast lookups:
    *   `hymo_paths`: Stores redirect rules.
    *   `hymo_hide_paths`: Stores hide rules.
    *   `hymo_inject_dirs`: Stores directories that need injection/spoofing.
*   **Concurrency**: Protected by a global spinlock `hymo_lock`.
*   **Atomic Versioning**: Uses `hymo_version` atomic counter. If the version is 0 (uninitialized) or hasn't changed, some fast paths might be taken (though the current patch checks version > 0 for any activity).
