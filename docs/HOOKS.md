# HymoFS Kernel Hooks Documentation

This document describes the additional kernel hooks required to enable advanced spoofing features in HymoFS.

## Overview

HymoFS v9 introduces new spoofing capabilities:
- **kstat spoofing**: Full control over `stat()` results (ino, dev, size, timestamps, etc.)
- **uname spoofing**: Spoof kernel version reported by `uname()`
- **cmdline spoofing**: Spoof `/proc/cmdline` or `/proc/bootconfig` content

## Required Kernel Hooks

### 1. uname Spoofing Hook

Add the following to `kernel/sys.c` in the `SYSCALL_DEFINE1(newuname, ...)` function:

```c
// Add before the function:
#ifdef CONFIG_HYMOFS
extern void hymofs_spoof_uname(struct new_utsname *name);
#endif

SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)
{
	struct new_utsname tmp;

	down_read(&uts_sem);
	memcpy(&tmp, utsname(), sizeof(tmp));
#ifdef CONFIG_HYMOFS
	hymofs_spoof_uname(&tmp);  // <-- Add this line
#endif
	up_read(&uts_sem);
	if (copy_to_user(name, &tmp, sizeof(tmp)))
		return -EFAULT;
	// ... rest of function
}
```

### 2. cmdline Spoofing Hook (for non-GKI kernels)

Add the following to `fs/proc/cmdline.c`:

```c
// Add at the top of the file:
#ifdef CONFIG_HYMOFS
#include "../../fs/hymofs.h"
#endif

// Modify the cmdline_proc_show function:
static int cmdline_proc_show(struct seq_file *m, void *v)
{
#ifdef CONFIG_HYMOFS
	if (!hymofs_spoof_cmdline(m)) {
		return 0;  // Spoofed successfully
	}
#endif
	seq_puts(m, saved_command_line);
	seq_putc(m, '\n');
	return 0;
}
```

### 3. bootconfig Spoofing Hook (for GKI kernels)

Add the following to `fs/proc/bootconfig.c`:

```c
// Add at the top:
#ifdef CONFIG_HYMOFS
extern int hymofs_spoof_cmdline(struct seq_file *m);
#endif

// Modify boot_config_proc_show:
static int boot_config_proc_show(struct seq_file *m, void *v)
{
#ifdef CONFIG_HYMOFS
	if (saved_boot_config) {
		if (!hymofs_spoof_cmdline(m)) {
			return 0;
		}
	}
#endif
	if (saved_boot_config)
		seq_puts(m, saved_boot_config);
	return 0;
}
```

## Usage Examples

### kstat Spoofing

From userspace (using the hymo ioctl interface):

```c
#include <linux/hymo_magic.h>

struct hymo_spoof_kstat kstat = {
    .target_pathname = "/system/app/Example.apk",
    .spoofed_ino = 12345,
    .spoofed_dev = 0x1234,
    .spoofed_size = 1024000,
    .spoofed_mtime_sec = 1609459200,  // 2021-01-01 00:00:00
    .spoofed_mtime_nsec = 0,
    // ... other fields
};

int fd = open("/dev/hymo", O_RDWR);
ioctl(fd, HYMO_IOC_ADD_SPOOF_KSTAT, &kstat);
close(fd);
```

### uname Spoofing

```c
struct hymo_spoof_uname uname = {
    .release = "5.15.0-generic",
    .version = "#1 SMP PREEMPT Tue Jan 1 00:00:00 UTC 2021"
};

int fd = open("/dev/hymo", O_RDWR);
ioctl(fd, HYMO_IOC_SET_UNAME, &uname);
close(fd);
```

Use `"default"` for release or version to keep the original value.

### cmdline Spoofing

```c
struct hymo_spoof_cmdline cmdline = {
    .cmdline = "androidboot.verifiedbootstate=green androidboot.vbmeta.device_state=locked"
};

int fd = open("/dev/hymo", O_RDWR);
ioctl(fd, HYMO_IOC_SET_CMDLINE, &cmdline);
close(fd);
```

## Feature Detection

Use `HYMO_IOC_GET_FEATURES` to detect available features:

```c
int features;
ioctl(fd, HYMO_IOC_GET_FEATURES, &features);

if (features & HYMO_FEATURE_KSTAT_SPOOF) {
    // kstat spoofing available
}
if (features & HYMO_FEATURE_UNAME_SPOOF) {
    // uname spoofing available
}
if (features & HYMO_FEATURE_CMDLINE_SPOOF) {
    // cmdline spoofing available
}
```

## Notes

1. Root users and KSU domain processes see real values (for management purposes).
2. All spoofing operations are RCU-protected for safe concurrent access.
3. Protocol version is now 9 (check with `HYMO_IOC_GET_VERSION`).
