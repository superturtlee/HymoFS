# HymoFS

HymoFS 是一个面向 Linux（Android GKI）的**内核级路径重定向与隐藏框架**。它提供路径重定向、目录项隐藏/注入、路径反向解析，以及可选的 stat、xattr、uname、cmdline 伪装，主要面向 root/SU 环境（如 KernelSU）和模块挂载叠加场景。

> **警告**：本项目为实验性内核修改。应用补丁会改动 VFS 与 namei 核心逻辑，仅建议在清楚风险的前提下使用。

---

## 功能概览

| 功能 | 说明 | Kconfig |
|------|------|--------|
| **正向重定向** | 打开/执行时把虚拟路径解析为真实路径（namei / getname） | `CONFIG_HYMOFS_FORWARD_REDIRECT` |
| **反向解析** | 用户态查询路径时把真实路径还原为虚拟路径（如 d_path） | `CONFIG_HYMOFS_REVERSE_LOOKUP` |
| **隐藏目录项** | 在目录列举（readdir / getdents）中隐藏指定文件或目录 | `CONFIG_HYMOFS_HIDE_ENTRIES` |
| **注入目录项** | 在目录列举中注入虚拟条目（实验性） | `CONFIG_HYMOFS_INJECT_ENTRIES` |
| **Stat 伪装** | 对指定 inode 伪装大小、时间、模式等 | `CONFIG_HYMOFS_STAT_SPOOF` |
| **Xattr 过滤** | 过滤或伪装扩展属性（如 SELinux 上下文） | `CONFIG_HYMOFS_XATTR_FILTER` |
| **Uname 伪装** | 伪装 uname 系统调用（内核版本等） | `CONFIG_HYMOFS_UNAME_SPOOF` |
| **Cmdline 伪装** | 伪装 `/proc/cmdline` 与 `/proc/bootconfig` | `CONFIG_HYMOFS_CMDLINE_SPOOF` |

重定向与隐藏规则在内核中以哈希表维护，可通过特权 fd 在运行时增删（见下方 **用户态 API**）。

---

## 支持的内核版本

补丁与 `setup.sh` 针对 **Android GKI 风格** 内核树。脚本会根据 `Makefile` 中的 VERSION / PATCHLEVEL 自动选择本仓库分支：

| 内核版本 | 分支名 |
|----------|--------|
| 5.15 (Android 13) | `android13_5.15` |
| 6.1 (Android 14) | `android14_6.1` |
| 6.6 (Android 15) | `android15_6.6` |
| 6.12 (Android 16) | `android16_6.12` |

若你的内核树布局不同（例如没有 `common/`），可手动指定内核根目录和 defconfig（见 **安装**）。

---

## 安装

### 一键安装（推荐）

在**内核源码根目录**下执行（GKI 一般为包含 `common/` 的目录）：

```bash
curl -LSs https://raw.githubusercontent.com/Anatdx/HymoFS/main/setup.sh | bash -s defconfig arch/arm64/configs/gki_defconfig
```

- 会自动检测内核版本并应用对应补丁。
- 若存在 `common/` 则对该目录打补丁，否则对当前目录。
- 会在指定 defconfig 中追加 HymoFS 相关选项（如 `CONFIG_HYMOFS=y` 及各子功能）。

### 手动参数

```text
kernel-dir <path>   内核源码根目录（默认自动检测 common/ 或当前目录）
defconfig <path>    相对内核目录的 defconfig 路径（必填）
branch <name>       HymoFS 分支，如 android15_6.6（默认按 Makefile 推断）
repo <url>          HymoFS 仓库地址（默认 https://github.com/Anatdx/HymoFS）
help                显示用法
```

例如 6.6 内核且自定义目录：

```bash
curl -LSs https://raw.githubusercontent.com/Anatdx/HymoFS/main/setup.sh | bash -s kernel-dir /path/to/kernel defconfig arch/arm64/configs/gki_defconfig branch android15_6.6
```

### 打补丁之后

1. 按原流程编译内核。HymoFS 随内核一起编译（`fs/hymofs.c`，需 `CONFIG_HYMOFS=y`）。
2. 需有用户态守护进程（如 [meta-hymo](https://github.com/KernelSU-Modules-Repo/hymo)）获取 HymoFS 的 fd 并配置重定向/隐藏规则，否则补丁不会生效。

---

## Kconfig 选项

均依赖 `CONFIG_HYMOFS`：

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `CONFIG_HYMOFS` | y | 总开关。 |
| `CONFIG_HYMOFS_REVERSE_LOOKUP` | y | 路径反向解析（d_path → 虚拟路径）。 |
| `CONFIG_HYMOFS_FORWARD_REDIRECT` | y | 路径正向重定向（namei / getname）。 |
| `CONFIG_HYMOFS_HIDE_ENTRIES` | y | readdir 中隐藏条目。 |
| `CONFIG_HYMOFS_INJECT_ENTRIES` | y | readdir 中注入虚拟条目（实验性）。 |
| `CONFIG_HYMOFS_STAT_SPOOF` | y | stat/kstat 伪装。 |
| `CONFIG_HYMOFS_XATTR_FILTER` | y | 扩展属性过滤/伪装。 |
| `CONFIG_HYMOFS_UNAME_SPOOF` | y | uname 伪装。 |
| `CONFIG_HYMOFS_CMDLINE_SPOOF` | y | /proc/cmdline、bootconfig 伪装。 |
| `CONFIG_HYMOFS_DEBUG` | n | 详细内核日志（生产环境应关闭）。 |

脚本会在 defconfig 末尾追加一组合适选项；可在 defconfig 中按需关闭子功能。

---

## 修改的内核文件

HymoFS 涉及以下部分：

- **fs**：`Kconfig`、`Makefile`、`d_path.c`、`exec.c`、`hymofs.c`（新增）、`namei.c`、`open.c`、`readdir.c`、`stat.c`、`xattr.c`、`proc/cmdline.c`
- **include/linux**：`hymofs.h`、`hymo_magic.h`（新增）
- **kernel**：`reboot.c`、`sys.c`

即对路径解析（namei、exec/open 中的 getname）、`d_path`、readdir/filldir、stat、xattr、uname、cmdline 等做了挂钩。与其他 VFS/namei 或安全模块的兼容性不保证。

---

## 用户态 API

- **特权 fd**：用户态通过 HYMO_CMD_GET_FD 等超级调用（或等价方式）获取一个 fd，所有控制通过在该 fd 上 **ioctl** 完成。定义见 `include/linux/hymo_magic.h`（或 meta-hymo 中的副本）。
- **协议版本**：`HYMO_PROTOCOL_VERSION`（如 12），守护进程与内核需一致。
- **常用 ioctl**（完整列表见 `hymo_magic.h`）：
  - `HYMO_IOC_ADD_RULE` / `HYMO_IOC_DEL_RULE`：添加/删除重定向规则（src → target）。
  - `HYMO_IOC_HIDE_RULE`：隐藏路径。
  - `HYMO_IOC_ADD_MERGE_RULE`：目录合并（如 overlay）。
  - `HYMO_IOC_CLEAR_ALL`：清空所有规则。
  - `HYMO_IOC_SET_ENABLED`：全局开关。
  - `HYMO_IOC_SET_STEALTH`：隐身（如挂载 id / 设备名伪装）。
  - `HYMO_IOC_SET_DEBUG`、`HYMO_IOC_GET_VERSION`、`HYMO_IOC_LIST_RULES` 等。
  - 可选：`HYMO_IOC_ADD_SPOOF_KSTAT`、`HYMO_IOC_SET_UNAME`、`HYMO_IOC_SET_CMDLINE`、`HYMO_IOC_SET_HIDE_UIDS` 等。

路径与规则长度受限制（如 `HYMO_MAX_LEN_PATHNAME`）。结构体与魔数由内核与用户态共用（如 meta-hymo 的 `hymofs.cpp` / `hymo_magic.h`）。

---

## 集成说明

- **[meta-hymo](https://github.com/KernelSU-Modules-Repo/hymo)**（Hymo）：KernelSU 的 C++ 模块管理器，可使用 HymoFS 做 overlay 挂载。由它运行 HymoFS 守护进程并配置规则；仅在选用 HymoFS 模式时需要本内核补丁。
- **KernelSU**：HymoFS 可隐藏或重定向 SU 及模块相关路径（如 `/data/adb/`、overlay 挂载点）。补丁中的 allowlist、profile 等结构用于与 KernelSU 相关逻辑配合。

---

## 风险与限制

- **稳定性**：修改 VFS/namei 与 readdir 具有侵入性，实现错误可能导致内核崩溃、卡死或数据异常。建议在非关键设备上测试。
- **性能**：重定向与隐藏检查会增加 open、exec、readdir、d_path 的开销；注入、stat 伪装、调试等会进一步增加。不需要的功能建议关闭。
- **兼容性**：可能与其它文件系统或安全补丁（如 SELinux、其它 overlay/隐藏方案）冲突。部分补丁版本还会修改 `security/selinux/avc.c`，请以实际仓库为准。
- **安全**：在特权守护进程 + 内核补丁下运行会扩大可信计算基，仅适合在可控的 root 环境中使用。

---

## 致谢

**特别感谢 [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu)** — HymoFS 的设计与实现参考了 SUSFS 项目（路径隐藏、readdir 挂钩、overlay 等思路）。

---

## 许可证

见本仓库 [LICENSE](LICENSE)。
