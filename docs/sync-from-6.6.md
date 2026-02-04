# 从 6.6 主线同步到其他内核版本

HymoFS 以 **6.6** 为主线开发，其他内核版本（如 6.1）通过分支维护。仓库级变更（README、CI、脚本、pre-commit）已同步到各分支。

## Patch 与内核版本

`patch/hymofs.patch` 是针对**具体内核版本**生成的 diff，行号和上下文与对应内核源码绑定，不能直接把 6.6 的 patch 用于 6.1 内核。

## 将 6.6 的 patch 变更移植到 6.1

若需要让 6.1 分支的补丁与 6.6 功能一致（如 exec/open 钩子、d_path 重构为 `hymofs_process_d_path` 等），建议在 **6.1 内核源码树**上操作：

1. 克隆或检出 **6.1** 内核源码（与当前 android14_6.1 使用的版本一致）。
2. 从 **android15_6.6** 分支复制 `patch/hymofs.patch` 到该 6.1 树根目录。
3. 在 6.1 树根目录执行：
   ```bash
   patch -p1 < hymofs.patch
   ```
4. 若有 `.rej` 文件，按 6.1 内核的 API/上下文手工解决冲突。
5. 解决完成后，从该 6.1 树重新生成补丁：
   ```bash
   git diff android14-6.1..hymofs-modified > hymofs.patch
   ```
   （分支名按你本地的 6.1 原始分支与修改分支为准。）
6. 将生成的 `hymofs.patch` 拷回 HymoFS 仓库的 **android14_6.1** 分支并替换 `patch/hymofs.patch`。

## 当前 6.1 分支状态

- **仓库级**：README、README_ZH、.gitignore、.githooks/pre-commit（按分支选择 android14-6.1 / android15-6.6）、script/buildbot.py、CI（clean_workflow、cleaner）已与 6.6 对齐。
- **patch**：仍为针对 6.1 的旧版补丁；如需与 6.6 功能完全一致，请按上述步骤在 6.1 内核树上重做补丁。
