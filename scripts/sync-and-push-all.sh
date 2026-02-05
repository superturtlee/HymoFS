#!/usr/bin/env bash
# HymoFS: 从 dev 分支单源 hymofs.c 同步到所有 patch_workspace，提交并推送到所有分支
# 用法: ./scripts/sync-and-push-all.sh [--dry-run] [--no-push]
# 要求: 在仓库根目录执行，dev 分支上存在单源文件（默认 src/hymofs.c）

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# 单源路径（相对于仓库根，且仅在 dev 分支使用）
SINGLE_SOURCE="${HYMOFS_SINGLE_SOURCE:-src/hymofs.c}"
DEV_BRANCH="${HYMOFS_DEV_BRANCH:-dev}"
# patch_workspace 下要同步的目标：目录名 androidXX-X.X 对应 fs 路径 common/fs/hymofs.c
PATCH_WS="patch_workspace"
TARGET_REL="common/fs/hymofs.c"

DRY_RUN=false
NO_PUSH=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --no-push) NO_PUSH=true ;;
    -h|--help)
      echo "Usage: $0 [--dry-run] [--no-push]"
      echo "  --dry-run  Only sync and show what would be committed/pushed"
      echo "  --no-push  Sync, commit on dev, merge to branches, but do not push"
      exit 0
      ;;
  esac
done

log() { echo "[sync-push] $*"; }
err() { echo "[sync-push] ERROR: $*" >&2; }

# 检查 dev 上是否存在单源
if ! git rev-parse --verify "${DEV_BRANCH}" &>/dev/null; then
  err "Branch '${DEV_BRANCH}' not found. Create it or set HYMOFS_DEV_BRANCH."
  exit 1
fi

if ! git show "${DEV_BRANCH}:${SINGLE_SOURCE}" &>/dev/null; then
  err "Single source '${SINGLE_SOURCE}' not found on branch '${DEV_BRANCH}'."
  exit 1
fi

# 列出 patch_workspace 下所有 android*-* 目录（排除 dev 等）
sync_targets=()
if [ -d "$PATCH_WS" ]; then
  for d in "$PATCH_WS"/android*-*; do
    [ -d "$d" ] || continue
    name="${d##*/}"
    # 排除非 android 版本目录
    case "$name" in
      android*-*) ;;
      *) continue ;;
    esac
    target_file="$d/$TARGET_REL"
    if [ -f "$target_file" ] || [ -d "$d/common/fs" ]; then
      sync_targets+=( "$target_file" )
    fi
  done
fi

if [ ${#sync_targets[@]} -eq 0 ]; then
  log "No patch_workspace targets found under $PATCH_WS (e.g. $PATCH_WS/android14-6.1/$TARGET_REL)."
  exit 0
fi

log "Single source: ${DEV_BRANCH}:${SINGLE_SOURCE}"
log "Sync targets (${#sync_targets[@]}): ${sync_targets[*]}"

# 当前分支
CURRENT_BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || echo "HEAD")"

# 1) 确保在 dev 上做同步与提交
if [ "$CURRENT_BRANCH" != "$DEV_BRANCH" ]; then
  if [ "$DRY_RUN" = true ]; then
    log "[dry-run] Would checkout ${DEV_BRANCH}"
  else
    git fetch origin "${DEV_BRANCH}" 2>/dev/null || true
    git checkout "${DEV_BRANCH}"
    git pull --rebase origin "${DEV_BRANCH}" 2>/dev/null || true
  fi
  CURRENT_BRANCH="$DEV_BRANCH"
fi

# 2) 同步：用 dev 上的单源覆盖每个目标文件
for target in "${sync_targets[@]}"; do
  dir="${target%/$TARGET_REL}"
  if [ ! -d "$dir" ]; then
    mkdir -p "$(dirname "$target")"
  fi
  if [ "$DRY_RUN" = true ]; then
    log "[dry-run] Would sync ${DEV_BRANCH}:${SINGLE_SOURCE} -> $target"
  else
    git show "${DEV_BRANCH}:${SINGLE_SOURCE}" > "$target"
  fi
done

# 若在 dry-run 下只做了“将要写入”的模拟，不实际改工作区
if [ "$DRY_RUN" = true ]; then
  log "[dry-run] Would commit in each patch_workspace repo, then empty commit on each HymoFS branch."
  log "[dry-run] Done. No commits or pushes."
  exit 0
fi

# 3) 在 patch_workspace 里每个「子仓库的子仓库」即 common/ 中提交
# 结构: patch_workspace/androidXX-X.X/common/.git 为源码仓库，同步文件为 common/fs/hymofs.c -> 在 common 里 add fs/hymofs.c
for target in "${sync_targets[@]}"; do
  # target = patch_workspace/android14-6.1/common/fs/hymofs.c -> 源码仓库根 = .../common
  common_repo_dir="${target%/fs/hymofs.c}"
  if [ ! -d "$common_repo_dir/.git" ]; then
    log "Skip (not a git repo): $common_repo_dir"
    continue
  fi
  log "Commit in repo (common): $common_repo_dir"
  ( cd "$common_repo_dir" && \
    git add . && \
    if ! git diff --cached --quiet 2>/dev/null; then
      git commit -m "sync: from HymoFS single source"
    fi
  ) || true
done

# 4) 收集 HymoFS 各分支名（与 patch_workspace 目录对应：android14-6.1 -> android14_6.1）
all_branches=()
for d in "$PATCH_WS"/android*-*; do
  [ -d "$d" ] || continue
  name="${d##*/}"
  branch_name="${name//-/_}"
  if [ "$branch_name" = "$DEV_BRANCH" ]; then
    continue
  fi
  if git rev-parse --verify "origin/$branch_name" &>/dev/null || git rev-parse --verify "$branch_name" &>/dev/null; then
    all_branches+=( "$branch_name" )
  fi
done
if [ ${#all_branches[@]} -eq 0 ]; then
  default_branches=( android12_5.10 android13_5.10 android13_5.15 android14_5.15 android14_6.1 android15_6.6 android16_6.12 )
  for b in "${default_branches[@]}"; do
    if git rev-parse --verify "origin/$b" &>/dev/null || git rev-parse --verify "$b" &>/dev/null; then
      all_branches+=( "$b" )
    fi
  done
fi

# 5) 回到 HymoFS：对每个分支做空提交（触发 githook），再推送
# 若有未提交修改则先 stash，否则 checkout 会拒绝切换
if ! git diff --quiet || ! git diff --cached --quiet; then
  log "Stashing local changes for branch switching..."
  git stash push -m "sync-push: temp before branch loop"
  STASHED=1
else
  STASHED=0
fi
# 若本地无该分支则用 origin/ 创建
for branch in "${all_branches[@]}"; do
  [ "$branch" = "$DEV_BRANCH" ] && continue
  log "Branch: $branch (empty commit, then push)"
  git fetch origin "$branch" 2>/dev/null || true
  if ! git checkout "$branch" 2>/dev/null; then
    git checkout -b "$branch" "origin/$branch" 2>/dev/null || { log "Skip (no branch): $branch"; continue; }
  fi
  git pull --rebase origin "$branch" 2>/dev/null || true
  git commit --allow-empty -m "sync: single source ${SINGLE_SOURCE} to patch_workspace (githook)"
  if [ "$NO_PUSH" = false ]; then
    git push origin "$branch"
    log "Pushed $branch."
  fi
done

# dev 也做一次空提交并推送
log "Branch: ${DEV_BRANCH} (empty commit, then push)"
git checkout "${DEV_BRANCH}"
git pull --rebase origin "${DEV_BRANCH}" 2>/dev/null || true
git commit --allow-empty -m "sync: single source ${SINGLE_SOURCE} to patch_workspace (githook)"
if [ "$NO_PUSH" = false ]; then
  git push origin "${DEV_BRANCH}"
  log "Pushed ${DEV_BRANCH}."
fi

if [ "$STASHED" = 1 ]; then
  log "Local changes were stashed. Restore with: git stash pop"
fi

if [ "$NO_PUSH" = false ]; then
  log "All branches: empty commit and pushed."
else
  log "Sync and empty commits done. Push skipped (--no-push)."
fi
