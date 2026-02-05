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
  log "[dry-run] Done. No commits or pushes."
  exit 0
fi

# 3) 在 dev 上提交
if git status -s | grep -q .; then
  git add "${sync_targets[@]}"
  git commit -m "sync: single source ${SINGLE_SOURCE} to all patch_workspace hymofs.c"
  log "Committed on ${DEV_BRANCH}."
else
  log "No changes after sync on ${DEV_BRANCH}."
fi

# 4) 推送 dev
if [ "$NO_PUSH" = false ]; then
  git push origin "${DEV_BRANCH}"
  log "Pushed ${DEV_BRANCH}."
fi

# 5) 所有需要同步的分支（除 dev 外）：checkout -> merge dev -> push
# 分支名与 patch_workspace 目录对应：android14-6.1 -> android14_6.1
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

# 若未从目录推断到任何分支，则使用默认列表
if [ ${#all_branches[@]} -eq 0 ]; then
  default_branches=( android12_5.10 android13_5.10 android13_5.15 android14_5.15 android14_6.1 android15_6.6 android16_6.12 )
  for b in "${default_branches[@]}"; do
    if git rev-parse --verify "origin/$b" &>/dev/null 2>/dev/null || git rev-parse --verify "$b" &>/dev/null; then
      all_branches+=( "$b" )
    fi
  done
fi

for branch in "${all_branches[@]}"; do
  if [ "$branch" = "$DEV_BRANCH" ]; then
    continue
  fi
  log "Branch: $branch (merge ${DEV_BRANCH}, then push)"
  git fetch origin "$branch" 2>/dev/null || true
  git checkout "$branch" 2>/dev/null || { log "Skip (no branch): $branch"; continue; }
  git pull --rebase origin "$branch" 2>/dev/null || true
  if git merge "$DEV_BRANCH" -m "merge: sync single source from ${DEV_BRANCH}"; then
    if [ "$NO_PUSH" = false ]; then
      git push origin "$branch"
      log "Pushed $branch."
    fi
  else
    err "Merge ${DEV_BRANCH} into $branch failed. Resolve and push manually."
    exit 1
  fi
done

# 回到 dev
git checkout "${DEV_BRANCH}"

if [ "$NO_PUSH" = false ]; then
  log "All branches synced and pushed."
else
  log "Sync and commits done. Push skipped (--no-push)."
fi
