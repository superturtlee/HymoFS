#!/usr/bin/env bash
# HymoFS: 清理 android14-6.1 的 patch_workspace，用纯净 common 6.1 重新应用 patch
# 用法: 在 HymoFS 仓库根目录执行: ./scripts/clean-and-reapply-6.1.sh [--dry-run]
# 要求: patch_workspace/android14-6.1/common 为 git 仓库，且 origin 指向 Android common 上游

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

COMMON_6_1="${REPO_ROOT}/patch_workspace/android14-6.1/common"
PATCH_FILE="${REPO_ROOT}/patch/hymofs.patch"
UPSTREAM_BRANCH="origin/android14-6.1"

DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    -h|--help)
      echo "Usage: $0 [--dry-run]"
      echo "  Reset android14-6.1 common to pristine upstream, then re-apply hymofs.patch."
      echo "  --dry-run  Only print what would be done."
      exit 0
      ;;
  esac
done

log() { echo "[clean-6.1] $*"; }
err() { echo "[clean-6.1] ERROR: $*" >&2; }

if [ ! -d "$COMMON_6_1" ]; then
  err "Directory not found: $COMMON_6_1"
  exit 1
fi

if [ ! -d "$COMMON_6_1/.git" ]; then
  err "Not a git repo: $COMMON_6_1 (need upstream to reset from)"
  exit 1
fi

if [ ! -f "$PATCH_FILE" ]; then
  err "Patch not found: $PATCH_FILE"
  exit 1
fi

log "Common 6.1: $COMMON_6_1"
log "Patch:      $PATCH_FILE"
log "Upstream:   $UPSTREAM_BRANCH"

if [ "$DRY_RUN" = true ]; then
  log "[dry-run] Would: cd $COMMON_6_1 && fetch + reset --hard $UPSTREAM_BRANCH + patch -p1 -F 3 < patch"
  exit 0
fi

cd "$COMMON_6_1"

# 确保有 upstream
if ! git rev-parse --verify "$UPSTREAM_BRANCH" &>/dev/null; then
  log "Fetching $UPSTREAM_BRANCH..."
  git fetch origin android14-6.1
fi

if ! git rev-parse --verify "$UPSTREAM_BRANCH" &>/dev/null; then
  err "Upstream branch not found: $UPSTREAM_BRANCH"
  exit 1
fi

# 未提交改动先暂存，避免丢失
if ! git diff --quiet || ! git diff --cached --quiet; then
  log "Stashing local changes..."
  git stash push -m "clean-and-reapply-6.1: before reset"
fi

# 重置为纯净 6.1（当前分支指向 upstream，不删分支）
log "Resetting to pristine $UPSTREAM_BRANCH..."
git reset --hard "$UPSTREAM_BRANCH"
git clean -fd

# 应用 HymoFS patch（在 common 目录内，patch 路径是 fs/xxx 所以 -p1）
log "Applying HymoFS patch..."
if ! patch -p1 -F 3 < "$PATCH_FILE"; then
  err "Patch applied with errors or rejects. Check .rej files in $COMMON_6_1"
  err "You can: 1) fix rejects by hand; 2) then generate 6.1-only patch: (cd $COMMON_6_1 && git add -A && git diff --cached > $REPO_ROOT/patch/hymofs_6.1.patch)"
  exit 1
fi

log "Done. 6.1 tree is now: pristine common + HymoFS patch only."
log "To commit in common repo: cd $COMMON_6_1 && git add -A && git status"
