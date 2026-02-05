#!/usr/bin/env bash
# 将单一源文件 src/hymofs.c 同步到各内核分支的 fs 目录，便于后续只改一处即可生效。
# 使用: 在 HymoFS 仓库根目录执行 ./scripts/sync-hymofs-single-source.sh

set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_FILE="$REPO_ROOT/src/hymofs.c"
PATCH_WS="$REPO_ROOT/patch_workspace"

if [ ! -f "$SRC_FILE" ]; then
    echo "Error: $SRC_FILE not found."
    exit 1
fi

for dir in "$PATCH_WS"/android*-*/common/fs "$PATCH_WS"/dev/common/fs; do
    if [ -d "$dir" ]; then
        cp "$SRC_FILE" "$dir/hymofs.c"
        echo "  synced -> $dir/hymofs.c"
    fi
done

echo "Done. All branches + dev use single source: src/hymofs.c"
