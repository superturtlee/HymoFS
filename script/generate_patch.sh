#!/bin/bash
# Generate patch from modified branch to origin branch
# This script creates a single unified patch file

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HYMOFS_ROOT="$(dirname "$SCRIPT_DIR")"
KERNEL_REPO="$HYMOFS_ROOT/patch_workspace/origin"
PATCH_DIR="$HYMOFS_ROOT/patch"

# Branch names
ORIGIN_BRANCH="oneplus/mt6991_v_15.0.2_ace5_ultra_6.6.89"
MODIFIED_BRANCH="ksu-hymofs-modified"

# Output patch file
PATCH_FILE="$PATCH_DIR/hymofs.patch"

cd "$KERNEL_REPO"

echo "Generating patch..."
echo "  Base branch: $ORIGIN_BRANCH"
echo "  Modified branch: $MODIFIED_BRANCH"
echo "  Output: $PATCH_FILE"

# Generate the diff
git diff "$ORIGIN_BRANCH".."$MODIFIED_BRANCH" > "$PATCH_FILE"

# Get stats
STATS=$(git diff --stat "$ORIGIN_BRANCH".."$MODIFIED_BRANCH" | tail -1)
echo ""
echo "Patch generated: $STATS"
echo "Saved to: $PATCH_FILE"
