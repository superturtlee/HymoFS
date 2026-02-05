#!/usr/bin/env bash
set -e

if [ -n "${HYMOFS_REPO}" ] && [ -f "${HYMOFS_REPO}/patch/hymofs.patch" ]; then
    PATCH="${HYMOFS_REPO}/patch/hymofs.patch"
else
    PATCH="/tmp/hymofs.patch"
    curl -LSs -o "$PATCH" "https://raw.githubusercontent.com/Anatdx/HymoFS/dev/patch/hymofs.patch"
fi

echo "[*] Applying HymoFS patch from $PATCH"
cd common && patch -p1 -F 3 < "$PATCH" && cd ..

