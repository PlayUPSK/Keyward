#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINDRES="${WINDRES:-x86_64-w64-mingw32-windres}"
ICON_SOURCE="$ROOT_DIR/images/keyward-logo-no-text-transparent.png"

if ! command -v "$WINDRES" >/dev/null 2>&1; then
  echo "warning: $WINDRES not found; skipping Windows resource generation" >&2
  exit 0
fi

generate() {
  local package_dir="$1"
  local rc_file="$2"
  local syso_file="$3"

  go run "$ROOT_DIR/scripts/winicon/main.go" \
    -in "$ICON_SOURCE" \
    -out "$ROOT_DIR/$package_dir/keyward.ico"

  (
    cd "$ROOT_DIR/$package_dir"
    "$WINDRES" \
      -J rc \
      -O coff \
      -F pe-x86-64 \
      -i "$rc_file" \
      -o "$syso_file"
  )
}

generate "agents/device-client/cmd/keyward-agent" "keyward-agent.rc" "resource_windows_amd64.syso"
generate "agents/device-client/cmd/keyward-tray" "keyward-tray.rc" "resource_windows_amd64.syso"
generate "agents/server-agent/cmd/keyward-server-agent" "keyward-server-agent.rc" "resource_windows_amd64.syso"

echo "Windows resources generated"
