#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/dist/go}"

DEFAULT_TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

APPS=(
  "agents/device-client|./cmd/keyward-agent|keyward-agent"
  "agents/device-client|./cmd/keyward-tray|keyward-tray"
  "agents/server-agent|./cmd/keyward-server-agent|keyward-server-agent"
)

usage() {
  cat <<'EOF'
usage: scripts/build-go.sh [os/arch ...]

Builds all Go binaries for the provided targets.

Examples:
  scripts/build-go.sh
  scripts/build-go.sh linux/amd64 darwin/arm64

Environment:
  OUTPUT_DIR   Override output directory (default: dist/go)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v go >/dev/null 2>&1; then
  echo "error: go is not installed or not in PATH" >&2
  exit 1
fi

TARGETS=("${@:-}")
if [[ ${#TARGETS[@]} -eq 0 || -z "${TARGETS[0]}" ]]; then
  TARGETS=("${DEFAULT_TARGETS[@]}")
fi

mkdir -p "$OUTPUT_DIR"

for target in "${TARGETS[@]}"; do
  if [[ "$target" == "windows/amd64" ]]; then
    "$ROOT_DIR/scripts/generate-windows-resources.sh"
    break
  fi
done

build_app() {
  local module_dir="$1"
  local package_path="$2"
  local binary_name="$3"
  local goos="$4"
  local goarch="$5"
  local suffix=""
  local -a build_args=("-trimpath" "-buildvcs=false")

  if [[ "$goos" == "windows" ]]; then
    suffix=".exe"
  fi

  if [[ "$goos" == "windows" && "$binary_name" == "keyward-tray" ]]; then
    build_args+=("-ldflags=-H=windowsgui")
  fi

  local target_dir="$OUTPUT_DIR/$goos-$goarch"
  mkdir -p "$target_dir"

  echo "==> $binary_name for $goos/$goarch"
  (
    cd "$ROOT_DIR/$module_dir"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build "${build_args[@]}" -o "$target_dir/$binary_name$suffix" "$package_path"
  )

  if [[ "$goos" == "windows" && "$binary_name" == "keyward-tray" ]]; then
    cp "$ROOT_DIR/$module_dir/cmd/keyward-tray/keyward-tray.exe.manifest" "$target_dir/$binary_name.exe.manifest"
  fi
}

for target in "${TARGETS[@]}"; do
  if [[ "$target" != */* ]]; then
    echo "error: invalid target '$target' (expected os/arch)" >&2
    exit 1
  fi

  goos="${target%%/*}"
  goarch="${target##*/}"

  for app in "${APPS[@]}"; do
    IFS='|' read -r module_dir package_path binary_name <<<"$app"
    build_app "$module_dir" "$package_path" "$binary_name" "$goos" "$goarch"
  done
done

echo
echo "Build artifacts written to $OUTPUT_DIR"
