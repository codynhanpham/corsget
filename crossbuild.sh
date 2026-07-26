#!/usr/bin/env bash
set -Eeuo pipefail

# Build every release target declared by the project.
# Linux and FreeBSD use cross-rs; Windows and macOS are built with cargo when
# this script is running on a native host that supports those targets.

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
TARGET_DIR="target/cross"

TARGETS=(
  "x86_64-unknown-freebsd"
  "armv7-unknown-linux-gnueabihf"
  "armv7-unknown-linux-musleabihf"
  "aarch64-unknown-linux-gnu"
  "aarch64-unknown-linux-musl"
  "riscv64gc-unknown-linux-gnu"
  "x86_64-pc-windows-msvc"
  "x86_64-apple-darwin"
)

if command -v cross >/dev/null 2>&1; then
  CROSS_COMMAND="cross"
else
  echo "error: cross is required for Linux and FreeBSD targets." >&2
  echo "install it with: cargo install cross --git https://github.com/cross-rs/cross" >&2
  exit 1
fi

for target in "${TARGETS[@]}"; do
  case "$target" in
    x86_64-pc-windows-msvc|x86_64-apple-darwin)
      COMMAND="cargo"
      ;;
    *)
      COMMAND="$CROSS_COMMAND"
      ;;
  esac

  echo "==> Building $target"
  "$COMMAND" build --locked --release --target "$target" --target-dir "$TARGET_DIR"
done

echo "All targets built successfully."
