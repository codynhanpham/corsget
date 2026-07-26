#!/usr/bin/env bash
set -Eeuo pipefail

# Build every release target declared by the project.
# Linux and FreeBSD use cross-rs. Windows and macOS targets are built with
# cargo only when the current host matches the target.

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
TARGET_DIR="target/cross"
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"

TARGETS=(
  "x86_64-unknown-freebsd"
  "armv7-unknown-linux-gnueabihf"
  "armv7-unknown-linux-musleabihf"
  "aarch64-unknown-linux-gnu"
  "aarch64-unknown-linux-musl"
  "riscv64gc-unknown-linux-gnu"
  "x86_64-unknown-linux-gnu"
  "x86_64-unknown-linux-musl"
  "x86_64-pc-windows-msvc"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

TARGET_ALREADY_LISTED=false
for target in "${TARGETS[@]}"; do
  if [[ "$target" == "$HOST_TARGET" ]]; then
    TARGET_ALREADY_LISTED=true
    break
  fi
done
if [[ "$TARGET_ALREADY_LISTED" == false ]]; then
  TARGETS+=("$HOST_TARGET")
fi

if command -v cross >/dev/null 2>&1; then
  CROSS_COMMAND="cross"
else
  echo "error: cross is required for Linux and FreeBSD targets." >&2
  echo "install it with: cargo install cross --git https://github.com/cross-rs/cross" >&2
  exit 1
fi

for target in "${TARGETS[@]}"; do
  case "$target" in
    x86_64-pc-windows-msvc|x86_64-apple-darwin|aarch64-apple-darwin)
      if [[ "$target" != "$HOST_TARGET" ]]; then
        echo "==> Skipping $target (native target; host is $HOST_TARGET)"
        continue
      fi
      COMMAND="cargo"
      ;;
    *)
      if [[ "$target" == "$HOST_TARGET" ]]; then
        COMMAND="cargo"
      else
        COMMAND="$CROSS_COMMAND"
      fi
      ;;
  esac

  echo "==> Building $target"
  "$COMMAND" build --locked --release --target "$target" --target-dir "$TARGET_DIR"
done

echo "All targets built successfully."
