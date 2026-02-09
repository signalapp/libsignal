#!/bin/bash
set -euo pipefail

echo "=== libsignal React Native devcontainer setup ==="

# Install Copilot CLI
echo "Installing @github/copilot-cli..."
npm install -g @github/copilot-cli

# Verify Rust toolchain
echo "Rust: $(rustc --version)"
echo "Cargo: $(cargo --version)"
echo "cargo-ndk: $(cargo ndk --version 2>/dev/null || echo 'not found')"

# Verify Android NDK
if [ -d "$ANDROID_NDK_HOME" ]; then
    echo "NDK: $ANDROID_NDK_HOME"
else
    echo "WARNING: ANDROID_NDK_HOME not found at $ANDROID_NDK_HOME"
fi

# Verify cross-compilation targets
echo "Rust targets:"
rustup target list --installed | grep -E "android|linux" || true

# Verify build tools
echo "CMake: $(cmake --version | head -1)"
echo "Ninja: $(ninja --version)"
echo "Clang: $(clang --version | head -1)"

echo ""
echo "=== Ready! Next steps ==="
echo "1. cargo build -p libsignal-ffi        # verify native build"
echo "2. cargo ndk -t arm64-v8a build -p libsignal-ffi --lib  # Android cross-compile"
echo ""
