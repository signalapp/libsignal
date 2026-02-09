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

# Verify Android emulator
echo "Emulator AVDs:"
$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager list avd -c 2>/dev/null || echo "  (none)"

# Check KVM availability
if [ -e /dev/kvm ]; then
    echo "KVM: available (hardware acceleration enabled)"
else
    echo "KVM: not available (emulator will be slow)"
    echo "  To enable: rebuild container on a host with KVM support"
fi

# Check WSLg / X11 availability
echo ""
echo "--- WSLg / X11 status ---"
if [ -S "/tmp/.X11-unix/X0" ]; then
    echo "X11 socket: found (/tmp/.X11-unix/X0)"
else
    echo "X11 socket: NOT found — GUI apps will not work"
fi
echo "DISPLAY=${DISPLAY:-<not set>}"
echo "WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-<not set>}"
echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-<not set>}"
echo "PULSE_SERVER=${PULSE_SERVER:-<not set>}"
if [ -e /dev/dxg ]; then
    echo "vGPU (dxg): available"
else
    echo "vGPU (dxg): not available (software rendering only)"
fi
if [ -d /usr/lib/wsl/lib ]; then
    echo "WSL lib: found (/usr/lib/wsl/lib)"
else
    echo "WSL lib: NOT found"
fi

# Install react-native npm deps if present
if [ -f "react-native/package.json" ]; then
    echo ""
    echo "Installing react-native npm dependencies..."
    cd react-native && npm install --no-audit --no-fund 2>/dev/null && cd ..
fi

echo ""
echo "=== Ready! Next steps ==="
echo "1. Test X11: gedit or xclock"
echo "2. cargo build -p libsignal-ffi        # verify native build"
echo "3. react-native/scripts/build_android.sh --release --strip  # Android cross-compile"
echo "4. react-native/scripts/run_tests.sh    # run tests"
echo "5. \$ANDROID_HOME/emulator/emulator -avd test_device -no-audio  # start emulator"
echo ""
