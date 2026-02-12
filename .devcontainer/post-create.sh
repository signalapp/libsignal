#!/usr/bin/env bash
set -euo pipefail

echo "=== libsignal React Native devcontainer setup ==="

# Fix KVM permissions if device is available
if [ -e /dev/kvm ]; then
    sudo chmod 666 /dev/kvm 2>/dev/null || true
    echo "KVM: available (permissions fixed)"
else
    echo "KVM: not available (emulator will be slow)"
    echo "  To enable: mount /dev/kvm into the container"
fi

# Fix target/ directory permissions (volume may have root ownership)
if [ -d "target" ]; then
    sudo chmod -R a+rwX target 2>/dev/null || true
fi

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

# Install react-native library npm deps
if [ -f "react-native/package.json" ]; then
    echo ""
    echo "Installing react-native library npm dependencies..."
    cd react-native && npm install --no-audit --no-fund 2>/dev/null && cd ..
fi

# Install example app npm deps
if [ -f "react-native/example/package.json" ]; then
    echo "Installing example app npm dependencies..."
    cd react-native/example && npm install --no-audit --no-fund 2>/dev/null && cd ../..
fi

echo ""
echo "=== Ready! Next steps ==="
echo "1. Start emulator:  \$ANDROID_HOME/emulator/emulator -avd test_x86_64 -no-window -no-audio -gpu swiftshader_indirect -no-boot-anim -no-snapshot &"
echo "2. Wait for boot:   adb wait-for-device && adb shell 'while [[ \"\$(getprop sys.boot_completed)\" != \"1\" ]]; do sleep 2; done'"
echo "3. Build & test:    See react-native/PROGRESS.md for full instructions"
echo ""
