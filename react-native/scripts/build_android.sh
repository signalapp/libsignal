#!/usr/bin/env bash
#
# Builds libsignal_ffi.so for Android targets using cargo-ndk.
#
# Prerequisites:
#   - Rust toolchain with Android targets:
#       rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
#   - cargo-ndk: cargo install cargo-ndk
#   - Android NDK (set ANDROID_NDK_HOME or let cargo-ndk find it via ANDROID_HOME)
#
# Usage:
#   ./scripts/build_android.sh [--release]
#
# Output:
#   android/jniLibs/<abi>/libsignal_ffi.so for each target ABI
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RN_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${RN_DIR}/.." && pwd)"
FFI_CRATE="${REPO_ROOT}/rust/bridge/ffi"
JNILIBS_DIR="${RN_DIR}/android/jniLibs"

BUILD_TYPE="debug"
CARGO_PROFILE=""
if [[ "${1:-}" == "--release" ]]; then
    BUILD_TYPE="release"
    CARGO_PROFILE="--release"
fi

# Android target triples and their corresponding ABI directory names
declare -A TARGETS=(
    ["aarch64-linux-android"]="arm64-v8a"
    ["armv7-linux-androideabi"]="armeabi-v7a"
    ["x86_64-linux-android"]="x86_64"
    ["i686-linux-android"]="x86"
)

echo "Building libsignal_ffi for Android (${BUILD_TYPE})..."

for target in "${!TARGETS[@]}"; do
    abi="${TARGETS[$target]}"
    echo "  Building for ${target} (${abi})..."

    cargo ndk --target "${target}" \
        --manifest-path "${FFI_CRATE}/Cargo.toml" \
        -- build ${CARGO_PROFILE} --lib

    # Find the built .so and copy to jniLibs
    TARGET_DIR="${REPO_ROOT}/target/${target}/${BUILD_TYPE}"
    SO_FILE="${TARGET_DIR}/libsignal_ffi.so"

    if [[ ! -f "${SO_FILE}" ]]; then
        echo "ERROR: Expected ${SO_FILE} not found" >&2
        exit 1
    fi

    mkdir -p "${JNILIBS_DIR}/${abi}"
    cp "${SO_FILE}" "${JNILIBS_DIR}/${abi}/libsignal_ffi.so"
    echo "    → ${JNILIBS_DIR}/${abi}/libsignal_ffi.so"
done

# Copy the header file for C++ compilation
echo "Copying signal_ffi.h..."
cp "${REPO_ROOT}/swift/Sources/SignalFfi/signal_ffi.h" "${RN_DIR}/cpp/signal_ffi.h"

echo "Done! Android libraries ready in ${JNILIBS_DIR}"
