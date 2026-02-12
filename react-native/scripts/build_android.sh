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
#   ./scripts/build_android.sh [--release] [--strip] [--abi ABI]
#
# Options:
#   --release    Build with optimizations (smaller binary)
#   --strip      Strip debug symbols (requires --release)
#   --abi ABI    Build only for specified ABI (e.g., arm64-v8a)
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
STRIP_SYMBOLS=false
FILTER_ABI=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)
            BUILD_TYPE="release"
            CARGO_PROFILE="--release"
            shift
            ;;
        --strip)
            STRIP_SYMBOLS=true
            shift
            ;;
        --abi)
            FILTER_ABI="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Find llvm-strip from NDK for stripping
if [[ "$STRIP_SYMBOLS" == "true" ]]; then
    NDK_DIR="${ANDROID_NDK_HOME:-${ANDROID_HOME}/ndk/$(ls -1 ${ANDROID_HOME}/ndk/ 2>/dev/null | sort -V | tail -1)}"
    LLVM_STRIP="${NDK_DIR}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
    if [[ ! -x "$LLVM_STRIP" ]]; then
        echo "ERROR: llvm-strip not found at ${LLVM_STRIP}" >&2
        exit 1
    fi
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

    # Skip if filtering by ABI and this doesn't match
    if [[ -n "$FILTER_ABI" && "$abi" != "$FILTER_ABI" ]]; then
        continue
    fi

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

    if [[ "$STRIP_SYMBOLS" == "true" ]]; then
        "$LLVM_STRIP" "${JNILIBS_DIR}/${abi}/libsignal_ffi.so"
        echo "    → ${JNILIBS_DIR}/${abi}/libsignal_ffi.so (stripped)"
    else
        echo "    → ${JNILIBS_DIR}/${abi}/libsignal_ffi.so"
    fi
done

# Copy the header file for C++ compilation
echo "Copying and patching signal_ffi.h for C++ compatibility..."
cp "${REPO_ROOT}/swift/Sources/SignalFfi/signal_ffi.h" "${RN_DIR}/cpp/signal_ffi.h"

# Create C++-compatible version: cbindgen generates `enum X {}; typedef uint8_t X;`
# which is valid C but invalid C++. Transform to `enum X : uint8_t {};`
# Auto-detect affected enum names rather than hardcoding.
python3 "${RN_DIR}/scripts/patch_header_cpp.py" \
    "${RN_DIR}/cpp/signal_ffi.h" \
    "${RN_DIR}/cpp/signal_ffi_cpp.h"

echo "Done! Android libraries ready in ${JNILIBS_DIR}"
