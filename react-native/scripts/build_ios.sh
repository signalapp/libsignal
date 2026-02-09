#!/usr/bin/env bash
#
# Builds libsignal_ffi.a for iOS targets (device + simulator).
#
# Prerequisites:
#   - Rust toolchain with iOS targets:
#       rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#   - Xcode command line tools
#
# Usage:
#   ./scripts/build_ios.sh [--release]
#
# Output:
#   ios/libsignal_ffi.a (universal fat binary)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RN_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${RN_DIR}/.." && pwd)"
FFI_CRATE="${REPO_ROOT}/rust/bridge/ffi"

BUILD_TYPE="debug"
CARGO_PROFILE=""
if [[ "${1:-}" == "--release" ]]; then
    BUILD_TYPE="release"
    CARGO_PROFILE="--release"
fi

IOS_TARGETS=(
    "aarch64-apple-ios"
    "aarch64-apple-ios-sim"
    "x86_64-apple-ios"
)

echo "Building libsignal_ffi for iOS (${BUILD_TYPE})..."

BUILT_LIBS=()
for target in "${IOS_TARGETS[@]}"; do
    echo "  Building for ${target}..."
    cargo build ${CARGO_PROFILE} \
        --manifest-path "${FFI_CRATE}/Cargo.toml" \
        --target "${target}" \
        --lib

    LIB_FILE="${REPO_ROOT}/target/${target}/${BUILD_TYPE}/libsignal_ffi.a"
    if [[ ! -f "${LIB_FILE}" ]]; then
        echo "ERROR: Expected ${LIB_FILE} not found" >&2
        exit 1
    fi
    BUILT_LIBS+=("${LIB_FILE}")
done

# Create a universal (fat) library using lipo
echo "Creating universal library..."
mkdir -p "${RN_DIR}/ios"

# Separate device and simulator libs for xcframework-compatible approach
DEVICE_LIB="${REPO_ROOT}/target/aarch64-apple-ios/${BUILD_TYPE}/libsignal_ffi.a"
SIM_LIBS=()
for target in "aarch64-apple-ios-sim" "x86_64-apple-ios"; do
    SIM_LIBS+=("${REPO_ROOT}/target/${target}/${BUILD_TYPE}/libsignal_ffi.a")
done

# Create fat simulator lib
SIM_FAT="${RN_DIR}/ios/libsignal_ffi_sim.a"
lipo -create "${SIM_LIBS[@]}" -output "${SIM_FAT}"

# Copy device lib
cp "${DEVICE_LIB}" "${RN_DIR}/ios/libsignal_ffi.a"

echo "  Device lib: ios/libsignal_ffi.a"
echo "  Simulator lib: ios/libsignal_ffi_sim.a"

# Copy the header file
echo "Copying signal_ffi.h..."
cp "${REPO_ROOT}/swift/Sources/SignalFfi/signal_ffi.h" "${RN_DIR}/cpp/signal_ffi.h"

echo "Done! iOS libraries ready."
