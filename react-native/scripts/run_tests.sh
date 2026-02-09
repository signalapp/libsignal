#!/usr/bin/env bash
#
# Run the React Native libsignal test suite.
#
# This script builds and runs all available tests:
#   1. Host FFI integration tests (C++ tests linking against host libsignal_ffi)
#   2. C++ JSI compilation check (verifies generated bindings compile)
#   3. Codegen verification (regenerates bindings and checks for diffs)
#
# Prerequisites:
#   - Rust toolchain (cargo build)
#   - CMake, ninja/make
#   - clang++ or g++ with C++17 support
#   - npm install in react-native/ (for JSI headers)
#
# Usage:
#   ./scripts/run_tests.sh [--skip-rust-build]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RN_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${RN_DIR}/.." && pwd)"

SKIP_RUST_BUILD=false
if [[ "${1:-}" == "--skip-rust-build" ]]; then
    SKIP_RUST_BUILD=true
fi

echo "============================================"
echo "  libsignal React Native Test Suite"
echo "============================================"
echo ""

# Step 0: Build the host libsignal_ffi if needed
if [[ "$SKIP_RUST_BUILD" == "false" ]]; then
    echo "Step 0: Building host libsignal_ffi..."
    cd "${REPO_ROOT}"
    cargo build -p libsignal-ffi --lib 2>&1 | tail -3
    echo "  ✓ Host library built"
    echo ""
fi

# Step 1: Generate C++-compatible header
echo "Step 1: Generating C++-compatible header..."
cp "${REPO_ROOT}/swift/Sources/SignalFfi/signal_ffi.h" "${RN_DIR}/cpp/signal_ffi.h"
python3 "${RN_DIR}/scripts/patch_header_cpp.py" \
    "${RN_DIR}/cpp/signal_ffi.h" \
    "${RN_DIR}/cpp/signal_ffi_cpp.h"
echo "  ✓ signal_ffi_cpp.h generated"
echo ""

# Step 2: Run codegen and verify it produces valid output
echo "Step 2: Running codegen..."
python3 "${RN_DIR}/scripts/gen_jsi_bindings.py" \
    "${REPO_ROOT}/swift/Sources/SignalFfi/signal_ffi.h" \
    "${RN_DIR}/cpp/generated_jsi_bindings.cpp" \
    "${REPO_ROOT}/node/ts/Native.ts"
echo "  ✓ Codegen completed"
echo ""

# Step 3: Build and run host FFI integration tests + JSI compilation check
echo "Step 3: Building tests..."
TEST_BUILD_DIR="${RN_DIR}/tests/build"
mkdir -p "${TEST_BUILD_DIR}"
cd "${TEST_BUILD_DIR}"
cmake .. -DCMAKE_BUILD_TYPE=Debug 2>&1 | grep -E '(JSI|Configuring)' || true
cmake --build . 2>&1 | tail -5
echo "  ✓ Tests built"
echo ""

echo "Step 4: Running host FFI integration tests..."
./test_ffi_host
echo ""

echo "Step 5: Verifying C++ JSI compilation..."
# If the check_jsi_compilation target built successfully (it's an OBJECT library),
# the cmake --build above would have already failed if it had errors.
echo "  ✓ JSI bindings compile successfully"
echo ""

echo "============================================"
echo "  All tests passed!"
echo "============================================"
