#!/bin/bash

#
# Copyright (C) 2020-2022 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/..
. bin/build_helpers.sh

# These paths are relative to the root directory
ANDROID_LIB_DIR=java/android/src/main/jniLibs
DESKTOP_LIB_DIR=java/shared/resources

export CARGO_PROFILE_RELEASE_DEBUG=1 # enable line tables
export CARGO_PROFILE_RELEASE_OPT_LEVEL=s # optimize for size over speed

case "$1" in
    desktop )
        # On Linux, cdylibs don't include public symbols from their dependencies,
        # even if those symbols have been re-exported in the Rust source.
        # Using LTO works around this at the cost of a slightly slower build.
        # https://github.com/rust-lang/rfcs/issues/2771
        export CARGO_PROFILE_RELEASE_LTO=thin
        echo_then_run cargo build -p libsignal-jni --release
        if [[ -z "${CARGO_BUILD_TARGET:-}" ]]; then
            copy_built_library target/release signal_jni "${DESKTOP_LIB_DIR}/"
        fi
        exit
        ;;
    android )
        android_abis=(arm64-v8a armeabi-v7a x86_64 x86)
        ;;
    android-arm64 | android-aarch64 )
        android_abis=(arm64-v8a)
        ;;
    android-arm | android-armv7 )
        android_abis=(armeabi-v7a)
        ;;
    android-x86_64 )
        android_abis=(x86_64)
        ;;
    android-x86 | android-i686 )
        android_abis=(x86)
        ;;
    *)
        echo "Unknown target (use 'desktop', 'android', or 'android-\$ARCH')" >&2
        exit 2
        ;;
esac

# Everything from here down is Android-only.

# Use full LTO and small BoringSSL curve tables to reduce binary size.
export CFLAGS="-DOPENSSL_SMALL -flto=full ${CFLAGS:-}"
export CARGO_PROFILE_RELEASE_LTO=fat
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

# Use the Android NDK's prebuilt Clang+lld as pqcrypto's compiler and Rust's linker.
ANDROID_TOOLCHAIN_DIR=$(echo "${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt"/*/bin/)
export CC_aarch64_linux_android="${ANDROID_TOOLCHAIN_DIR}/aarch64-linux-android21-clang"
export CC_armv7_linux_androideabi="${ANDROID_TOOLCHAIN_DIR}/armv7a-linux-androideabi21-clang"
export CC_x86_64_linux_android="${ANDROID_TOOLCHAIN_DIR}/x86_64-linux-android21-clang"
export CC_i686_linux_android="${ANDROID_TOOLCHAIN_DIR}/i686-linux-android21-clang"

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${CC_aarch64_linux_android}"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="${CC_armv7_linux_androideabi}"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="${CC_x86_64_linux_android}"
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="${CC_i686_linux_android}"

export TARGET_AR="${ANDROID_TOOLCHAIN_DIR}/llvm-ar"
export RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8 ${RUSTFLAGS:-}" # Enable ARMv8 cryptography acceleration when available

# The 64-bit curve25519-dalek backend is faster than the 32-bit one on at least some armv7a phones.
# Comment out the following to allow the 32-bit backend on 32-bit targets.
export RUSTFLAGS="--cfg curve25519_dalek_bits=\"64\" ${RUSTFLAGS:-}"

target_for_abi() {
    case "$1" in
        arm64-v8a)
            echo aarch64-linux-android
            ;;
        armeabi-v7a)
            echo armv7-linux-androideabi
            ;;
        x86_64)
            echo x86_64-linux-android
            ;;
        x86)
            echo i686-linux-android
            ;;
        *)
            echo "Unknown Android ABI $1; please update build_jni.sh" >&2
            exit 2
            ;;
    esac
}

for abi in "${android_abis[@]}"; do
    rust_target=$(target_for_abi "$abi")
    echo_then_run cargo build -p libsignal-jni --release -Z unstable-options --target "$rust_target" --out-dir "${ANDROID_LIB_DIR}/$abi"
done
