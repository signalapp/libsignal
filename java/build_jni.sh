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

# Keep these settings in sync with .github/workflows/jni_artifacts.yml,
# which builds for Windows as well.
export CARGO_PROFILE_RELEASE_DEBUG=1 # enable line tables
# On Linux, cdylibs don't include public symbols from their dependencies,
# even if those symbols have been re-exported in the Rust source.
# Using LTO works around this at the cost of a slightly slower build.
# https://github.com/rust-lang/rfcs/issues/2771
export CARGO_PROFILE_RELEASE_LTO=thin
export CARGO_PROFILE_RELEASE_OPT_LEVEL=s # optimize for size over speed

if [ "$1" = 'desktop' ];
then
    echo_then_run cargo build -p libsignal-jni --release
    copy_built_library target/release signal_jni "${DESKTOP_LIB_DIR}/"
elif [ "$1" = 'android' ];
then
    # Use small BoringSSL curve tables to reduce binary size on Android.
    export CFLAGS="-DOPENSSL_SMALL -flto=thin ${CFLAGS:-}"

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
    export RUSTFLAGS="-C link-arg=-fuse-ld=lld ${RUSTFLAGS:-}"

    echo_then_run cargo build -p libsignal-jni --release -Z unstable-options --target aarch64-linux-android --out-dir "${ANDROID_LIB_DIR}/arm64-v8a"
    echo_then_run cargo build -p libsignal-jni --release -Z unstable-options --target armv7-linux-androideabi --out-dir "${ANDROID_LIB_DIR}/armeabi-v7a"
    echo_then_run cargo build -p libsignal-jni --release -Z unstable-options --target x86_64-linux-android --out-dir "${ANDROID_LIB_DIR}/x86_64"
    echo_then_run cargo build -p libsignal-jni --release -Z unstable-options --target i686-linux-android --out-dir "${ANDROID_LIB_DIR}/x86"
else
    echo "Unknown target (use 'desktop' or 'android')"
fi

