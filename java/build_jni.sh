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
DESKTOP_LIB_DIR=java/client/src/main/resources
SERVER_LIB_DIR=java/server/src/main/resources

export CARGO_PROFILE_RELEASE_DEBUG=1 # enable line tables
export RUSTFLAGS="--cfg aes_armv8 ${RUSTFLAGS:-}" # Enable ARMv8 cryptography acceleration when available

DEBUG_LEVEL_LOGS=
while [ "${1:-}" != "" ]; do
    case "${1:-}" in
        --debug-level-logs )
            DEBUG_LEVEL_LOGS=1
            shift
            ;;
        -* )
            echo "Unrecognized flag $1; expected --debug-level-logs" >&2
            exit 2
            ;;
        *)
            break
    esac
done

if [[ -z "${DEBUG_LEVEL_LOGS:-}" ]]; then
  FEATURES+=("log/release_max_level_info")
fi

# usage: build_desktop_for_arch target_triple host_triple output_dir
build_desktop_for_arch () {
    local CC
    local CXX
    local CPATH

    local lib_dir="${3}/"
    local cpuarch="${1%%-*}"
    case "$cpuarch" in
        x86_64)
            suffix=amd64
            ;;
        aarch64)
            suffix=aarch64
            ;;
        *)
            echo "building for unknown CPU architecture ${cpuarch}; update build_jni.sh"
            exit 2
    esac
    if [[ "$1" != "$2" ]]; then
        # Set up cross-compiling flags
        if [[ "$1" == *-linux-* && "$2" == *-linux-* && -z "${CC:-}" ]]; then
            # When cross-compiling *from* Linux *to* Linux,
            # set up standard cross-compiling environment if not already set
            echo 'setting Linux cross-compilation options...'
            export "CARGO_TARGET_$(echo "$cpuarch" | tr "[:lower:]" "[:upper:]")_UNKNOWN_LINUX_GNU_LINKER"="${cpuarch}-linux-gnu-gcc"
            export CC="${cpuarch}-linux-gnu-gcc"
            export CXX="${cpuarch}-linux-gnu-g++"
            export CPATH="/usr/${cpuarch}-linux-gnu/include"
        fi
    fi

    echo_then_run cargo build -p libsignal-jni -p libsignal-jni-testing --release ${FEATURES:+--features "${FEATURES[*]}"} --target "$1"
    copy_built_library "target/${1}/release" signal_jni "$lib_dir" "signal_jni_${suffix}"
    copy_built_library "target/${1}/release" signal_jni_testing "$lib_dir" "signal_jni_testing_${suffix}"
}

android_abis=()

while [ "${1:-}" != "" ]; do
    case "${1:-}" in
        desktop | server | server-all )
            if [[ "$1" == desktop ]]; then
                lib_dir=$DESKTOP_LIB_DIR
            else
                lib_dir=$SERVER_LIB_DIR
            fi
            # On Linux, cdylibs don't include public symbols from their dependencies,
            # even if those symbols have been re-exported in the Rust source.
            # Using LTO works around this at the cost of a slightly slower build.
            # https://github.com/rust-lang/rfcs/issues/2771
            export CARGO_PROFILE_RELEASE_LTO=thin
            host_triple=$(rustc -vV | sed -n 's|host: ||p')
            if [[ "$1" == "server-all" ]]; then
                build_desktop_for_arch x86_64-unknown-linux-gnu "$host_triple" $lib_dir
                # Enable ARMv8.2 extensions for a production aarch64 server build
                RUSTFLAGS="-C target-feature=+v8.2a ${RUSTFLAGS:-}" \
                    build_desktop_for_arch aarch64-unknown-linux-gnu "$host_triple" $lib_dir
            else
                build_desktop_for_arch "${CARGO_BUILD_TARGET:-$host_triple}" "$host_triple" $lib_dir
            fi
            exit
            ;;

        android )
            android_abis+=(arm64-v8a armeabi-v7a x86_64 x86)
            ;;
        android-arm64 | android-aarch64 )
            android_abis+=(arm64-v8a)
            ;;
        android-arm | android-armv7 )
            android_abis+=(armeabi-v7a)
            ;;
        android-x86_64 )
            android_abis+=(x86_64)
            ;;
        android-x86 | android-i686 )
            android_abis+=(x86)
            ;;
        *)
            echo "Unknown target '${1:-}' (use 'desktop', 'android', or 'android-\$ARCH')" >&2
            exit 2
            ;;
    esac
    shift
done

if (( ${#android_abis[@]} == 0 )); then
    echo "Missing target (use 'desktop', 'android', or 'android-\$ARCH')" >&2
    exit 2
fi

# Everything from here down is Android-only.
export CARGO_PROFILE_RELEASE_OPT_LEVEL=s # optimize for size over speed

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
    echo_then_run cargo build -p libsignal-jni -p libsignal-jni-testing --release ${FEATURES:+--features "${FEATURES[*]}"} -Z unstable-options --target "$rust_target" --artifact-dir "${ANDROID_LIB_DIR}/$abi"
done
