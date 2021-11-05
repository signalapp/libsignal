#!/bin/bash

#
# Copyright (C) 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/..
. bin/build_helpers.sh

# These paths are relative to the root directory
ANDROID_LIB_DIR=java/android/src/main/jniLibs
DESKTOP_LIB_DIR=java/java/src/main/resources

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
    copy_built_library target/release signal_jni $DESKTOP_LIB_DIR/
elif [ "$1" = 'android' ];
then
    echo_then_run cargo ndk --target armv7-linux-androideabi --platform 19 -- build -Z unstable-options -p libsignal-jni --release --out-dir=$ANDROID_LIB_DIR/armeabi-v7a
    echo_then_run cargo ndk --target aarch64-linux-android --platform 21 -- build -Z unstable-options -p libsignal-jni --release --out-dir=$ANDROID_LIB_DIR/arm64-v8a
    echo_then_run cargo ndk --target i686-linux-android --platform 19 -- build -Z unstable-options -p libsignal-jni --release --out-dir=$ANDROID_LIB_DIR/x86
    echo_then_run cargo ndk --target x86_64-linux-android --platform 21 -- build -Z unstable-options -p libsignal-jni --release --out-dir=$ANDROID_LIB_DIR/x86_64
else
    echo "Unknown target (use 'desktop' or 'android')"
fi

