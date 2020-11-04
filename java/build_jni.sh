#!/bin/sh

#
# Copyright (C) 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

command -v shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

# These paths are relative to the root directory
ANDROID_LIB_DIR=java/android/src/main/jniLibs
DESKTOP_LIB_DIR=java/java/src/main/resources

export RUSTFLAGS="-C link-args=-s"

cd ..

cargo build -Z unstable-options -p libsignal-jni --release --target x86_64-unknown-linux-gnu --out-dir=$DESKTOP_LIB_DIR
cargo ndk --target armv7-linux-androideabi --platform 19 -- build -Z unstable-options -p libsignal-jni --release --out-dir=$ANDROID_LIB_DIR/armeabi-v7a
cargo ndk --target aarch64-linux-android --platform 21 -- build -Z unstable-options -p libsignal-jni --release --out-dir=$ANDROID_LIB_DIR/arm64-v8a
cargo ndk --target i686-linux-android --platform 19 -- build -Z unstable-options -p libsignal-jni --release --out-dir=$ANDROID_LIB_DIR/x86
cargo ndk --target x86_64-linux-android --platform 21 -- build -Z unstable-options -p libsignal-jni --release --out-dir=$ANDROID_LIB_DIR/x86_64
