#!/bin/bash

#
# Copyright 2023 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/..
. bin/build_helpers.sh

echo "Checking cargo-about version"
VERSION=$(cargo about --version)
echo "Found $VERSION"

EXPECTED_VERSION="cargo-about $(cat acknowledgments/cargo-about-version)"
if [ "$VERSION" != "$EXPECTED_VERSION" ]; then
	echo "This tool works with $EXPECTED_VERSION but $VERSION is installed"
	false
fi

generate() {
	template="$1"
	output="$2"
	shift 2
	echo_then_run cargo about generate \
		--config acknowledgments/about.toml \
		--all-features --fail \
		"$template" --output-file "$output" \
		"$@"
}

# List every target we ship, just in case some dependencies are platform-gated.
ANDROID_TARGETS=(
	aarch64-linux-android
	armv7-linux-androideabi
	i686-linux-android
	x86_64-linux-android
)
DESKTOP_TARGETS=(
	aarch64-apple-darwin
	aarch64-pc-windows-msvc
	aarch64-unknown-linux-gnu
	x86_64-apple-darwin
	x86_64-pc-windows-msvc
	x86_64-unknown-linux-gnu
)
IOS_TARGETS=(aarch64-apple-ios)

# shellcheck disable=SC2068  # We want "--target" to end up as a separate argument.
generate acknowledgments/acknowledgments{.html.hbs,.html} ${DESKTOP_TARGETS[@]/#/--target } ${IOS_TARGETS[@]/#/--target } ${ANDROID_TARGETS[@]/#/--target } --workspace
# shellcheck disable=SC2068
generate acknowledgments/acknowledgments{.md.hbs,-android.md} ${ANDROID_TARGETS[@]/#/--target } --manifest-path rust/bridge/jni/Cargo.toml
# shellcheck disable=SC2068
generate acknowledgments/acknowledgments{.md.hbs,-android-testing.md} ${ANDROID_TARGETS[@]/#/--target } --manifest-path rust/bridge/jni/testing/Cargo.toml
# shellcheck disable=SC2068
generate acknowledgments/acknowledgments{.md.hbs,-desktop.md} ${DESKTOP_TARGETS[@]/#/--target } --manifest-path rust/bridge/node/Cargo.toml
# shellcheck disable=SC2068
generate acknowledgments/acknowledgments{.plist.hbs,-ios.plist} ${IOS_TARGETS[@]/#/--target } --manifest-path rust/bridge/ffi/Cargo.toml
