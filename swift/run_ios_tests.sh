#!/bin/bash

#
# Copyright 2026 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/..
. bin/build_helpers.sh

CARGO_BUILD_TARGET=aarch64-apple-ios-sim swift/build_ffi.sh --release
swift/build_xcframework.py --simulator-only
export LIBSIGNAL_FFI_XCFRAMEWORK="${CARGO_TARGET_DIR:-target}/LibSignalFfi.xcframework"

# Pick the first available iPhone on the newest installed iOS runtime.
SIMULATOR=$(xcrun simctl list --json devices available iPhone |
  jq -r '[.devices | to_entries | sort_by(.key) | reverse | .[].value | select(length > 0) | .[0]][0].udid // empty')
if [[ -z "${SIMULATOR}" ]]; then
  echo 'error: no iPhone simulator available' >&2
  exit 1
fi

# xcodebuild only passes TEST_RUNNER_-prefixed variables through to the tests.
for name in "${!LIBSIGNAL_TESTING_@}"; do
  export "TEST_RUNNER_${name}=${!name}"
done

echo_then_run xcodebuild test -scheme LibSignalClient -destination "platform=iOS Simulator,id=${SIMULATOR}" "$@"
