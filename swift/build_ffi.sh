#!/bin/bash

#
# Copyright 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/..
. bin/build_helpers.sh

usage() {
  cat >&2 <<END
Usage: $(basename "$0") [-d]

Options:
	-d -- debug build (default is release)
	-v -- verbose build

Use CARGO_BUILD_TARGET for cross-compilation (such as for iOS).
END
}

RELEASE_BUILD=1
CARGO_PROFILE_DIR=release
VERBOSE=

while [ "${1:-}" != "" ]; do
  case $1 in
    -d | --debug )
      RELEASE_BUILD=
      CARGO_PROFILE_DIR=debug
      ;;
    -v | --verbose )
      VERBOSE=1
      ;;
    -h | --help )
      usage
      exit
      ;;
    * )
      usage
      exit 1
  esac
  shift
done

check_rust

check_cbindgen() {
  if ! which cbindgen > /dev/null; then
    echo 'error: cbindgen not found in PATH' >&2
    if which cargo > /dev/null; then
      echo 'note: get it by running' >&2
      printf "\n\t%s\n\n" "cargo install cbindgen --vers '^0.16'" >&2
    fi
    exit 1
  fi
}

check_cbindgen

if [[ -n "${DEVELOPER_SDK_DIR:-}" ]]; then
  # Assume we're in Xcode, which means we're probably cross-compiling.
  # In this case, we need to add an extra library search path for build scripts and proc-macros,
  # which run on the host instead of the target.
  # (macOS Big Sur does not have linkable libraries in /usr/lib/.)
  export LIBRARY_PATH="${DEVELOPER_SDK_DIR}/MacOSX.sdk/usr/lib:${LIBRARY_PATH:-}"
fi

set -x
cargo build -p libsignal-ffi ${RELEASE_BUILD:+--release} ${VERBOSE:+--verbose}
cbindgen ${RELEASE_BUILD:+--profile release} \
  -o "${CARGO_BUILD_TARGET_DIR:-target}/${CARGO_BUILD_TARGET:-}/${CARGO_PROFILE_DIR}"/signal_ffi.h \
  rust/bridge/ffi
