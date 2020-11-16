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

Use CARGO_BUILD_TARGET for cross-compilation (such as for iOS).
END
}

CARGO_PROFILE_ARG=--release

while [ "${1:-}" != "" ]; do
  case $1 in
    -d | --debug )
      CARGO_PROFILE_ARG=
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

set -x
cargo build -p libsignal-ffi ${CARGO_PROFILE_ARG}
