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
Usage: $(basename "$0") [-d] [-o DIR/]

Options:
	-d -- debug build (default is release, follows \$CONFIGURATION_NAME)
	-o -- where to copy the built module (default: build/\$CONFIGURATION_NAME)
END
}

CONFIGURATION_NAME=${CONFIGURATION_NAME:-Release}

while [[ "${1:-}" != "" ]]; do
  case $1 in
    -d | --debug )
      CONFIGURATION_NAME=Debug
      ;;
    -o )
      shift
      OUT_DIR="$1"
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

case ${CONFIGURATION_NAME} in
  Debug )
    CARGO_PROFILE_ARG=
    CARGO_PROFILE_DIR=debug
    ;;
  Release )
    CARGO_PROFILE_ARG=--release
    CARGO_PROFILE_DIR=Release
    ;;
  * )
    echo 'error: unexpected CONFIGURATION_NAME:' ${CONFIGURATION_NAME} >&2
    exit 1
esac

OUT_DIR=${OUT_DIR:-build/${CONFIGURATION_NAME}}

check_rust

echo_then_run cargo build -p libsignal-node ${CARGO_PROFILE_ARG}

for possible_library_name in libsignal_node.dylib libsignal_node.so signal_node.dll; do
  possible_library_path="${CARGO_BUILD_TARGET_DIR:-target}/${CARGO_BUILD_TARGET:-}/${CARGO_PROFILE_DIR}/${possible_library_name}"
  if [ -e "${possible_library_path}" ]; then
    echo_then_run mkdir -p "${OUT_DIR}"
    echo_then_run cp "${possible_library_path}" "${OUT_DIR}"/libsignal_client.node
    break
  fi
done
