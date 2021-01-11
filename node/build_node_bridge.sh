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

This script is intended to be run as part of \`node-gyp build\` (or
\`yarn install\`). If you run it manually, you must provide certain environment
variables (see below).

Options:
	-d -- debug build (default is release, follows \$CONFIGURATION_NAME)
	-o -- where to copy the built module (default: build/\$CONFIGURATION_NAME)

\$NODE_OS_NAME must also be set to the value of Node's \`os.platform()\`.
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
    CARGO_PROFILE_DIR=release
    ;;
  * )
    echo 'error: unexpected CONFIGURATION_NAME:' ${CONFIGURATION_NAME} >&2
    exit 1
esac

if [[ -z "${NODE_OS_NAME:-}" ]]; then
  echo 'error: NODE_OS_NAME not set' >&2
  echo "note: run through \`yarn install\` to populate this automatically" >&2
  exit 1
fi

OUT_DIR=${OUT_DIR:-build/${CONFIGURATION_NAME}}

check_rust

echo_then_run cargo build -p libsignal-node ${CARGO_PROFILE_ARG}

copy_built_library "${CARGO_BUILD_TARGET_DIR:-target}/${CARGO_BUILD_TARGET:-}/${CARGO_PROFILE_DIR}" signal_node "${OUT_DIR}"/libsignal_client_"${NODE_OS_NAME}".node
