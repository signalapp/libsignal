#!/bin/bash

#
# Copyright 2024 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/..
. bin/build_helpers.sh

# Get the list of *handled* error codes and the list of *declared* error codes and compare them.
# When modifying this script, be mindful of potential differences between GNU grep and BSD grep.
if ! diff -U 1 -L 'Codes handled in Error.swift' -L 'Codes declared in signal_ffi.h' \
    <(grep -o -E 'case SignalErrorCode[^:]+' swift/Sources/LibSignalClient/Error.swift | cut -d' ' -f 2 | sort -u) \
    <(grep -o -E '^  SignalErrorCode[^,]+' swift/Sources/SignalFfi/signal_ffi.h | grep -v 'UnknownError' | cut -d' ' -f 3 | sort -u)
then
    printf '\n=== Make sure Error.swift is in sync with the error codes declared in Rust! ===\n\n' >&2
    exit 1
fi
