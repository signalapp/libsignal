#!/bin/bash

#
# Copyright (C) 2024 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

# This script exists entirely for running inside an environment where `cargo` may not be in PATH
# (*cough* IDEs on Macs *cough*). It falls back to the default rustup install location.

CARGO=cargo

if ! command -v "$CARGO" > /dev/null; then
    CARGO="$HOME/.cargo/bin/cargo"
fi

"$CARGO" "$@"
