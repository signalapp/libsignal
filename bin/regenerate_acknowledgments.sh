#!/bin/bash

#
# Copyright 2023 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/..
. bin/build_helpers.sh

for template in acknowledgments/*.hbs; do
    echo_then_run cargo about generate --config acknowledgments/about.toml --all-features --fail "$template" --output-file "${template%.hbs}"
done
