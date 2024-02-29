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

for template in acknowledgments/*.hbs; do
    echo_then_run cargo about generate --config acknowledgments/about.toml --all-features --fail "$template" --output-file "${template%.hbs}"
done
