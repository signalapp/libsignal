#!/bin/bash

#
# Copyright 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/..
. ../bin/build_helpers.sh

#
# copy_repo.sh <source> <destination>
#
# Copy the given node directory to the artifact repository.
#
# Example:
# libsignal-client/node$ scripts/copy_repo.sh . ../../libsignal-client-node
#

rsync -avrv \
  --exclude='dist/test' \
  --exclude='node_modules' \
  --exclude='scripts' \
  --exclude='test' \
  --exclude='.gitignore' \
  --exclude='.nvmrc' \
  --exclude='Makefile' \
  --exclude='tsconfig.json' \
  --exclude='BUILDING.md' \
  --exclude='README.md' \
  --exclude='build_node_bridge.py' \
   $1 $2

mkdir -p $2/build
cp -vf ../build/Release/libsignal_client_*.node $2/build

# Ensure that the LICENSE file is up to date.
cp -vf $1/../LICENSE $2

# Ensure that the README.md file is up to date.
cp -vf $1/../README.md $2
