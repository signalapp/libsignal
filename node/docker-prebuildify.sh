#!/bin/bash
# shellcheck disable=SC1004

#
# Copyright 2022 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/..

DOCKER_IMAGE=libsignal-node-builder

IS_TTY=""
if [[ -t 0 ]]; then
    IS_TTY="yes"
fi

docker build --build-arg "UID=${UID:-501}" --build-arg "GID=${GID:-501}" -t ${DOCKER_IMAGE} -f node/Dockerfile .

# We build both architectures in the same run action to save on intermediates
# (including downloading dependencies)
docker run ${IS_TTY:+ -it} --init --rm -v "${PWD}":/home/libsignal/src ${DOCKER_IMAGE} sh -c '
    cd ~/src/node &&
    env CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        CC=aarch64-linux-gnu-gcc \
        CXX=aarch64-linux-gnu-g++ \
        CPATH=/usr/aarch64-linux-gnu/include \
        npx prebuildify --napi -t $(cat ~/.nvmrc) --arch arm64 &&
    npx prebuildify --napi -t $(cat ~/.nvmrc) --arch x64
'
