#
# Copyright 2022 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

# Debian bullseye is the basis for Ubuntu 20.04.
FROM --platform=linux/amd64 debian:bullseye-slim

# Install only what's needed to set up Rust and Node.
# We'll install additional tools at the end to take advantage of Docker's caching of earlier steps.
RUN apt-get update && apt-get install -y apt-transport-https ca-certificates xz-utils

# User-specific setup!

ARG UID
ARG GID

# Create a user to map the host user to.
RUN groupadd -o -g "${GID}" libsignal \
    && useradd -m -o -u "${UID}" -g "${GID}" -s /bin/bash libsignal

USER libsignal
ENV HOME /home/libsignal
ENV USER libsignal
ENV SHELL /bin/bash

WORKDIR /home/libsignal

# Rust setup
COPY rust-toolchain rust-toolchain
ENV PATH="/home/libsignal/.cargo/bin:${PATH}"
ARG RUSTUP_SHA=ad1f8b5199b3b9e231472ed7aa08d2e5d1d539198a15c5b1e53c746aad81d27b

ADD --chown=libsignal --chmod=755 --checksum=sha256:${RUSTUP_SHA} \
    https://static.rust-lang.org/rustup/archive/1.21.1/x86_64-unknown-linux-gnu/rustup-init /tmp/rustup-init

RUN    /tmp/rustup-init -y --profile minimal --default-toolchain "$(cat rust-toolchain)" \
    && rm -rf /tmp/rustup-init

RUN rustup target add aarch64-unknown-linux-gnu

# Node setup

ARG NODE_VERSION

ADD --chown=libsignal https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz node.tar.xz

RUN tar -xf node.tar.xz \
    && mv node-v* node \
    && rm -f node.tar.xz

ENV PATH="/home/libsignal/node/bin:${PATH}"

# And finally any bonus packages we're going to need
# Note that we jump back to root for this.
USER root
RUN apt-get install -y clang cmake crossbuild-essential-arm64 git python3 protobuf-compiler
USER libsignal

RUN cargo install dump_syms --no-default-features --features cli

CMD [ "/bin/bash" ]
