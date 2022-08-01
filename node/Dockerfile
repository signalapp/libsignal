#
# Copyright 2022 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

FROM ubuntu:16.04

# Basic dependencies
RUN apt-get update && apt-get install -y apt-transport-https curl

# Newer Clang
# https://blog.kowalczyk.info/article/k/how-to-install-latest-clang-6.0-on-ubuntu-16.04-xenial-wsl.html
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key 2>/dev/null | apt-key add - \
    && echo 'deb https://apt.llvm.org/xenial/ llvm-toolchain-xenial-12 main' >/etc/apt/sources.list.d/llvm.list \
    && apt-get update && apt-get install -y clang-12 libclang-12-dev

# Newer CMake
# https://apt.kitware.com/
RUN curl https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null \
        | gpg --dearmor - >/usr/share/keyrings/kitware-archive-keyring.gpg \
    && echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ xenial main' >/etc/apt/sources.list.d/kitware.list \
    && apt-get update && apt-get install -y cmake

# Newer Python
# https://devguide.python.org/getting-started/setup-building/index.html#install-dependencies
RUN echo 'deb-src http://archive.ubuntu.com/ubuntu/ xenial main restricted' >> /etc/apt/sources.list.d/deb-src.list \
    && apt-get update && apt-get build-dep -y python3 && apt-get install -y zlib1g-dev

# ...which we have to build.
RUN cd /tmp \
    && curl -O https://www.python.org/ftp/python/3.10.5/Python-3.10.5.tar.xz \
    && tar -xf Python-3.10.5.tar.xz \
    && cd Python-3.10.5 \
    && ./configure && make -j && make install \
    # Clean up after ourselves, so the final image isn't bigger than it needs to be.
    && cd / && rm -rf /tmp/Python-3.10.5*

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

RUN curl -f https://static.rust-lang.org/rustup/archive/1.21.1/x86_64-unknown-linux-gnu/rustup-init -o /tmp/rustup-init \
    && echo "${RUSTUP_SHA} /tmp/rustup-init" | sha256sum -c - \
    && chmod a+x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain "$(cat rust-toolchain)" \
    && rm -rf /tmp/rustup-init

RUN rustup target add aarch64-unknown-linux-gnu

# Node setup

COPY .nvmrc .nvmrc

RUN curl -f https://nodejs.org/dist/v$(cat .nvmrc)/node-v$(cat .nvmrc)-linux-x64.tar.xz -o ~/node.tar.xz \
    && tar -xf node.tar.xz \
    && mv node-v* node \
    && rm -f node.tar.xz

ENV PATH="/home/libsignal/node/bin:${PATH}"

# And finally any bonus packages we're going to need
# Note that we jump back to root for this.
USER root
RUN apt-get install -y crossbuild-essential-arm64
USER libsignal

CMD [ "/bin/bash" ]
