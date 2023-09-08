#
# Copyright 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

FROM ubuntu:jammy-20230624@sha256:b060fffe8e1561c9c3e6dea6db487b900100fc26830b9ea2ec966c151ab4c020

COPY java/docker/ docker/
COPY java/docker/apt.conf java/docker/sources.list /etc/apt/

# Bit of a chicken-and-egg problem.
# Ubuntu needs the ca-certificates package before it'll trust our mirror.
# But we can't install it because it doesn't trust our mirror!
# To resolve, we temporarily disable verification.
RUN    apt-get update -oAcquire::https::Verify-Peer=false \
    && apt-get install -oAcquire::https::Verify-Peer=false -y ca-certificates
# Back to normal, verification back on
RUN    apt-get update

# Install only what's needed to set up Rust and Android
# We'll install additional tools at the end to take advantage of Docker's caching of earlier steps.
RUN    apt-get install -y curl openjdk-11-jdk-headless unzip

ARG UID
ARG GID

# Create a user to map the host user to.
RUN    groupadd -o -g "${GID}" libsignal \
    && useradd -m -o -u "${UID}" -g "${GID}" -s /bin/bash libsignal

USER libsignal
ENV HOME /home/libsignal
ENV USER libsignal
ENV SHELL /bin/bash

WORKDIR /home/libsignal

# Android SDK setup...
ARG ANDROID_SDK_FILENAME=commandlinetools-linux-7583922_latest.zip
ARG ANDROID_SDK_SHA=124f2d5115eee365df6cf3228ffbca6fc3911d16f8025bebd5b1c6e2fcfa7faf
ARG ANDROID_API_LEVELS=android-30
ARG ANDROID_BUILD_TOOLS_VERSION=30.0.2
ARG NDK_VERSION=25.2.9519653
ENV ANDROID_HOME /home/libsignal/android-sdk
ENV PATH ${PATH}:${ANDROID_HOME}/tools:${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/cmdline-tools/bin

RUN    curl -O https://dl.google.com/android/repository/${ANDROID_SDK_FILENAME} \
    && echo "${ANDROID_SDK_SHA} ${ANDROID_SDK_FILENAME}" | sha256sum -c - \
    && unzip -q ${ANDROID_SDK_FILENAME} -d android-sdk \
    && rm -rf ${ANDROID_SDK_FILENAME}

RUN    yes | sdkmanager --sdk_root=${ANDROID_HOME} "platforms;${ANDROID_API_LEVELS}" "build-tools;${ANDROID_BUILD_TOOLS_VERSION}" "platform-tools" "ndk;${NDK_VERSION}"

# Pre-download Gradle.
COPY   java/gradle gradle
COPY   java/gradlew gradlew
RUN    ./gradlew --version

# Rust setup...

COPY rust-toolchain rust-toolchain
ARG RUSTUP_SHA=ad1f8b5199b3b9e231472ed7aa08d2e5d1d539198a15c5b1e53c746aad81d27b
ENV PATH="/home/libsignal/.cargo/bin:${PATH}"

RUN    curl -f https://static.rust-lang.org/rustup/archive/1.21.1/x86_64-unknown-linux-gnu/rustup-init -o /tmp/rustup-init \
    && echo "${RUSTUP_SHA} /tmp/rustup-init" | sha256sum -c - \
    && chmod a+x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain "$(cat rust-toolchain)" \
    && rm -rf /tmp/rustup-init

RUN    rustup target add armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android

# Install the full set of tools now that the long setup steps are done.
# Note that we temporarily hop back to root to do this.
USER root
# clang and libclang are used by boring-sys's bindgen;
# otherwise we could use plain old gcc and g++.
RUN    apt-get install -y \
               clang \
               cmake \
               git \
               gpg-agent \
               libclang-dev \
               make
USER libsignal

# Convert ssh to https for git dependency access without a key.
RUN    git config --global url."https://github".insteadOf ssh://git@github

CMD [ "/bin/bash" ]
