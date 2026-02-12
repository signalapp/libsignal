FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

ARG RUST_TOOLCHAIN=nightly-2025-09-24
ARG NDK_VERSION=27.1.12297006
ARG CMDLINE_TOOLS_VERSION=11076708

# System dependencies for boring-sys (BoringSSL), bindgen, and general build
# libprotobuf-dev provides well-known .proto files (duration.proto, etc.)
# needed by libsignal-net-grpc's build.rs during cross-compilation.
# Emulator deps: libx11-6, libpulse0, libgl1, libnss3, libxcomposite1, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    clang \
    libclang-dev \
    pkg-config \
    protobuf-compiler \
    libprotobuf-dev \
    python3 \
    python3-pip \
    openjdk-21-jdk-headless \
    unzip \
    curl \
    git \
    # Android emulator runtime dependencies
    libx11-6 \
    libpulse0 \
    libgl1 \
    libnss3 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxi6 \
    libxtst6 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libgbm1 \
    libpango-1.0-0 \
    libxrandr2 \
    libxss1 \
    # GUI test apps (gedit for quick X11 verification, x11-apps for xclock)
    gedit \
    x11-apps \
    # vGPU support (mesa VA-API drivers for WSLg GPU acceleration)
    mesa-utils \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# Install Android command-line tools + NDK + emulator + system image
ENV ANDROID_HOME=/opt/android-sdk
RUN mkdir -p ${ANDROID_HOME}/cmdline-tools && \
    curl -sSL "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip" \
      -o /tmp/cmdline-tools.zip && \
    unzip -q /tmp/cmdline-tools.zip -d ${ANDROID_HOME}/cmdline-tools && \
    mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest && \
    rm /tmp/cmdline-tools.zip

ENV PATH="${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/emulator:${PATH}"

RUN yes | sdkmanager --licenses > /dev/null 2>&1 && \
    sdkmanager \
      "ndk;${NDK_VERSION}" \
      "platforms;android-35" \
      "platform-tools" \
      "build-tools;35.0.0" \
      "emulator" \
      "system-images;android-35;google_apis;x86_64"

ENV ANDROID_NDK_HOME=${ANDROID_HOME}/ndk/${NDK_VERSION}

# Create default AVD for testing
RUN echo "no" | ${ANDROID_HOME}/cmdline-tools/latest/bin/avdmanager create avd \
    --name "test_x86_64" \
    --package "system-images;android-35;google_apis;x86_64" \
    --device "pixel_6" \
    --force

# Make Android SDK writable by vscode user (for Gradle)
RUN chmod -R a+rw ${ANDROID_HOME}

# Install Rust as vscode user
USER vscode

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
    --default-toolchain ${RUST_TOOLCHAIN} \
    -y

ENV PATH="/home/vscode/.cargo/bin:${PATH}"

# Add Android cross-compilation targets + cargo-ndk
RUN rustup target add \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android && \
    cargo install cargo-ndk

USER root
