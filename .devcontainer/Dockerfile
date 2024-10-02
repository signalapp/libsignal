FROM mcr.microsoft.com/devcontainers/base:bookworm

# Install clang, cmake, make, protobuf-compiler, git
RUN apt-get update && \
    apt-get install -y clang libclang-dev cmake make git protobuf-compiler curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*