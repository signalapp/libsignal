#!/bin/bash

#set -ex

brew bundle install --file=- << EOF
brew "awscli"
brew "cmake"
brew "cocoapods"
brew "coreutils"
brew "fnm"
brew "gh"
brew "git"
brew "jq"
brew "just"
brew "pipx"
brew "protobuf"
brew "python"
brew "rocksdb"
brew "ruby"
brew "rustup"
brew "shellcheck"
brew "swiftlint"
brew "taplo"
brew "yamllint"
cask "gcloud-cli"
EOF

# Install Python tools using pipx.
# This keeps their dependencies isolated from other things on your system,
# but is still global state for each tool. We may some day want to switch this to a venv instead.
"$(brew --prefix pipx)/bin/pipx" install "mypy<2.0"
"$(brew --prefix pipx)/bin/pipx" install flake8
"$(brew --prefix pipx)/bin/pipx" inject flake8 \
    flake8-comprehensions \
    flake8-deprecated \
    flake8-import-order \
    flake8-quotes

PATH="$(brew --prefix rustup)/bin:$PATH"
export PATH

repo_root="$(dirname "$0")/.."

just --justfile "$repo_root/justfile" install-stable \
    --target armv7-linux-androideabi,aarch64-linux-android,i686-linux-android,x86_64-linux-android \
    --target x86_64-apple-ios,aarch64-apple-ios,aarch64-apple-ios-sim

# Nightly is used for `just format-rust` and the minimal-versions check in `just check-pre-commit`.
just --justfile "$repo_root/justfile" install-nightly
