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
