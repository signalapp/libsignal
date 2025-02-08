#!/bin/bash

#set -ex

cat << EOF | brew bundle install --file=-
tap "homebrew/bundle"
brew "awscli"
brew "cmake"
brew "cocoapods"
brew "coreutils"
brew "fnm"
brew "gh"
brew "git"
brew "jq"
brew "just"
brew "protobuf"
brew "python"
brew "rocksdb"
brew "ruby"
brew "rustup"
brew "shellcheck"
brew "swiftformat"
brew "swiftlint"
brew "taplo"
brew "terraform"
brew "yamllint"
cask "google-cloud-sdk"
EOF
