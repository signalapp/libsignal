#
# Copyright 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

# shellcheck shell=bash

check_rust() {
  if ! which rustup > /dev/null && [[ -n "$SHELL" ]]; then
    # Try to find rustup using the user's default shell.
    # This will be important when running from inside Xcode,
    # which does not run in a login shell context.
    RUSTUP_PATH=$("$SHELL" -c 'which rustup' || true)
    if [[ "$RUSTUP_PATH" == /* || "$RUSTUP_PATH" == '~'/* ]]; then
      PATH=$(dirname "$RUSTUP_PATH"):$PATH
    fi
  fi

  if ! which rustup > /dev/null; then
    echo 'error: rustup not found; install Rust from https://rustup.rs/' >&2
    exit 1
  fi

  if [[ -n "${CARGO_BUILD_TARGET:-}" ]] && ! (rustup target list --installed | grep -q "${CARGO_BUILD_TARGET:-}"); then
    echo "error: Rust target ${CARGO_BUILD_TARGET} not installed" >&2
    echo 'note: get it by running' >&2
    printf "\n\t%s\n\n" "rustup +${RUSTUP_TOOLCHAIN:-$(cat ./rust-toolchain)} target add ${CARGO_BUILD_TARGET}" >&2
    exit 1
  fi
}

echo_then_run() {
  echo "$@"
  "$@"
}
