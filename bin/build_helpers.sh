#
# Copyright 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

# shellcheck shell=bash

check_rust() {
  if ! command -v rustup > /dev/null && [[ -d ~/.cargo/bin ]]; then
    # Try to find rustup in its default per-user install location.
    # This will be important when running from inside Xcode,
    # which does not run in a login shell context.
    PATH=~/.cargo/bin:$PATH
  fi

  if ! command -v rustup > /dev/null; then
    if ! command -v cargo > /dev/null; then
      echo 'error: cargo not found in PATH; do you have Rust installed?' >&2
      echo 'note: we recommend installing Rust via rustup from https://rustup.rs/' >&2
      exit 1
    fi

    echo 'warning: rustup not found in PATH; using cargo at' "$(command -v cargo)" >&2
    echo 'note: this project uses Rust toolchain' "'$(cat ./rust-toolchain)'" >&2
    return
  fi

  if [[ -n "${CARGO_BUILD_TARGET:-}" ]] && ! (rustup target list --installed | grep -q "${CARGO_BUILD_TARGET:-}"); then
    # TODO: We could remove this once Catalyst support is promoted to tier 2
    if [[ -n "${BUILD_STD:-}" ]]; then
      echo "warning: Building using -Zbuild-std to support tier 3 target ${CARGO_BUILD_TARGET}." >&2
    else
      echo "error: Rust target ${CARGO_BUILD_TARGET} not installed" >&2
      echo 'note: get it by running' >&2
      printf "\n\t%s\n\n" "rustup +${RUSTUP_TOOLCHAIN:-$(cat ./rust-toolchain)} target add ${CARGO_BUILD_TARGET}" >&2
      exit 1
    fi
  fi
}

# usage: copy_built_library target/release signal_node out_dir/libsignal_node.node
#        copy_built_library target/release signal_jni out_dir/
copy_built_library() {
  for possible_library_name in "lib$2.dylib" "lib$2.so" "$2.dll"; do
    possible_library_path="$1/${possible_library_name}"
    if [ -e "${possible_library_path}" ]; then
      out_dir=$(dirname "$3"x) # trailing x to distinguish directories from files
      echo_then_run mkdir -p "${out_dir}"
      echo_then_run cp "${possible_library_path}" "$3"
      break
    fi
  done
}

echo_then_run() {
  echo "$@"
  "$@"
}
