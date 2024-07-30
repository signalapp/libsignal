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

# usage: copy_built_library target/release signal_jni out_dir/ signal_jni_amd64
copy_built_library() {
  for pattern in "libX.dylib" "libX.so" "X.dll"; do
    possible_library_name="${pattern%X*}${2}${pattern#*X}"
    possible_augmented_name="${pattern%X*}${4}${pattern#*X}"
    possible_library_path="$1/${possible_library_name}"
    if [ -e "${possible_library_path}" ]; then
      out_dir=$(dirname "$3"x) # trailing x to distinguish directories from files
      echo_then_run mkdir -p "${out_dir}"
      echo_then_run cp "${possible_library_path}" "$3/${possible_augmented_name}"
      break
    fi
  done
}

echo_then_run() {
  for x in "$@"; do
    # Put single quotes around any argument with spaces in it.
    if [[ "$x" == *" "* ]]; then
      echo -n "'$x' "
    else
      echo -n "$x "
    fi
  done
  echo
  "$@"
}
