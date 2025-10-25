#!/usr/bin/env python3

#
# Copyright 2025 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

import os
import subprocess
import sys
from typing import Iterator


def rust_paths_to_remap() -> Iterator[str]:
    # Repo root
    yield os.path.dirname(os.path.abspath(os.path.dirname(__file__)))

    rust_sysroot = subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip()
    yield rust_sysroot
    # Rust stdlib internals (must go after sysroot)
    yield os.path.join(rust_sysroot, 'lib', 'rustlib', 'src', 'rust')
    # There's a library/ folder inside rustlib/src/rust as well that's also redundant,
    # but (a) there are precompiled strings with library/ as the root in the stdlib,
    # and (b) both the stdlib and libsignal have a core/ subdirectory.

    cargo_home = os.environ.get('CARGO_HOME', os.path.join(os.path.expanduser('~'), '.cargo'))
    # Git dependencies
    yield os.path.join(cargo_home, 'git', 'checkouts')
    # Iterate over all crates.io dependency directories:
    for index_dir in os.scandir(os.path.join(cargo_home, 'registry', 'src')):
        if not index_dir.name.startswith('index.'):
            continue
        yield index_dir.path


def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    # For invoking as `build_helpers.py print-rust-paths-to-remap`.
    print_remap_parser = subparsers.add_parser('print-rust-paths-to-remap')
    print_remap_parser.set_defaults(action='print-rust-paths-to-remap')

    args = parser.parse_args(sys.argv[1:])
    if 'action' not in args:
        parser.print_usage(file=sys.stderr)
        return 1

    # This should be replaced with a `match` when we drop Python 3.9.
    if args.action == 'print-rust-paths-to-remap':
        for path in rust_paths_to_remap():
            print(path)
        return 0
    else:
        raise NotImplementedError(args.action)


if __name__ == '__main__':
    sys.exit(_main())
