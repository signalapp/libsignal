#!/usr/bin/env python3

#
# Copyright 2026 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import argparse
import itertools
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SLICES = [
    ['aarch64-apple-ios'],
    ['aarch64-apple-ios-sim', 'x86_64-apple-ios'],
]
SIMULATOR_ONLY_SLICES = [
    ['aarch64-apple-ios-sim'],
]


def run(*args: str) -> None:
    print(shlex.join(args))
    subprocess.run(args, check=True)


def library_path(target_dir: Path, target: str) -> Path:
    return target_dir / target / 'release' / 'libsignal_ffi.a'


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Packages release builds of libsignal_ffi.a into LibSignalFfi.xcframework.',
        epilog='Build each target first with `CARGO_BUILD_TARGET=<target> swift/build_ffi.sh --release`.',
    )
    parser.add_argument('--simulator-only', action='store_true', help='package only aarch64-apple-ios-sim')
    parser.add_argument('--zip', action='store_true', help='also write LibSignalFfi.xcframework.zip')
    args = parser.parse_args()

    os.chdir(Path(__file__).resolve().parent.parent)
    target_dir = Path(os.environ.get('CARGO_TARGET_DIR', 'target'))
    output = target_dir / 'LibSignalFfi.xcframework'
    zip_output = target_dir / 'LibSignalFfi.xcframework.zip'
    slices = SIMULATOR_ONLY_SLICES if args.simulator_only else SLICES

    missing = [
        target
        for target in itertools.chain.from_iterable(slices)
        if not library_path(target_dir, target).exists()
    ]
    if missing:
        for target in missing:
            print(f'error: {library_path(target_dir, target)} not found', file=sys.stderr)
        build_command = ' && '.join(f'CARGO_BUILD_TARGET={target} swift/build_ffi.sh --release' for target in missing)
        print('note: build them by running', file=sys.stderr)
        print(f'\n\t{build_command}\n', file=sys.stderr)
        return 1

    shutil.rmtree(output, ignore_errors=True)
    zip_output.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory() as work_dir:
        library_args: list[str] = []
        for targets in slices:
            if len(targets) == 1:
                slice_library = library_path(target_dir, targets[0])
            else:
                slice_library = Path(work_dir) / targets[0] / 'libsignal_ffi.a'
                slice_library.parent.mkdir()
                run(
                    'lipo', '-create',
                    *(str(library_path(target_dir, target)) for target in targets),
                    '-output', str(slice_library),
                )
            library_args += ['-library', str(slice_library)]

        # Omit -headers: Package.swift's SignalFfi target provides them, so it never references this binary.
        run('xcodebuild', '-create-xcframework', *library_args, '-output', str(output))

    if args.zip:
        # --norsrc, --noextattr, --noacl and --noqtn keep macOS metadata (resource forks, extended
        # attributes, etc) out of the archive.
        run(
            'ditto', '-c', '-k', '--norsrc', '--noextattr', '--noacl', '--noqtn', '--keepParent',
            str(output), str(zip_output),
        )

    return 0


if __name__ == '__main__':
    sys.exit(main())
