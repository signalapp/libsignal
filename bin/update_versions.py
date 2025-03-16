#!/usr/bin/env python3

#
# Copyright 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

# Keep crate versions and lib package versions in accord

import collections
import fileinput
import subprocess
import sys
import re
import os


def read_version(file: str, pattern: re.Pattern[str]) -> str:
    with open(file) as f:
        for line in f:
            match = pattern.match(line)
            if match:
                return match.group(2)
    raise Exception(f"Could not determine version from {file}")


def update_version(file: str, pattern: re.Pattern[str], new_version: str) -> None:
    with fileinput.input(files=(file,), inplace=True) as f:
        for line in f:
            print(pattern.sub(f"\\g<1>{new_version}\\g<3>", line, count=1), end='')


# Note that all of these capture three groups; update_version() relies on that.
PODSPEC_PATTERN = re.compile(r"^(.*\.version\s+=\s+')(.*)(')")
GRADLE_PATTERN = re.compile(r'^(\s+version\s+=\s+")(.*)(")')
NODE_PATTERN = re.compile(r'^(\s+"version": ")(.*)(")')
CARGO_PATTERN = re.compile(r'^(version = ")(.*)(")')
RUST_PATTERN = re.compile(r'^(pub const VERSION: &str = ")(.*)(")')
RELEASE_NOTES_PATTERN = re.compile(r'^(v)(.*)()$')


def bridge_path(*bridge: str) -> str:
    return os.path.join('rust', 'bridge', *bridge, 'Cargo.toml')


VERSION_FILES = [
    ('RELEASE_NOTES.md', RELEASE_NOTES_PATTERN),
    ('LibSignalClient.podspec', PODSPEC_PATTERN),
    (os.path.join('java', 'build.gradle'), GRADLE_PATTERN),
    (os.path.join('node', 'package.json'), NODE_PATTERN),
    (os.path.join('rust', 'core', 'src', 'version.rs'), RUST_PATTERN),
    ('Cargo.toml', CARGO_PATTERN),
]


def main() -> int:
    os.chdir(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

    if len(sys.argv) > 1:
        new_version = sys.argv[1]
        if new_version[0] == 'v':
            new_version = new_version[1:]
        for (path, pattern) in VERSION_FILES:
            update_version(path, pattern, new_version)
        # It's hard to update the package-lock.json file in a straightforward way with regexes, so use the appropriate
        # tool.
        subprocess.run(['npm', 'install', '--package-lock-only'], cwd='node')

        return 0

    found_versions = collections.defaultdict(list)
    for (path, pattern) in VERSION_FILES:
        version = read_version(path, pattern)
        found_versions[version].append(path)

    if len(found_versions) != 1:
        print("ERROR: found inconsistent versions:")
        for (version, files) in sorted(found_versions.items()):
            print(f"{version}:")
            for file in files:
                print(f"  {file}")

        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
