#!/usr/bin/env python3

#
# Copyright 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

# Keep crate versions and lib package versions in accord

import fileinput
import sys
import re
import os


def read_version(file, pattern):
    with open(file) as f:
        for line in f:
            match = pattern.match(line)
            if match:
                return match.group(2)
    raise Exception(f"Could not determine version from {file}")


def update_version(file, pattern, new_version):
    with fileinput.input(files=(file,), inplace=True) as f:
        for line in f:
            print(pattern.sub(f"\\g<1>{new_version}\\g<3>", line, count=1), end='')


PODSPEC_PATTERN = re.compile(r"^(.*\.version\s+=\s+')(.*)(')")
GRADLE_PATTERN = re.compile(r'^(def\s+version_number\s+=\s+")(.*)(")')
NODE_PATTERN = re.compile(r'^(\s+"version": ")(.*)(")')
CARGO_PATTERN = re.compile(r'^(version = ")(.*)(")')


def bridge_path(bridge):
    return os.path.join('rust', 'bridge', bridge, 'Cargo.toml')


def main():
    os.chdir(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

    if len(sys.argv) > 1:
        new_version = sys.argv[1]
        if new_version[0] == 'v':
            new_version = new_version[1:]
        update_version('LibSignalClient.podspec', PODSPEC_PATTERN, new_version)
        update_version(os.path.join('java', 'build.gradle'), GRADLE_PATTERN, new_version)
        update_version(os.path.join('node', 'package.json'), NODE_PATTERN, new_version)
        update_version(bridge_path('ffi'), CARGO_PATTERN, new_version)
        update_version(bridge_path('jni'), CARGO_PATTERN, new_version)
        update_version(bridge_path('node'), CARGO_PATTERN, new_version)
        return 0

    package_versions = {
        'swift': read_version('LibSignalClient.podspec', PODSPEC_PATTERN),
        'java': read_version(os.path.join('java', 'build.gradle'), GRADLE_PATTERN),
        'node': read_version(os.path.join('node', 'package.json'), NODE_PATTERN)
    }

    bridge_versions = {
        'swift': read_version(bridge_path('ffi'), CARGO_PATTERN),
        'java': read_version(bridge_path('jni'), CARGO_PATTERN),
        'node': read_version(bridge_path('node'), CARGO_PATTERN),
    }

    for bridge in package_versions:
        if bridge_versions[bridge] != package_versions[bridge]:
            print("ERROR: Bridge %s has package version %s but crate version is %s" % (
                bridge, package_versions[bridge], bridge_versions[bridge]))
            return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
