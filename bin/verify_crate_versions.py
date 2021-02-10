#!/usr/bin/env python3

#
# Copyright 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

# Verify crate versions and lib package versions are in accord

import sys
import re
import json
import os


def swift_version():
    version_re = re.compile(r".*\.version\s+=\s+'(.*)'")
    for line in open('SignalClient.podspec'):
        match = version_re.match(line)
        if match:
            return match.group(1)
    raise Exception("Could not determine version from SignalClient.podspec")


def java_version():
    version_re = re.compile(r"\s+ext\.version_number\s+=\s+\"(.*)\"")
    for line in open('java/build.gradle'):
        match = version_re.match(line)
        if match:
            return match.group(1)
    raise Exception("Could not determine version from java/build.gradle")


def node_version():
    package_json = json.load(open('package.json'))
    return package_json['version']


def bridge_version(bridge):
    version_re = re.compile('^version = "(.*)"')
    bridge_cargo_toml = os.path.join('rust/bridge/', bridge, 'Cargo.toml')
    for line in open(bridge_cargo_toml):
        match = version_re.match(line)
        if match:
            return match.group(1)
    raise Exception("Could not determine version from ", bridge_cargo_toml)


def main():

    package_versions = {
        'swift': swift_version(),
        'java': java_version(),
        'node': node_version()
    }

    bridge_versions = {
        'swift': bridge_version('ffi'),
        'java': bridge_version('jni'),
        'node': bridge_version('node'),
    }

    rc = 0
    for bridge in ['swift', 'java', 'node']:
        if bridge_versions[bridge] != package_versions[bridge]:
            print("ERROR: Bridge %s has package version %s but crate version is %s" % (
                bridge, package_versions[bridge], bridge_versions[bridge]))
            rc = 1

    return rc


if __name__ == '__main__':
    sys.exit(main())
