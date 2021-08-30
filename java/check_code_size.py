#!/usr/bin/env python3

#
# Copyright (C) 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import os
import json
import sys


def warn(message):
    if 'GITHUB_ACTIONS' in os.environ:
        print("::warning ::" + message)
    else:
        print("warning: " + message, file=sys.stderr)


our_abs_dir = os.path.dirname(os.path.realpath(__file__))

lib_size = os.path.getsize(os.path.join(
    our_abs_dir, 'android', 'build', 'intermediates', 'stripped_native_libs', 'release', 'out',
    'lib', 'arm64-v8a', 'libsignal_jni.so'))

with open(os.path.join(our_abs_dir, 'code_size.json')) as old_sizes_file:
    old_sizes = json.load(old_sizes_file)

most_recent_tag_size = old_sizes[-1]
delta = lib_size - most_recent_tag_size['size']
delta_fraction = (float(delta) / most_recent_tag_size['size'])
message = "current build is {0}% larger than v{1} (current: {2} bytes, v{1}: {3} bytes)".format(
    int(delta_fraction * 100),
    most_recent_tag_size['version'],
    lib_size,
    most_recent_tag_size['size']
)
if delta_fraction > 0.10:
    warn(message)
else:
    print(message)


def print_plot(sizes):
    highest_size = max(recent_sizes, key=lambda x: x['size'])['size']

    scale = 1 * 1024 * 1024
    while scale < highest_size:
        scale *= 2
    scale /= 20

    for entry in sizes:
        bucket = int(entry['size'] / scale) + 1
        print('{:>12}: {} ({} bytes)'.format(entry['version'], '*' * bucket, entry['size']))


recent_sizes = old_sizes[-10:]
recent_sizes.append({'version': 'current', 'size': lib_size})
print_plot(recent_sizes)
