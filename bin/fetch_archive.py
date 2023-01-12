#!/usr/bin/env python3

#
# Copyright 2023 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

# This script is based on RingRTC's fetch-artifact.py,
# but simplified for using only as a helper for LibSignalClient.podspec.

import argparse
import hashlib
import os
import sys
import urllib.request

from typing import BinaryIO

UNVERIFIED_DOWNLOAD_NAME = "unverified.tmp"


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Download and verify a build artifact archive.')
    parser.add_argument('-u', '--url',
                        required=True,
                        help='URL of an artifact archive')
    parser.add_argument('-c', '--checksum',
                        required=True,
                        help='sha256sum of the unexpanded artifact archive')
    parser.add_argument('-o', '--output-dir',
                        required=True,
                        help='Directory to store the archives in')
    return parser


def download_if_needed(archive_file: str, url: str, checksum: str) -> BinaryIO:
    try:
        f = open(archive_file, 'rb')
        digest = hashlib.sha256()
        chunk = f.read1()
        while chunk:
            digest.update(chunk)
            chunk = f.read1()
        if digest.hexdigest() == checksum.lower():
            return f
        print("existing file '{}' has non-matching checksum {}; re-downloading...".format(archive_file, digest.hexdigest()), file=sys.stderr)
    except FileNotFoundError:
        pass

    print("downloading {}...".format(archive_file), file=sys.stderr)
    try:
        with urllib.request.urlopen(url) as response:
            digest = hashlib.sha256()
            f = open(UNVERIFIED_DOWNLOAD_NAME, 'w+b')
            chunk = response.read1()
            while chunk:
                digest.update(chunk)
                f.write(chunk)
                chunk = response.read1()
            assert digest.hexdigest() == checksum.lower(), "expected {}, actual {}".format(checksum.lower(), digest.hexdigest())
            os.replace(UNVERIFIED_DOWNLOAD_NAME, archive_file)
            return f
    except urllib.error.HTTPError as e:
        print(e, e.filename, file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    os.makedirs(os.path.abspath(args.output_dir), exist_ok=True)
    os.chdir(args.output_dir)

    archive_file = os.path.basename(args.url)
    download_if_needed(archive_file, args.url, args.checksum)


main()
