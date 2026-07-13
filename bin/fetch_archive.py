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
import subprocess
import sys

UNVERIFIED_DOWNLOAD_NAME = 'unverified.tmp'


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


def download_if_needed(archive_file: str, url: str, checksum: str) -> None:
    try:
        fr = open(archive_file, 'rb')
        digest = hashlib.sha256()
        chunk = fr.read1()
        while chunk:
            digest.update(chunk)
            chunk = fr.read1()
        if digest.hexdigest() == checksum.lower():
            return
        print("existing file '{}' has non-matching checksum {}; re-downloading...".format(archive_file, digest.hexdigest()), file=sys.stderr)
    except FileNotFoundError:
        pass

    print('downloading {}...'.format(archive_file), file=sys.stderr)
    try:
        subprocess.run(
            [
                'curl',
                '--fail',
                '--location',
                '--show-error',
                '--silent',
                '--retry', '3',
                '--output', UNVERIFIED_DOWNLOAD_NAME,
                url,
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print('curl failed to download {} (exit {})'.format(url, e.returncode), file=sys.stderr)
        sys.exit(1)

    digest = hashlib.sha256()
    with open(UNVERIFIED_DOWNLOAD_NAME, 'rb') as fw:
        chunk = fw.read1()
        while chunk:
            digest.update(chunk)
            chunk = fw.read1()
    assert digest.hexdigest() == checksum.lower(), 'expected {}, actual {}'.format(checksum.lower(), digest.hexdigest())

    os.replace(UNVERIFIED_DOWNLOAD_NAME, archive_file)


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    os.makedirs(os.path.abspath(args.output_dir), exist_ok=True)
    os.chdir(args.output_dir)

    archive_file = os.path.basename(args.url)
    download_if_needed(archive_file, args.url, args.checksum)


main()
