#!/usr/bin/env python3

#
# Copyright (C) 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import glob
import json
import os
import subprocess
import sys

from typing import Any, Callable, Iterable, List, Mapping, Optional, TypeVar

T = TypeVar('T')


def warn(message: str) -> None:
    if 'GITHUB_ACTIONS' in os.environ:
        print("::warning ::" + message)
    else:
        print("warning: " + message, file=sys.stderr)


def measure_stripped_library_size(lib_path: str) -> int:
    ndk_home = os.environ.get('ANDROID_NDK_HOME')
    if not ndk_home:
        raise Exception("must set ANDROID_NDK_HOME to an Android NDK to run this script")

    strip_glob = os.path.join(ndk_home, 'toolchains', 'llvm', 'prebuilt', '*', 'bin', 'llvm-strip')
    strip = next(glob.iglob(strip_glob), None)
    if not strip:
        raise Exception("NDK does not contain llvm-strip (tried {})".format(strip_glob))

    return len(subprocess.check_output([strip, '-o', '-', lib_path]))


def print_size_diff(lib_size: int, old_entry: Mapping[str, Any], *, warn_on_jump: bool = True) -> None:
    delta = lib_size - old_entry['size']
    delta_fraction = (float(delta) / old_entry['size'])
    message = f"current build is {delta} bytes ({int(delta_fraction * 100)}%) larger than {old_entry['version']}"
    if warn_on_jump and delta > 100_000:
        warn(message)
    else:
        print(message)


def print_size_for_release(lib_size: int) -> None:
    message = f"if this this commit marks a release, update code_size.json with {lib_size}"
    print(message)


def current_origin_main_entry() -> Optional[Mapping[str, Any]]:
    try:
        if os.environ.get('GITHUB_EVENT_NAME') == 'push':
            base_ref = os.environ.get('GITHUB_REF_NAME', 'HEAD^')
            most_recent_commit = subprocess.run(["git", "rev-parse", "HEAD^"], capture_output=True, check=True).stdout.decode().strip()
        else:
            base_ref = os.environ.get('GITHUB_BASE_REF', 'main')
            remote_name = os.environ.get('CHECK_CODE_SIZE_REMOTE', 'origin')
            most_recent_commit = subprocess.run(["git", "merge-base", "HEAD", f"{remote_name}/{base_ref}"], capture_output=True, check=True).stdout.decode().strip()

        repo_path = os.environ.get('GITHUB_REPOSITORY')
        if repo_path is None:
            repo_path = subprocess.run(["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"], capture_output=True, check=True).stdout.decode().strip()

        runs_info = subprocess.run(["gh", "api", "--method=GET", f"repos/{repo_path}/actions/runs", "-f", f"head_sha={most_recent_commit}"], capture_output=True, check=True).stdout
        runs_json = json.loads(runs_info)

        run_id = [run['id'] for run in runs_json['workflow_runs'] if run['name'] == 'Build and Test'][0]

        run_jobs = subprocess.run(["gh", "run", "view", "-R", repo_path, f"{run_id}", "--json", "jobs"], capture_output=True, check=True).stdout
        jobs_json = json.loads(run_jobs)

        job_id = [job['databaseId'] for job in jobs_json['jobs'] if job['name'] == "Java"][0]

        job_logs = subprocess.run(["gh", "run", "view", "-R", repo_path, "--job", f"{job_id}", "--log"], capture_output=True, check=True).stdout.decode()

        for line in job_logs.splitlines():
            if "check_code_size.py" in line and "current: *" in line:
                (_, after) = line.split("(", maxsplit=1)
                (bytes_count, _) = after.split(" bytes)", maxsplit=1)
                return {'size': int(bytes_count), 'version': f"{most_recent_commit[:6]} ({base_ref})"}

        print(f"skipping checking current {base_ref} (most recent run did not include check_code_size.py)", file=sys.stderr)

    except Exception as e:
        print(f"skipping checking current {base_ref}: {e}", file=sys.stderr)
        if isinstance(e, subprocess.CalledProcessError):
            print("stdout:", e.stdout.decode(), file=sys.stderr)
            print("stderr:", e.stderr.decode(), file=sys.stderr)

    return None


our_abs_dir = os.path.dirname(os.path.realpath(__file__))

lib_size = measure_stripped_library_size(os.path.join(
    our_abs_dir, 'android', 'src', 'main', 'jniLibs', 'arm64-v8a', 'libsignal_jni.so'))

with open(os.path.join(our_abs_dir, 'code_size.json')) as old_sizes_file:
    old_sizes = json.load(old_sizes_file)

most_recent_tag_entry = old_sizes[-1]
origin_main_entry = current_origin_main_entry()
if origin_main_entry is not None:
    print_size_diff(lib_size, most_recent_tag_entry, warn_on_jump=False)
    print_size_diff(lib_size, origin_main_entry)
else:
    print_size_diff(lib_size, most_recent_tag_entry)
print_size_for_release(lib_size)


# Typing this properly requires a bunch of helpers in Python 3.9,
# and we don't have a strict type at the use site anyway.
def max_map(items: Iterable[T], transform: Callable[[T], Any]) -> Any:
    return transform(max(items, key=transform))


def print_plot(sizes: List[Mapping[str, Any]]) -> None:
    highest_size = max_map(recent_sizes, lambda x: x['size'])
    version_width = max_map(recent_sizes, lambda x: len(x['version']))

    scale = 1.0 * 1024 * 1024
    while scale < highest_size:
        scale *= 2
    scale /= 20
    plot_width = int(highest_size / scale) + 1

    for entry in sizes:
        bucket = int(entry['size'] / scale) + 1
        print('{:>{}}: {:<{}} ({} bytes)'.format(entry['version'], version_width, '*' * bucket, plot_width, entry['size']))


recent_sizes = old_sizes[-10:]
if origin_main_entry is not None:
    recent_sizes.append(origin_main_entry)
recent_sizes.append({'version': 'current', 'size': lib_size})
print_plot(recent_sizes)
