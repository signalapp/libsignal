#!/usr/bin/env python3

#
# Copyright (C) 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import os
import json
import subprocess
import sys


def warn(message):
    if 'GITHUB_ACTIONS' in os.environ:
        print("::warning ::" + message)
    else:
        print("warning: " + message, file=sys.stderr)


def print_size_diff(lib_size, old_entry):
    delta = lib_size - old_entry['size']
    delta_fraction = (float(delta) / old_entry['size'])
    message = "current build is {0}% larger than {1} (current: {2} bytes, {1}: {3} bytes)".format(
        int(delta_fraction * 100),
        old_entry['version'],
        lib_size,
        old_entry['size']
    )
    if delta_fraction > 0.10:
        warn(message)
    else:
        print(message)


def current_origin_main_entry():
    try:
        most_recent_main = subprocess.run(["git", "merge-base", "HEAD", "origin/main"], capture_output=True, check=True).stdout.decode().strip()

        repo_path = os.environ.get('GITHUB_REPOSITORY')
        if repo_path is None:
            repo_path = subprocess.run(["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"], capture_output=True, check=True).stdout.decode().strip()

        runs_info = subprocess.run(["gh", "api", "--method=GET", f"repos/{repo_path}/actions/runs", "-f", f"head_sha={most_recent_main}"], capture_output=True, check=True).stdout
        runs_json = json.loads(runs_info)

        run_id = [run['id'] for run in runs_json['workflow_runs'] if run['name'] == 'Build and Test'][0]

        run_jobs = subprocess.run(["gh", "run", "view", f"{run_id}", "--json", "jobs"], capture_output=True, check=True).stdout
        jobs_json = json.loads(run_jobs)

        job_id = [job['databaseId'] for job in jobs_json['jobs'] if job['name'] == "Java"][0]

        job_logs = subprocess.run(["gh", "run", "view", "--job", f"{job_id}", "--log"], capture_output=True, check=True).stdout.decode()

        for line in job_logs.splitlines():
            if "check_code_size.py" in line and "current build" in line:
                (_, after) = line.split("(current: ", maxsplit=1)
                (bytes_count, _) = after.split(" ", maxsplit=1)
                return {'size': int(bytes_count), 'version': most_recent_main[:6] + ' (main)'}

    except Exception as e:
        print("skipping checking current origin/main:", e, file=sys.stderr)
        if isinstance(e, subprocess.CalledProcessError):
            print("stdout:", e.stdout.decode(), file=sys.stderr)
            print("stderr:", e.stderr.decode(), file=sys.stderr)

    return None


our_abs_dir = os.path.dirname(os.path.realpath(__file__))

lib_size = os.path.getsize(os.path.join(
    our_abs_dir, 'android', 'build', 'intermediates', 'stripped_native_libs', 'release', 'stripReleaseDebugSymbols',
    'out', 'lib', 'arm64-v8a', 'libsignal_jni.so'))

with open(os.path.join(our_abs_dir, 'code_size.json')) as old_sizes_file:
    old_sizes = json.load(old_sizes_file)

most_recent_tag_entry = old_sizes[-1]
print_size_diff(lib_size, most_recent_tag_entry)

origin_main_entry = current_origin_main_entry()
if origin_main_entry is not None:
    print_size_diff(lib_size, origin_main_entry)


def print_plot(sizes):
    highest_size = max(recent_sizes, key=lambda x: x['size'])['size']

    scale = 1 * 1024 * 1024
    while scale < highest_size:
        scale *= 2
    scale /= 20

    for entry in sizes:
        bucket = int(entry['size'] / scale) + 1
        print('{:>14}: {} ({} bytes)'.format(entry['version'], '*' * bucket, entry['size']))


recent_sizes = old_sizes[-10:]
if origin_main_entry is not None:
    recent_sizes.append(origin_main_entry)
recent_sizes.append({'version': 'current', 'size': lib_size})
print_plot(recent_sizes)
