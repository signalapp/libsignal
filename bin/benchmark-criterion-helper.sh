#!/usr/bin/env bash
set -euo pipefail
# Don't invoke this directly. See ./benchmark-criterion
# This script is intended to be invoked as a cargo runner.
# Add $LIBSIGNAL_BENCHMARK_ARGS to the arguments if the benchmark is criterion.
if "$@" --help 2>&1 | grep criterion > /dev/null; then
    # We intentionally want to expand the args here
    # shellcheck disable=SC2086
    exec "$@" $LIBSIGNAL_BENCHMARK_ARGS
else
    exec "$@"
fi
