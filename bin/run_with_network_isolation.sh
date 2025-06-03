#!/bin/bash
set -euo pipefail

# Script to run commands in a network-isolated namespace
# Usage:
#   ./run_with_network_isolation.sh [command...]
#   ./run_with_network_isolation.sh bash    # interactive shell
#
# If no command is provided, defaults to bash

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Error: This script uses network namespaces, and so it only works on Linux." >&2
    exit 1
fi

RUN_UID=$(id -u)
RUN_GID=$(id -g)
ORIG_PATH="$PATH"

if [ $# -eq 0 ]; then
    # No arguments, default to bash interactive shell
    CMD="bash"
else
    # Multiple arguments, join as command string
    CMD="$*"
fi

DEESCALATE_AND_RUN_CMD="setpriv --reuid=${RUN_UID} --regid=${RUN_GID} --clear-groups -- bash -c \"${CMD}\""
SETUP_NETWORKING="ip link set lo up"

# Enter a network-isolated namespace as root, set up loopback, then run the command as the original user
# We have to pass PATH separetely to the de-escalated environment because it is stripped by sudo for safety.
sudo -E env PATH="$ORIG_PATH" unshare --net -- bash -c "${SETUP_NETWORKING} && ${DEESCALATE_AND_RUN_CMD}"
