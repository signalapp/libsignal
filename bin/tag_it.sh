#!/bin/sh

#
# Copyright 2023 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

#set -ex

if [ -z "$1" ]
then
    echo "usage: $(basename "$0") NEW_TAG"
    exit 1
fi

NEW_TAG="$1"
MOST_RECENT_TAG=$(git describe --abbrev=0)
TAG_FILE=$(mktemp)

echo "$NEW_TAG" > "$TAG_FILE"
echo "
# Edit this file as you see fit and it will become the tag annotation.
# Lines started with '#' will-as usual-be ignored.
" >> "$TAG_FILE"

git log "$MOST_RECENT_TAG"..@ --pretty="format:- %s" >> "$TAG_FILE"
git tag -a "$NEW_TAG" -e -F "$TAG_FILE"
