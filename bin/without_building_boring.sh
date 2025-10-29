#!/bin/bash

# This is expected to be the path to a BoringSSL *build* directory,
# but if we set it to the *source* directory it's enough for bindgen to run.
# And we can use a relative path because build scripts run from the package root).
export BORING_BSSL_PATH=deps/boringssl/src
command "$@"
