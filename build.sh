#!/bin/bash
# This is what our team needed to do to let Desktop use the rust code.
# We preserve this for anyone else who will encounter this problem
cargo build
nvm use
cd node
npm run build
npm run tsc
mkdir prebuilds
mkdir prebuilds/darwin-arm64
cp ./build/Release/libsignal_client_darwin_arm64.node ./prebuilds/darwin-arm64/electron.abi140.node