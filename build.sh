#!/bin/bash
cargo build
nvm use
cd node
#npm install
npm run build
npm run tsc
# cp -b ./prebuilds/darwin-arm64/electron.abi140.node ./backups/electron.abi140.node.bk
# rm ./prebuilds/darwin-arm64/electron.abi140.node
cp ./build/Release/libsignal_client_darwin_arm64.node ./prebuilds/darwin-arm64/electron.abi140.node