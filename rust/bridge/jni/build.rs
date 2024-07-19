//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::env;

fn main() {
    if env::var("CARGO_CFG_TARGET_ARCH").expect("set by Cargo") == "aarch64"
        && env::var("CARGO_CFG_TARGET_OS").expect("set by Cargo") == "android"
    {
        // HACK: Force libdl to be linked.
        // Something about the Docker-based build results in it getting skipped;
        // if we figure out what, we can remove this.
        println!("cargo:rustc-cdylib-link-arg=-Wl,--no-as-needed,-ldl,--as-needed");
    }
}
