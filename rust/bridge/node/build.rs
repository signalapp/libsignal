//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::env;

fn main() {
    if env::var("TARGET").expect("set by Cargo") == "x86_64-unknown-linux-gnu" {
        // The nightly compiler uses a new linker, rust-lld, by default on
        // x86_64-unknown-linux-gnu, which causes issues with the `linkme` crate.
        // We could disable rust-lld instead but then we'd lose out on the faster
        // link times, so pass additional flags to the linker instead. See
        // https://github.com/dtolnay/linkme/issues/94 and
        // https://blog.rust-lang.org/2024/05/17/enabling-rust-lld-on-linux.html#possible-drawbacks
        println!("cargo:rustc-link-arg=-Wl,-z,nostart-stop-gc");
    }
}
