//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").expect("set by cargo") == "ios" {
        match &*std::env::var("TARGET").expect("set by cargo") {
            "x86_64-apple-ios" | "aarch64-apple-ios-sim" => {
                // Simulator targets, allow testing.
            }
            "x86_64-apple-ios-macabi" | "aarch64-apple-ios-macabi" => {
                // Mac Catalyst targets, allow testing.
            }
            "aarch64-apple-ios" => {
                // iOS device target.
                println!("cargo:rustc-cfg=ios_device_as_detected_in_build_rs")
            }
            target => {
                panic!("unknown iOS target '{}', please add it to build.rs", target)
            }
        }
    }
}
