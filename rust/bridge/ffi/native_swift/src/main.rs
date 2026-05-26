//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// To make sure the linkmes work
extern crate libsignal_bridge;
extern crate libsignal_bridge_testing;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use clap::Parser;
use heck::{ToLowerCamelCase, ToSnakeCase};
use libsignal_bridge_types::ffi::{FFI_ITEMS, SwiftMetadataContext};
use minijinja::context;

#[derive(Parser)]
/// Regenerate NativeNice.swift and NativeNiceTesting.swift
///
/// This command assumes it's being invoked from the workspace root.
struct Cli {
    /// Don't actually overwrite output files, just make sure they're up-to-date.
    #[clap(long)]
    verify: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    env.add_filter("to_snake_case", |x: String| x.to_snake_case());
    env.add_filter("to_lower_camel_case", |x: String| x.to_lower_camel_case());
    env.add_template("NativeNice.swift.in", include_str!("NativeNice.swift.in"))?;
    let mut non_testing_ctx = SwiftMetadataContext::default();
    let mut testing_ctx = SwiftMetadataContext::default();
    for item in FFI_ITEMS.iter() {
        (item.apply)(
            if item.module_path.starts_with("libsignal_bridge_testing") {
                &mut testing_ctx
            } else {
                &mut non_testing_ctx
            },
        );
    }
    for testing in [false, true] {
        let code = env.get_template("NativeNice.swift.in")?.render(context! {
            non_testing_ctx => non_testing_ctx,
            testing_ctx => testing_ctx,
            testing => testing,
        })?;
        let dst = PathBuf::from(if testing {
            "./swift/Tests/LibSignalClientTests/NativeTestingNice.swift"
        } else {
            "./swift/Sources/LibSignalClient/NativeNice.swift"
        });
        let (r, mut w) = std::io::pipe()?;
        std::thread::spawn(move || w.write_all(code.as_bytes()).expect("write succeeds"));
        let out = Command::new("swift")
            .arg("format")
            .arg("-")
            .stdin(r)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()?;
        anyhow::ensure!(out.status.success(), "swift formatting failed");
        let code = String::from_utf8(out.stdout)?;
        if args.verify {
            anyhow::ensure!(
                std::fs::read_to_string(&dst)? == code,
                "{dst:?} is not up-to-date"
            );
        } else {
            std::fs::write(&dst, code.as_bytes())?;
        }
    }
    Ok(())
}
