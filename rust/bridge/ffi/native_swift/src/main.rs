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
use minijinja::value::DynObject;

#[derive(Parser)]
/// Regenerate NativeNice.swift and NativeNiceTesting.swift
///
/// This command assumes it's being invoked from the workspace root.
struct Cli {
    /// Don't actually overwrite output files, just make sure they're up-to-date.
    #[clap(long)]
    verify: bool,
}

fn preserve_underscores(
    inner: impl Fn(&str) -> String + 'static,
) -> impl Fn(String) -> String + 'static {
    move |x| {
        let x_sans_underscore = x.trim_start_matches('_');
        let core = inner(x_sans_underscore);
        format!("{}{core}", &x[0..(x.len() - x_sans_underscore.len())])
    }
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    // cbindgen does some mangling to avoid identifiers conflicting with keywords
    env.add_filter("to_snake_case", |x: String| match x.as_str() {
        "double" | "Double" => "double_".to_string(),
        _ => preserve_underscores(ToSnakeCase::to_snake_case)(x),
    });
    env.add_filter(
        "to_lower_camel_case",
        preserve_underscores(ToLowerCamelCase::to_lower_camel_case),
    );
    env.add_filter("arg_converter", |ty: String| {
        libsignal_bridge_types::metadata::ffi::names::arg_converter(&ty)
    });
    env.add_filter("return_converter", |ty: String| {
        libsignal_bridge_types::metadata::ffi::names::return_converter(&ty)
    });
    env.add_function("enum_has_payload", |e: DynObject| {
        e.get_value_by_str("variants")
            .expect("missing variants")
            .try_iter()
            .expect("enumerate variants")
            .any(|name_struct_pair| {
                name_struct_pair
                    .get_item_by_index(1)
                    .expect("get_item_by_index()")
                    .as_object()
                    .expect("struct is object")
                    .get_value_by_str("fields")
                    .expect("missing fields")
                    .len()
                    .expect("fields has len")
                    > 0
            })
    });
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
        if !args.verify {
            // If we're not verifying, write the initial code to disk to help us debug syntax errors.
            std::fs::write(&dst, code.as_bytes())?;
        }
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
