//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

// To make sure the linkmes work
extern crate libsignal_bridge;
extern crate libsignal_bridge_testing;
extern crate signal_node;

use std::io::Write;
use std::process::{Command, Stdio};

use clap::Parser;
use heck::ToLowerCamelCase;
use libsignal_bridge_types::metadata::node::TsMetadataContext;
use libsignal_bridge_types::net::remote_config::RemoteConfigKey;
use minijinja::context;

#[derive(Parser)]
/// Regenerate Native.ts
///
/// This command assumes it's being invoked from the workspace root.
struct Cli {
    /// Don't actually overwrite Native.ts, just make sure it's up-to-date.
    #[clap(long)]
    verify: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    env.add_filter("to_lower_camel_case", |x: String| x.to_lower_camel_case());
    env.add_filter("return_ffi_type", |x: String| {
        libsignal_bridge_types::metadata::node::names::return_ffi_type(&x)
    });
    env.add_filter("return_converter_function", |x: String| {
        libsignal_bridge_types::metadata::node::names::return_converter_function(&x)
    });
    env.add_filter("arg_ffi_type", |x: String| {
        libsignal_bridge_types::metadata::node::names::arg_ffi_type(&x)
    });
    env.add_filter("arg_converter_function", |x: String| {
        libsignal_bridge_types::metadata::node::names::arg_converter_function(&x)
    });
    env.add_template("Native.ts.in", include_str!("Native.ts.in"))?;
    env.add_template("NativeNice.ts.in", include_str!("NativeNice.ts.in"))?;
    let mut ctx = TsMetadataContext::default();
    for item in libsignal_bridge_types::metadata::node::NODE_ITEMS.iter() {
        // We don't check item.module_path because, unlike other client languages, we emit both
        // testing and non-testing native into the same typescript file.
        (item.apply)(&mut ctx);
    }
    for name in ["Native.ts", "NativeNice.ts"] {
        let tmpl = env.get_template(&format!("{name}.in"))?;
        let code = tmpl.render(context! {
            ctx => ctx,
            remote_config_keys => RemoteConfigKey::KEYS,
        })?;
        let code = {
            let (r, mut w) = std::io::pipe()?;
            std::thread::spawn(move || w.write_all(code.as_bytes()).expect("writing code to pipe"));
            let output = Command::new("npm")
                .current_dir("node")
                .args([
                    "run",
                    "--silent",
                    "format-stdin",
                    "--",
                    "--stdin-filepath",
                    name,
                ])
                .stdin(r)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .output()?;
            anyhow::ensure!(output.status.success(), "prettier failed");
            String::from_utf8(output.stdout)?
        };
        let dst = format!("./node/ts/{name}");
        if args.verify {
            anyhow::ensure!(
                std::fs::read_to_string(dst)? == code,
                "{name} is not up-to-date"
            );
        } else {
            std::fs::write(dst, code.as_bytes())?;
        }
    }
    Ok(())
}
