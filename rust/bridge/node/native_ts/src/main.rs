//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

// To make sure the linkmes work
extern crate libsignal_bridge;
extern crate libsignal_bridge_testing;
extern crate signal_node;

use clap::Parser;
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
    env.add_template("Native.ts.in", include_str!("Native.ts.in"))?;
    let tmpl = env.get_template("Native.ts.in")?;
    let mut ctx = TsMetadataContext::default();
    for item in libsignal_bridge_types::metadata::node::NODE_ITEMS.iter() {
        // We don't check item.module_path because, unlike other client languages, we emit both
        // testing and non-testing native into the same typescript file.
        (item.apply)(&mut ctx);
    }
    let code = tmpl.render(context! {
        ctx => ctx,
        remote_config_keys => RemoteConfigKey::KEYS,
    })?;
    let dst = "./node/ts/Native.ts";
    if args.verify {
        anyhow::ensure!(
            std::fs::read_to_string(dst)? == code,
            "Native.ts is not up-to-date"
        );
    } else {
        std::fs::write(dst, code.as_bytes())?;
    }
    Ok(())
}
