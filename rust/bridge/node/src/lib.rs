//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

use neon::prelude::*;

pub mod logging;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    libsignal_bridge::node::register(&mut cx)?;
    cx.export_function("initLogger", logging::init_logger)?;
    Ok(())
}
