//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::bridge_fn;
use libsignal_bridge_types::net::tokio::TokioAsyncContext;

use crate::support::*;
use crate::*;

bridge_handle_fns!(TokioAsyncContext, clone = false);

#[bridge_fn]
fn TokioAsyncContext_new() -> TokioAsyncContext {
    TokioAsyncContext::new()
}

#[bridge_fn]
fn TokioAsyncContext_cancel(context: &TokioAsyncContext, raw_cancellation_id: u64) {
    context.cancel(raw_cancellation_id.into())
}
