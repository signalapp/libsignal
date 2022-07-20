//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

use std::convert::TryFrom;

use libsignal_bridge::node::{ResultTypeInfo, SignalNodeError};
use libsignal_protocol::IdentityKeyPair;
use neon::prelude::*;
use neon::types::buffer::TypedArray;

mod logging;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    libsignal_bridge::node::register(&mut cx)?;
    cx.export_function("initLogger", logging::init_logger)?;
    cx.export_function("IdentityKeyPair_Deserialize", identitykeypair_deserialize)?;
    Ok(())
}

/// ts: export function IdentityKeyPair_Deserialize(buffer: Buffer): { publicKey: PublicKey, privateKey: PrivateKey }
fn identitykeypair_deserialize(mut cx: FunctionContext) -> JsResult<JsObject> {
    let buffer = cx.argument::<JsBuffer>(0)?;
    let identity_keypair_or_error = IdentityKeyPair::try_from(buffer.as_slice(&cx));
    let identity_keypair = identity_keypair_or_error.or_else(|e| {
        let module = cx.this();
        SignalNodeError::throw(e, &mut cx, module, "identitykeypair_deserialize")?;
        unreachable!()
    })?;
    let public_key = identity_keypair.public_key().convert_into(&mut cx)?;
    let private_key = identity_keypair.private_key().convert_into(&mut cx)?;
    let result = cx.empty_object();
    result.set(&mut cx, "publicKey", public_key)?;
    result.set(&mut cx, "privateKey", private_key)?;
    Ok(result)
}
