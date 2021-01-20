//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge::node::*;
use libsignal_bridge::*;
use libsignal_protocol_rust::*;
use neon::context::Context;
use neon::prelude::*;

fn return_boolean<'a>(
    cx: &mut FunctionContext<'a>,
    value: Result<bool, SignalProtocolError>,
) -> JsResult<'a, JsValue> {
    match value {
        Ok(v) => Ok(cx.boolean(v).upcast()),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

#[allow(non_snake_case)]
fn PrivateKey_generate(mut cx: FunctionContext) -> JsResult<JsValue> {
    let mut rng = rand::rngs::OsRng;
    let keypair = KeyPair::generate(&mut rng);
    return_boxed_object(&mut cx, Ok(keypair.private_key))
}

#[allow(non_snake_case)]
fn PrivateKey_getPublicKey(mut cx: FunctionContext) -> JsResult<JsValue> {
    let obj = cx.argument::<DefaultJsBox<PrivateKey>>(0)?;
    let new_obj = obj.public_key();
    return_boxed_object(&mut cx, new_obj)
}

#[allow(non_snake_case)]
fn PrivateKey_sign(mut cx: FunctionContext) -> JsResult<JsValue> {
    let key = cx.argument::<DefaultJsBox<PrivateKey>>(0)?;
    let message = cx.argument::<JsBuffer>(1)?;

    let mut rng = rand::rngs::OsRng;
    let signature = {
        let guard = cx.lock();
        let message = message.borrow(&guard);
        key.calculate_signature(message.as_slice::<u8>(), &mut rng)
    };

    return_binary_data(&mut cx, signature)
}

#[allow(non_snake_case)]
fn PrivateKey_agree(mut cx: FunctionContext) -> JsResult<JsValue> {
    let key = cx.argument::<DefaultJsBox<PrivateKey>>(0)?;
    let other_key = cx.argument::<DefaultJsBox<PublicKey>>(1)?;

    let shared_secret = key.calculate_agreement(&other_key);
    return_binary_data(&mut cx, shared_secret)
}

#[allow(non_snake_case)]
fn PublicKey_verify(mut cx: FunctionContext) -> JsResult<JsValue> {
    let key = cx.argument::<DefaultJsBox<PublicKey>>(0)?;
    let message = cx.argument::<JsBuffer>(1)?;
    let signature = cx.argument::<JsBuffer>(2)?;

    let ok = {
        let guard = cx.lock();
        let message = message.borrow(&guard);
        let signature = signature.borrow(&guard);
        key.verify_signature(message.as_slice::<u8>(), signature.as_slice::<u8>())
    };

    return_boolean(&mut cx, ok)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("PrivateKey_generate", PrivateKey_generate)?;
    cx.export_function("PrivateKey_deserialize", node_PrivateKey_deserialize)?;
    cx.export_function("PrivateKey_serialize", node_PrivateKey_serialize)?;
    cx.export_function("PrivateKey_sign", PrivateKey_sign)?;
    cx.export_function("PrivateKey_agree", PrivateKey_agree)?;
    cx.export_function("PrivateKey_getPublicKey", PrivateKey_getPublicKey)?;

    cx.export_function("PublicKey_verify", PublicKey_verify)?;
    cx.export_function("PublicKey_deserialize", node_PublicKey_deserialize)?;
    cx.export_function("PublicKey_serialize", node_PublicKey_serialize)?;
    Ok(())
}
