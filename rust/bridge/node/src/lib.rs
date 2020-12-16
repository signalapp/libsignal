//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol_rust::*;
use neon::context::Context;
use neon::prelude::*;
use std::convert::TryFrom;
use std::ops::Deref;

struct DefaultFinalize<T>(T);

impl<T> Finalize for DefaultFinalize<T> {}

impl<T> Deref for DefaultFinalize<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

type DefaultJsBox<T> = JsBox<DefaultFinalize<T>>;

fn return_boxed_object<'a, T: 'static + Send>(
    cx: &mut FunctionContext<'a>,
    value: Result<T, SignalProtocolError>,
) -> JsResult<'a, JsValue> {
    match value {
        Ok(v) => Ok(cx.boxed(DefaultFinalize(v)).upcast()),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

fn return_boolean<'a>(
    cx: &mut FunctionContext<'a>,
    value: Result<bool, SignalProtocolError>,
) -> JsResult<'a, JsValue> {
    match value {
        Ok(v) => Ok(cx.boolean(v).upcast()),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

fn return_binary_data<'a, T: AsRef<[u8]>>(
    cx: &mut FunctionContext<'a>,
    bytes: Result<T, SignalProtocolError>,
) -> JsResult<'a, JsValue> {
    match bytes {
        Ok(bytes) => {
            let bytes = bytes.as_ref();

            let bytes_len = match u32::try_from(bytes.len()) {
                Ok(l) => l,
                Err(_) => {
                    return cx.throw_error("Cannot return very large object to JS environment")
                }
            };
            let mut buffer = cx.buffer(bytes_len)?;
            cx.borrow_mut(&mut buffer, |raw_buffer| {
                raw_buffer.as_mut_slice().copy_from_slice(&bytes);
            });
            Ok(buffer.upcast())
        }
        Err(e) => cx.throw_error(e.to_string()),
    }
}

macro_rules! node_bridge_deserialize {
    ( $typ:ident::$fn:ident is $node_name:ident ) => {
        #[allow(non_snake_case)]
        fn $node_name(mut cx: FunctionContext) -> JsResult<JsValue> {
            let buffer = cx.argument::<JsBuffer>(0)?;
            let obj: Result<$typ, SignalProtocolError> = {
                let guard = cx.lock();
                let slice = buffer.borrow(&guard).as_slice::<u8>();
                $typ::$fn(slice)
            };
            return_boxed_object(&mut cx, obj)
        }
    };
}

macro_rules! node_bridge_serialize {
    ( $typ:ident::$fn:ident is $node_name:ident ) => {
        #[allow(non_snake_case)]
        fn $node_name(mut cx: FunctionContext) -> JsResult<JsValue> {
            let obj = cx.argument::<DefaultJsBox<$typ>>(0)?;
            let bytes = obj.$fn();
            return_binary_data(&mut cx, Ok(bytes))
        }
    };
}

#[allow(non_snake_case)]
fn PrivateKey_generate(mut cx: FunctionContext) -> JsResult<JsValue> {
    let mut rng = rand::rngs::OsRng;
    let keypair = KeyPair::generate(&mut rng);
    return_boxed_object(&mut cx, Ok(keypair.private_key))
}

node_bridge_deserialize!(PrivateKey::deserialize is PrivateKey_deserialize);

node_bridge_serialize!(PrivateKey::serialize is PrivateKey_serialize);

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

node_bridge_deserialize!(PublicKey::deserialize is PublicKey_deserialize);

node_bridge_serialize!(PublicKey::serialize is PublicKey_serialize);

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
    cx.export_function("PrivateKey_deserialize", PrivateKey_deserialize)?;
    cx.export_function("PrivateKey_serialize", PrivateKey_serialize)?;
    cx.export_function("PrivateKey_sign", PrivateKey_sign)?;
    cx.export_function("PrivateKey_agree", PrivateKey_agree)?;
    cx.export_function("PrivateKey_getPublicKey", PrivateKey_getPublicKey)?;

    cx.export_function("PublicKey_verify", PublicKey_verify)?;
    cx.export_function("PublicKey_deserialize", PublicKey_deserialize)?;
    cx.export_function("PublicKey_serialize", PublicKey_serialize)?;
    Ok(())
}
