//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol_rust::*;
use neon::context::Context;
use neon::prelude::*;
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

fn boxed<'a, T: Send>(cx: &mut FunctionContext<'a>, value: T) -> Handle<'a, DefaultJsBox<T>> {
    cx.boxed(DefaultFinalize(value))
}

#[allow(non_snake_case)]
fn PrivateKey_generate(mut cx: FunctionContext) -> JsResult<JsValue> {
    let cx = &mut cx;
    let mut rng = rand::rngs::OsRng;
    let keypair = KeyPair::generate(&mut rng);
    Ok(boxed(cx, keypair.private_key).upcast())
}

#[allow(non_snake_case)]
fn PrivateKey_serialize(mut cx: FunctionContext) -> JsResult<JsValue> {
    let value = cx.argument::<DefaultJsBox<PrivateKey>>(0)?;
    let bytes = value.serialize();
    let mut buffer = cx.buffer(bytes.len() as u32)?;
    cx.borrow_mut(&mut buffer, |raw_buffer| {
        raw_buffer.as_mut_slice().copy_from_slice(&bytes);
    });
    Ok(buffer.upcast())
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("PrivateKey_generate", PrivateKey_generate)?;
    cx.export_function("PrivateKey_serialize", PrivateKey_serialize)?;
    Ok(())
}
