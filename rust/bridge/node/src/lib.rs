//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_bridge::node;
use libsignal_bridge::node::ResultTypeInfo;
use libsignal_protocol::*;
use neon::context::Context;
use neon::prelude::*;
use signal_neon_futures::*;
use std::fmt;
use std::marker::PhantomData;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

pub mod logging;

#[derive(Debug)]
struct CallbackError {
    message: String,
}

impl CallbackError {
    fn new(message: String) -> CallbackError {
        Self { message }
    }
}

impl fmt::Display for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "callback error {}", self.message)
    }
}

impl std::error::Error for CallbackError {}

fn js_error_to_rust(func: &'static str, err: String) -> SignalProtocolError {
    SignalProtocolError::ApplicationCallbackError(func, Box::new(CallbackError::new(err)))
}

struct NodeSenderKeyStore<'a> {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
    phantom: PhantomData<&'a ()>,
}

impl<'a> NodeSenderKeyStore<'a> {
    fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
            phantom: PhantomData,
        }
    }

    async fn do_get_sender_key(
        &self,
        name: SenderKeyName,
    ) -> Result<Option<SenderKeyRecord>, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name: Handle<JsValue> = name.convert_into(cx)?;
            let result = call_method(cx, store_object, "_getSenderKey", vec![name])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<node::DefaultJsBox<SenderKeyRecord>, _>(cx) {
                Ok(obj) => Ok(Some((***obj).clone())),
                Err(_) => {
                    if value.is_a::<JsNull, _>(cx) {
                        Ok(None)
                    } else {
                        Err("result must be an object".to_owned())
                    }
                }
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_save_sender_key(
        &self,
        name: SenderKeyName,
        record: SenderKeyRecord,
    ) -> Result<(), String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name: Handle<JsValue> = name.convert_into(cx)?;
            let record: Handle<JsValue> = record.convert_into(cx)?;
            let result = call_method(cx, store_object, "_saveSenderKey", vec![name, record])?
                .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _saveSenderKey".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl<'a> Finalize for NodeSenderKeyStore<'a> {
    fn finalize<'b, C: neon::prelude::Context<'b>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl<'a> SenderKeyStore for NodeSenderKeyStore<'a> {
    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        _ctx: libsignal_protocol::Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        self.do_get_sender_key(sender_key_name.clone())
            .await
            .map_err(|s| js_error_to_rust("getSenderKey", s))
    }

    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        _ctx: libsignal_protocol::Context,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_sender_key(sender_key_name.clone(), record.clone())
            .await
            .map_err(|s| js_error_to_rust("saveSenderKey", s))
    }
}

#[allow(non_snake_case)]
/// ts: export function SenderKeyDistributionMessage_Create(name: SenderKeyName, store: SenderKeyStore): Promise<SenderKeyDistributionMessage>
pub fn SenderKeyDistributionMessage_Create(mut cx: FunctionContext) -> JsResult<JsObject> {
    let name_arg = cx.argument(0)?;
    let mut name_borrow = <&SenderKeyName as node::ArgTypeInfo>::borrow(&mut cx, name_arg)?;
    let name = <&SenderKeyName as node::ArgTypeInfo>::load_from(&mut name_borrow);
    let name = name.clone();

    let store_arg = cx.argument(1)?;
    let mut store = NodeSenderKeyStore::new(&mut cx, store_arg);

    promise(&mut cx, async move {
        let mut rng = rand::rngs::OsRng;
        let future = AssertUnwindSafe(create_sender_key_distribution_message(
            &name, &mut store, &mut rng, None,
        ));
        let result = future.await;
        settle_promise(move |cx| {
            store.finalize(cx);
            result.convert_into(cx)
        })
    })
}

#[allow(non_snake_case)]
/// ts: export function SenderKeyDistributionMessage_Process(name: SenderKeyName, msg: SenderKeyDistributionMessage, store: SenderKeyStore): Promise<void>
pub fn SenderKeyDistributionMessage_Process(mut cx: FunctionContext) -> JsResult<JsObject> {
    let name_arg = cx.argument(0)?;
    let mut name_borrow = <&SenderKeyName as node::ArgTypeInfo>::borrow(&mut cx, name_arg)?;
    let name = <&SenderKeyName as node::ArgTypeInfo>::load_from(&mut name_borrow);
    let name = name.clone();

    let skdm_arg = cx.argument(1)?;
    let mut skdm_borrow =
        <&SenderKeyDistributionMessage as node::ArgTypeInfo>::borrow(&mut cx, skdm_arg)?;
    let skdm = <&SenderKeyDistributionMessage as node::ArgTypeInfo>::load_from(&mut skdm_borrow);
    let skdm = skdm.clone();

    let store_arg = cx.argument(2)?;
    let mut store = NodeSenderKeyStore::new(&mut cx, store_arg);

    promise(&mut cx, async move {
        let future = AssertUnwindSafe(process_sender_key_distribution_message(
            &name, &skdm, &mut store, None,
        ));
        let result = future.await;
        settle_promise(move |cx| {
            store.finalize(cx);
            result.convert_into(cx)
        })
    })
}

#[allow(non_snake_case)]
/// ts: export function GroupCipher_Encrypt(name: SenderKeyName, store: SenderKeyStore, message: Buffer): Promise<Buffer>
pub fn GroupCipher_Encrypt(mut cx: FunctionContext) -> JsResult<JsObject> {
    let name_arg = cx.argument(0)?;
    let mut name_borrow = <&SenderKeyName as node::ArgTypeInfo>::borrow(&mut cx, name_arg)?;
    let name = <&SenderKeyName as node::ArgTypeInfo>::load_from(&mut name_borrow);
    let name = name.clone();

    let store_arg = cx.argument(1)?;
    let mut store = NodeSenderKeyStore::new(&mut cx, store_arg);

    let message = cx.argument::<JsBuffer>(2)?;
    let message = {
        let guard = cx.lock();
        let message = message.borrow(&guard);
        message.as_slice::<u8>().to_vec()
    };

    promise(&mut cx, async move {
        let mut rng = rand::rngs::OsRng;
        let future = AssertUnwindSafe(group_encrypt(&mut store, &name, &message, &mut rng, None));
        let result = future.await;
        settle_promise(move |cx| {
            store.finalize(cx);
            result.convert_into(cx)
        })
    })
}

#[allow(non_snake_case)]
/// ts: export function GroupCipher_Decrypt(name: SenderKeyName, store: SenderKeyStore, message: Buffer): Promise<Buffer>
pub fn GroupCipher_Decrypt(mut cx: FunctionContext) -> JsResult<JsObject> {
    let name_arg = cx.argument(0)?;
    let mut name_borrow = <&SenderKeyName as node::ArgTypeInfo>::borrow(&mut cx, name_arg)?;
    let name = <&SenderKeyName as node::ArgTypeInfo>::load_from(&mut name_borrow);
    let name = name.clone();

    let store_arg = cx.argument(1)?;
    let mut store = NodeSenderKeyStore::new(&mut cx, store_arg);

    let message = cx.argument::<JsBuffer>(2)?;
    let message = {
        let guard = cx.lock();
        let message = message.borrow(&guard);
        message.as_slice::<u8>().to_vec()
    };

    promise(&mut cx, async move {
        let future = AssertUnwindSafe(group_decrypt(&message, &mut store, &name, None));
        let result = future.await;
        settle_promise(move |cx| {
            store.finalize(cx);
            result.convert_into(cx)
        })
    })
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    libsignal_bridge::node::register(&mut cx)?;
    cx.export_function("initLogger", logging::init_logger)?;
    cx.export_function(
        "SenderKeyDistributionMessage_Create",
        SenderKeyDistributionMessage_Create,
    )?;
    cx.export_function(
        "SenderKeyDistributionMessage_Process",
        SenderKeyDistributionMessage_Process,
    )?;
    cx.export_function("GroupCipher_Encrypt", GroupCipher_Encrypt)?;
    cx.export_function("GroupCipher_Decrypt", GroupCipher_Decrypt)?;
    Ok(())
}
