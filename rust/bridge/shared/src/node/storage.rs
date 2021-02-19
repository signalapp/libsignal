//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;

use async_trait::async_trait;
use signal_neon_futures::*;
use std::sync::Arc;

pub struct NodeSenderKeyStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodeSenderKeyStore {
    pub(crate) fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
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
            Ok(value) => match value.downcast::<DefaultJsBox<SenderKeyRecord>, _>(cx) {
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

impl Finalize for NodeSenderKeyStore {
    fn finalize<'a, C: Context<'a>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for NodeSenderKeyStore {
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
