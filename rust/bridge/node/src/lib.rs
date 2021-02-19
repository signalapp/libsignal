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
use std::convert::TryFrom;
use std::fmt;
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

struct NodePreKeyStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodePreKeyStore {
    fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
        }
    }

    async fn do_get_pre_key(&self, id: u32) -> Result<PreKeyRecord, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let id = id.convert_into(cx)?;
            let result = call_method(cx, store_object, "_getPreKey", vec![id.upcast()])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<node::DefaultJsBox<PreKeyRecord>, _>(cx) {
                Ok(obj) => Ok((***obj).clone()),
                Err(_) => Err("result must be an object".to_owned()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_save_pre_key(&self, id: u32, record: PreKeyRecord) -> Result<(), String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let id: Handle<JsNumber> = id.convert_into(cx)?;
            let record: Handle<JsValue> = record.convert_into(cx)?;
            let result = call_method(cx, store_object, "_savePreKey", vec![id.upcast(), record])?
                .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _savePreKey".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_remove_pre_key(&self, id: u32) -> Result<(), String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let id: Handle<JsNumber> = id.convert_into(cx)?;
            let result = call_method(cx, store_object, "_removePreKey", vec![id.upcast()])?
                .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _removePreKey".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NodePreKeyStore {
    fn finalize<'b, C: neon::prelude::Context<'b>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl PreKeyStore for NodePreKeyStore {
    async fn get_pre_key(
        &self,
        pre_key_id: u32,
        _ctx: libsignal_protocol::Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        self.do_get_pre_key(pre_key_id)
            .await
            .map_err(|s| js_error_to_rust("getPreKey", s))
    }

    async fn save_pre_key(
        &mut self,
        pre_key_id: u32,
        record: &PreKeyRecord,
        _ctx: libsignal_protocol::Context,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_pre_key(pre_key_id, record.clone())
            .await
            .map_err(|s| js_error_to_rust("savePreKey", s))
    }

    async fn remove_pre_key(
        &mut self,
        pre_key_id: u32,
        _ctx: libsignal_protocol::Context,
    ) -> Result<(), SignalProtocolError> {
        self.do_remove_pre_key(pre_key_id)
            .await
            .map_err(|s| js_error_to_rust("removePreKey", s))
    }
}

struct NodeSignedPreKeyStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodeSignedPreKeyStore {
    fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
        }
    }

    async fn do_get_signed_pre_key(&self, id: u32) -> Result<SignedPreKeyRecord, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let id = id.convert_into(cx)?;
            let result = call_method(cx, store_object, "_getSignedPreKey", vec![id.upcast()])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<node::DefaultJsBox<SignedPreKeyRecord>, _>(cx) {
                Ok(obj) => Ok((***obj).clone()),
                Err(_) => Err("result must be an object".to_owned()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_save_signed_pre_key(
        &self,
        id: u32,
        record: SignedPreKeyRecord,
    ) -> Result<(), String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let id: Handle<JsNumber> = id.convert_into(cx)?;
            let record: Handle<JsValue> = record.convert_into(cx)?;
            let result = call_method(
                cx,
                store_object,
                "_saveSignedPreKey",
                vec![id.upcast(), record],
            )?
            .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _saveSignedPreKey".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NodeSignedPreKeyStore {
    fn finalize<'b, C: neon::prelude::Context<'b>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for NodeSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        signed_pre_key_id: u32,
        _ctx: libsignal_protocol::Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        self.do_get_signed_pre_key(signed_pre_key_id)
            .await
            .map_err(|s| js_error_to_rust("getSignedPreKey", s))
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_pre_key_id: u32,
        record: &SignedPreKeyRecord,
        _ctx: libsignal_protocol::Context,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_signed_pre_key(signed_pre_key_id, record.clone())
            .await
            .map_err(|s| js_error_to_rust("saveSignedPreKey", s))
    }
}

struct NodeSessionStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodeSessionStore {
    fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
        }
    }

    async fn do_get_session(&self, name: ProtocolAddress) -> Result<Option<SessionRecord>, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name: Handle<JsValue> = name.convert_into(cx)?;
            let result = call_method(cx, store_object, "_getSession", vec![name])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<node::DefaultJsBox<SessionRecord>, _>(cx) {
                Ok(obj) => Ok(Some((***obj).clone())),
                Err(_) => {
                    if value.is_a::<JsNull, _>(cx) || value.is_a::<JsUndefined, _>(cx) {
                        Ok(None)
                    } else {
                        Err("_getSession returned unexpected type".into())
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

    async fn do_save_session(
        &self,
        name: ProtocolAddress,
        record: SessionRecord,
    ) -> Result<(), String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name = name.convert_into(cx)?;
            let record = record.convert_into(cx)?;
            let result = call_method(
                cx,
                store_object,
                "_saveSession",
                vec![name, record.upcast()],
            )?
            .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _saveSession".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NodeSessionStore {
    fn finalize<'b, C: neon::prelude::Context<'b>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl SessionStore for NodeSessionStore {
    async fn load_session(
        &self,
        name: &ProtocolAddress,
        _ctx: libsignal_protocol::Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        self.do_get_session(name.clone())
            .await
            .map_err(|s| js_error_to_rust("getSession", s))
    }

    async fn store_session(
        &mut self,
        name: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: libsignal_protocol::Context,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_session(name.clone(), record.clone())
            .await
            .map_err(|s| js_error_to_rust("saveSession", s))
    }
}

struct NodeIdentityStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodeIdentityStore {
    fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
        }
    }

    async fn do_get_identity_key(&self) -> Result<PrivateKey, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let result = call_method(cx, store_object, "_getIdentityKey", vec![])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<node::DefaultJsBox<PrivateKey>, _>(cx) {
                Ok(obj) => Ok(***obj),
                Err(_) => Err("result must be an object".to_owned()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_get_local_registration_id(&self) -> Result<u32, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let result = call_method(cx, store_object, "_getLocalRegistrationId", vec![])?
                .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsNumber, _>(cx) {
                Ok(b) => Ok(b.value(cx) as u32),
                Err(_) => Err("unexpected result from _getLocalRegistrationId".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_get_identity(&self, name: ProtocolAddress) -> Result<Option<PublicKey>, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name: Handle<JsValue> = name.convert_into(cx)?;
            let result = call_method(cx, store_object, "_getIdentity", vec![name])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<node::DefaultJsBox<PublicKey>, _>(cx) {
                Ok(obj) => Ok(Some(***obj)),
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

    async fn do_save_identity(
        &self,
        name: ProtocolAddress,
        key: PublicKey,
    ) -> Result<bool, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name: Handle<JsValue> = name.convert_into(cx)?;
            let key: Handle<JsValue> = key.convert_into(cx)?;
            let result = call_method(cx, store_object, "_saveIdentity", vec![name, key])?
                .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsBoolean, _>(cx) {
                Ok(b) => Ok(b.value(cx)),
                Err(_) => Err("unexpected result from _saveIdentity".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_is_trusted(
        &self,
        name: ProtocolAddress,
        key: PublicKey,
        direction: Direction,
    ) -> Result<bool, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name: Handle<JsValue> = name.convert_into(cx)?;
            let key: Handle<JsValue> = key.convert_into(cx)?;
            let sending = direction == Direction::Sending;

            let sending = sending.convert_into(cx)?;
            let result = call_method(
                cx,
                store_object,
                "_isTrustedIdentity",
                vec![name, key, sending.upcast()],
            )?
            .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsBoolean, _>(cx) {
                Ok(b) => Ok(b.value(cx)),
                Err(_) => Err("unexpected result from _isTrustedIdentity".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NodeIdentityStore {
    fn finalize<'b, C: neon::prelude::Context<'b>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for NodeIdentityStore {
    async fn get_identity_key_pair(
        &self,
        _ctx: libsignal_protocol::Context,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        let pk = self
            .do_get_identity_key()
            .await
            .map_err(|s| js_error_to_rust("getIdentityPrivateKey", s))?;

        IdentityKeyPair::try_from(pk)
    }

    async fn get_local_registration_id(
        &self,
        _ctx: libsignal_protocol::Context,
    ) -> Result<u32, SignalProtocolError> {
        self.do_get_local_registration_id()
            .await
            .map_err(|s| js_error_to_rust("getLocalRegistrationId", s))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: libsignal_protocol::Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self
            .do_get_identity(address.clone())
            .await
            .map_err(|s| js_error_to_rust("getIdentity", s))?
            .map(IdentityKey::new))
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _ctx: libsignal_protocol::Context,
    ) -> Result<bool, SignalProtocolError> {
        self.do_save_identity(address.clone(), *identity.public_key())
            .await
            .map_err(|s| js_error_to_rust("saveIdentity", s))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: libsignal_protocol::Direction,
        _ctx: libsignal_protocol::Context,
    ) -> Result<bool, SignalProtocolError> {
        self.do_is_trusted(address.clone(), *identity.public_key(), direction)
            .await
            .map_err(|s| js_error_to_rust("isTrustedIdentity", s))
    }
}

struct NodeSenderKeyStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodeSenderKeyStore {
    fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
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

impl Finalize for NodeSenderKeyStore {
    fn finalize<'b, C: neon::prelude::Context<'b>>(self, cx: &mut C) {
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

#[allow(non_snake_case)]
/// ts: export function SenderKeyDistributionMessage_Create(name: Wrapper<SenderKeyName>, store: SenderKeyStore): Promise<SenderKeyDistributionMessage>
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
/// ts: export function SenderKeyDistributionMessage_Process(name: Wrapper<SenderKeyName>, msg: Wrapper<SenderKeyDistributionMessage>, store: SenderKeyStore): Promise<void>
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
/// ts: export function GroupCipher_Encrypt(name: Wrapper<SenderKeyName>, store: SenderKeyStore, message: Buffer): Promise<Buffer>
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
/// ts: export function GroupCipher_Decrypt(name: Wrapper<SenderKeyName>, store: SenderKeyStore, message: Buffer): Promise<Buffer>
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

#[allow(non_snake_case)]
/// ts: export function SessionBuilder_ProcessPreKeyBundle(bundle: Wrapper<PreKeyBundle>, address: Wrapper<ProtocolAddress>, session_store: SessionStore, identity_store: IdentityKeyStore): Promise<void>
pub fn SessionBuilder_ProcessPreKeyBundle(mut cx: FunctionContext) -> JsResult<JsObject> {
    let bundle_arg = cx.argument(0)?;
    let mut bundle_borrow = <&PreKeyBundle as node::ArgTypeInfo>::borrow(&mut cx, bundle_arg)?;
    let bundle = <&PreKeyBundle as node::ArgTypeInfo>::load_from(&mut bundle_borrow);
    let bundle = bundle.clone();

    let name_arg = cx.argument(1)?;
    let mut name_borrow = <&ProtocolAddress as node::ArgTypeInfo>::borrow(&mut cx, name_arg)?;
    let name = <&ProtocolAddress as node::ArgTypeInfo>::load_from(&mut name_borrow);
    let name = name.clone();

    let session_store_arg = cx.argument(2)?;
    let mut session_store = NodeSessionStore::new(&mut cx, session_store_arg);

    let identity_store_arg = cx.argument(3)?;
    let mut identity_key_store = NodeIdentityStore::new(&mut cx, identity_store_arg);

    promise(&mut cx, async move {
        let mut csprng = rand::rngs::OsRng;
        let future = AssertUnwindSafe(process_prekey_bundle(
            &name,
            &mut session_store,
            &mut identity_key_store,
            &bundle,
            &mut csprng,
            None,
        ));

        let result = future.await;
        settle_promise(move |cx| {
            session_store.finalize(cx);
            identity_key_store.finalize(cx);
            result.convert_into(cx)
        })
    })
}

#[allow(non_snake_case)]
/// ts: export function SessionCipher_EncryptMessage(message: Buffer, address: Wrapper<ProtocolAddress>, session_store: SessionStore, identity_store: IdentityKeyStore): Promise<CiphertextMessage>
pub fn SessionCipher_EncryptMessage(mut cx: FunctionContext) -> JsResult<JsObject> {
    let message = cx.argument::<JsBuffer>(0)?;
    let message = {
        let guard = cx.lock();
        let message = message.borrow(&guard);
        message.as_slice::<u8>().to_vec()
    };

    let name_arg = cx.argument(1)?;
    let mut name_borrow = <&ProtocolAddress as node::ArgTypeInfo>::borrow(&mut cx, name_arg)?;
    let name = <&ProtocolAddress as node::ArgTypeInfo>::load_from(&mut name_borrow);
    let name = name.clone();

    let session_store_arg = cx.argument(2)?;
    let mut session_store = NodeSessionStore::new(&mut cx, session_store_arg);

    let identity_store_arg = cx.argument(3)?;
    let mut identity_key_store = NodeIdentityStore::new(&mut cx, identity_store_arg);

    promise(&mut cx, async move {
        let future = AssertUnwindSafe(message_encrypt(
            &message,
            &name,
            &mut session_store,
            &mut identity_key_store,
            None,
        ));

        let result = future.await;
        settle_promise(move |cx| {
            session_store.finalize(cx);
            identity_key_store.finalize(cx);
            result.convert_into(cx)
        })
    })
}

#[allow(non_snake_case)]
/// ts: export function SessionCipher_DecryptSignalMessage(message: Wrapper<SignalMessage>, address: Wrapper<ProtocolAddress>, session_store: SessionStore, identity_store: IdentityKeyStore): Promise<Buffer>
pub fn SessionCipher_DecryptSignalMessage(mut cx: FunctionContext) -> JsResult<JsObject> {
    let message_arg = cx.argument(0)?;
    let mut message_borrow = <&SignalMessage as node::ArgTypeInfo>::borrow(&mut cx, message_arg)?;
    let message = <&SignalMessage as node::ArgTypeInfo>::load_from(&mut message_borrow);
    let message = message.clone();

    let name_arg = cx.argument(1)?;
    let mut name_borrow = <&ProtocolAddress as node::ArgTypeInfo>::borrow(&mut cx, name_arg)?;
    let name = <&ProtocolAddress as node::ArgTypeInfo>::load_from(&mut name_borrow);
    let name = name.clone();

    let session_store_arg = cx.argument(2)?;
    let mut session_store = NodeSessionStore::new(&mut cx, session_store_arg);

    let identity_store_arg = cx.argument(3)?;
    let mut identity_key_store = NodeIdentityStore::new(&mut cx, identity_store_arg);

    promise(&mut cx, async move {
        let mut csprng = rand::rngs::OsRng;
        let future = AssertUnwindSafe(message_decrypt_signal(
            &message,
            &name,
            &mut session_store,
            &mut identity_key_store,
            &mut csprng,
            None,
        ));
        let result = future.await;
        settle_promise(move |cx| {
            session_store.finalize(cx);
            identity_key_store.finalize(cx);
            result.convert_into(cx)
        })
    })
}

#[allow(non_snake_case)]
/// ts: export function SessionCipher_DecryptPreKeySignalMessage(message: Wrapper<PreKeySignalMessage>, address: Wrapper<ProtocolAddress>, session_store: SessionStore, identity_store: IdentityKeyStore, prekey_store: PreKeyStore, signed_prekey_store: SignedPreKeyStore): Promise<Buffer>
pub fn SessionCipher_DecryptPreKeySignalMessage(mut cx: FunctionContext) -> JsResult<JsObject> {
    let message_arg = cx.argument(0)?;
    let mut message_borrow =
        <&PreKeySignalMessage as node::ArgTypeInfo>::borrow(&mut cx, message_arg)?;
    let message = <&PreKeySignalMessage as node::ArgTypeInfo>::load_from(&mut message_borrow);
    let message = message.clone();

    let name_arg = cx.argument(1)?;
    let mut name_borrow = <&ProtocolAddress as node::ArgTypeInfo>::borrow(&mut cx, name_arg)?;
    let name = <&ProtocolAddress as node::ArgTypeInfo>::load_from(&mut name_borrow);
    let name = name.clone();

    let session_store_arg = cx.argument(2)?;
    let mut session_store = NodeSessionStore::new(&mut cx, session_store_arg);

    let identity_store_arg = cx.argument(3)?;
    let mut identity_key_store = NodeIdentityStore::new(&mut cx, identity_store_arg);

    let prekey_store_arg = cx.argument(4)?;
    let mut prekey_store = NodePreKeyStore::new(&mut cx, prekey_store_arg);

    let signed_prekey_store_arg = cx.argument(5)?;
    let mut signed_prekey_store = NodeSignedPreKeyStore::new(&mut cx, signed_prekey_store_arg);

    promise(&mut cx, async move {
        let mut csprng = rand::rngs::OsRng;
        let future = AssertUnwindSafe(message_decrypt_prekey(
            &message,
            &name,
            &mut session_store,
            &mut identity_key_store,
            &mut prekey_store,
            &mut signed_prekey_store,
            &mut csprng,
            None,
        ));
        let result = future.await;
        settle_promise(move |cx| {
            session_store.finalize(cx);
            identity_key_store.finalize(cx);
            prekey_store.finalize(cx);
            signed_prekey_store.finalize(cx);
            result.convert_into(cx)
        })
    })
}

#[allow(non_snake_case)]
/// ts: export function SealedSender_EncryptMessage(message: Buffer, address: Wrapper<ProtocolAddress>, sender_cert: Wrapper<SenderCertificate>, session_store: SessionStore, identity_store: IdentityKeyStore): Promise<Buffer>
pub fn SealedSender_EncryptMessage(mut cx: FunctionContext) -> JsResult<JsObject> {
    let message = cx.argument::<JsBuffer>(0)?;
    let message = {
        let guard = cx.lock();
        let message = message.borrow(&guard);
        message.as_slice::<u8>().to_vec()
    };

    let destination_arg = cx.argument(1)?;
    let mut destination_borrow =
        <&ProtocolAddress as node::ArgTypeInfo>::borrow(&mut cx, destination_arg)?;
    let destination = <&ProtocolAddress as node::ArgTypeInfo>::load_from(&mut destination_borrow);
    let destination = destination.clone();

    let sender_cert_arg = cx.argument(2)?;
    let mut sender_cert_borrow =
        <&SenderCertificate as node::ArgTypeInfo>::borrow(&mut cx, sender_cert_arg)?;
    let sender_cert = <&SenderCertificate as node::ArgTypeInfo>::load_from(&mut sender_cert_borrow);
    let sender_cert = sender_cert.clone();

    let session_store_arg = cx.argument(3)?;
    let mut session_store = NodeSessionStore::new(&mut cx, session_store_arg);

    let identity_store_arg = cx.argument(4)?;
    let mut identity_key_store = NodeIdentityStore::new(&mut cx, identity_store_arg);

    promise(&mut cx, async move {
        let mut rng = rand::rngs::OsRng;
        let future = AssertUnwindSafe(sealed_sender_encrypt(
            &destination,
            &sender_cert,
            &message,
            &mut session_store,
            &mut identity_key_store,
            None,
            &mut rng,
        ));

        let result = future.await;
        settle_promise(move |cx| {
            session_store.finalize(cx);
            identity_key_store.finalize(cx);
            result.convert_into(cx)
        })
    })
}

#[allow(non_snake_case)]
/// ts: export function SealedSender_DecryptToUsmc(message: Buffer, identity_store: IdentityKeyStore): Promise<UnidentifiedSenderMessageContent>
pub fn SealedSender_DecryptToUsmc(mut cx: FunctionContext) -> JsResult<JsObject> {
    let message = cx.argument::<JsBuffer>(0)?;
    let message = {
        let guard = cx.lock();
        let message = message.borrow(&guard);
        message.as_slice::<u8>().to_vec()
    };

    let identity_store_arg = cx.argument(1)?;
    let mut identity_key_store = NodeIdentityStore::new(&mut cx, identity_store_arg);

    promise(&mut cx, async move {
        let future = AssertUnwindSafe(sealed_sender_decrypt_to_usmc(
            &message,
            &mut identity_key_store,
            None,
        ));

        let result = future.await;
        settle_promise(move |cx| {
            identity_key_store.finalize(cx);
            result.convert_into(cx)
        })
    })
}

#[allow(non_snake_case)]
/// ts: export function SealedSender_DecryptMessage(message: Buffer, trust_root: Wrapper<PublicKey>, timestamp: number, local_e164: string | null, local_uuid: string, local_device_id: number, session_store: SessionStore, identity_store: IdentityKeyStore, prekey_store: PreKeyStore, signed_prekey_store: SignedPreKeyStore): Promise<SealedSenderDecryptionResult>
pub fn SealedSender_DecryptMessage(mut cx: FunctionContext) -> JsResult<JsObject> {
    let message = cx.argument::<JsBuffer>(0)?;
    let message = {
        let guard = cx.lock();
        let message = message.borrow(&guard);
        message.as_slice::<u8>().to_vec()
    };

    let trust_root_arg = cx.argument(1)?;
    let mut trust_root_borrow = <&PublicKey as node::ArgTypeInfo>::borrow(&mut cx, trust_root_arg)?;
    let trust_root = <&PublicKey as node::ArgTypeInfo>::load_from(&mut trust_root_borrow);
    let trust_root = *trust_root;

    let timestamp: Handle<JsNumber> = cx.argument(2)?;
    let timestamp = timestamp.value(&mut cx) as u64;

    let local_e164: Handle<JsValue> = cx.argument(3)?;
    let local_e164 = match local_e164.downcast::<JsString, _>(&mut cx) {
        Ok(s) => Some(s.value(&mut cx)),
        Err(_) => None,
    };

    let local_uuid: Handle<JsString> = cx.argument(4)?;
    let local_uuid = local_uuid.value(&mut cx);

    let local_device_id: Handle<JsNumber> = cx.argument(5)?;
    let local_device_id = local_device_id.value(&mut cx) as u32;

    let session_store_arg = cx.argument(6)?;
    let mut session_store = NodeSessionStore::new(&mut cx, session_store_arg);

    let identity_store_arg = cx.argument(7)?;
    let mut identity_key_store = NodeIdentityStore::new(&mut cx, identity_store_arg);

    let prekey_store_arg = cx.argument(8)?;
    let mut prekey_store = NodePreKeyStore::new(&mut cx, prekey_store_arg);

    let signed_prekey_store_arg = cx.argument(9)?;
    let mut signed_prekey_store = NodeSignedPreKeyStore::new(&mut cx, signed_prekey_store_arg);

    promise(&mut cx, async move {
        let future = AssertUnwindSafe(sealed_sender_decrypt(
            &message,
            &trust_root,
            timestamp,
            local_e164,
            local_uuid,
            local_device_id,
            &mut identity_key_store,
            &mut session_store,
            &mut prekey_store,
            &mut signed_prekey_store,
            None,
        ));
        let result = future.await;
        settle_promise(move |cx| {
            session_store.finalize(cx);
            identity_key_store.finalize(cx);
            prekey_store.finalize(cx);
            signed_prekey_store.finalize(cx);
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

    cx.export_function(
        "SessionBuilder_ProcessPreKeyBundle",
        SessionBuilder_ProcessPreKeyBundle,
    )?;
    cx.export_function("SessionCipher_EncryptMessage", SessionCipher_EncryptMessage)?;
    cx.export_function(
        "SessionCipher_DecryptSignalMessage",
        SessionCipher_DecryptSignalMessage,
    )?;
    cx.export_function(
        "SessionCipher_DecryptPreKeySignalMessage",
        SessionCipher_DecryptPreKeySignalMessage,
    )?;

    cx.export_function("SealedSender_EncryptMessage", SealedSender_EncryptMessage)?;
    cx.export_function("SealedSender_DecryptMessage", SealedSender_DecryptMessage)?;
    cx.export_function("SealedSender_DecryptToUsmc", SealedSender_DecryptToUsmc)?;

    Ok(())
}
