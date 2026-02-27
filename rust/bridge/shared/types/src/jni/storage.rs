//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cell::RefCell;

use async_trait::async_trait;

use super::*;
// TODO: This re-export is because of the jni_arg_type macro expecting all bridging structs to
// appear in the jni module.
pub use crate::protocol::storage::{
    JavaKyberPreKeyStore, JavaPreKeyStore, JavaSenderKeyStore, JavaSessionStore,
    JavaSignedPreKeyStore,
};

pub type JavaIdentityKeyStore<'a> = JObject<'a>;

pub struct JniIdentityKeyStore<'a> {
    env: RefCell<EnvHandle<'a>>,
    store: &'a JObject<'a>,
}

impl<'a> JniIdentityKeyStore<'a> {
    pub fn new<'context: 'a>(
        env: &mut JNIEnv<'context>,
        store: &'a JObject<'a>,
    ) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            store,
            ClassName("org.signal.libsignal.protocol.state.IdentityKeyStore"),
        )?;
        Ok(Self {
            env: EnvHandle::new(env).into(),
            store,
        })
    }
}

#[derive(Debug, derive_more::From)]
enum BridgeOrProtocolError {
    Bridge(BridgeLayerError),
    Protocol(SignalProtocolError),
}

impl From<BridgeOrProtocolError> for SignalProtocolError {
    fn from(value: BridgeOrProtocolError) -> Self {
        match value {
            BridgeOrProtocolError::Protocol(e) => e,
            BridgeOrProtocolError::Bridge(e) => match e {
                BridgeLayerError::BadJniParameter(m) => {
                    SignalProtocolError::InvalidArgument(m.to_string())
                }
                BridgeLayerError::CallbackException(callback, exception) => {
                    SignalProtocolError::ApplicationCallbackError(callback, Box::new(exception))
                }
                err => SignalProtocolError::FfiBindingError(format!("{err}")),
            },
        }
    }
}

impl JniIdentityKeyStore<'_> {
    fn do_get_identity_key_pair(&self) -> Result<IdentityKeyPair, BridgeOrProtocolError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "getIdentityKeyPair", |env| {
                let callback_args = jni_args!(() -> org.signal.libsignal.protocol.IdentityKeyPair);
                let bits = get_object_with_serialization(
                    env,
                    self.store,
                    callback_args,
                    "getIdentityKeyPair",
                )?;

                match bits {
                    None => Err(SignalProtocolError::InvalidState(
                        "get_identity_key_pair",
                        "no local identity key".to_string(),
                    )
                    .into()),
                    Some(k) => Ok(IdentityKeyPair::try_from(k.as_ref())?),
                }
            })
    }

    fn do_get_local_registration_id(&self) -> Result<u32, BridgeLayerError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "getLocalRegistrationId", |env| {
                let i: jint = call_method_checked(
                    env,
                    self.store,
                    "getLocalRegistrationId",
                    jni_args!(() -> int),
                )?;
                u32::convert_from(env, &i)
            })
    }

    fn do_save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, BridgeLayerError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "saveIdentity", |env| {
                let address_jobject = protocol_address_to_jobject(env, address)?;
                let key_handle = identity.public_key().convert_into(env)?;
                let key_jobject = jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.IdentityKey"),
                    key_handle,
                )?;
                let callback_args = jni_args!((
                    address_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
                    key_jobject => org.signal.libsignal.protocol.IdentityKey
                ) -> org.signal.libsignal.protocol.state.IdentityKeyStore::IdentityChange);
                let result = call_method_checked(env, self.store, "saveIdentity", callback_args)?;
                let result = call_method_checked(env, result, "ordinal", jni_args!(() -> int))?;
                result
                    .try_into()
                    .ok()
                    .and_then(|v: isize| IdentityChange::try_from(v).ok())
                    .ok_or_else(|| {
                        BridgeLayerError::IntegerOverflow(format!(
                            "{result} invalid as IdentityChange"
                        ))
                    })
            })
    }

    fn do_is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, BridgeLayerError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "isTrustedIdentity", |env| {
                let address_jobject = protocol_address_to_jobject(env, address)?;
                let key_handle = identity.public_key().convert_into(env)?;
                let key_jobject = jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.IdentityKey"),
                    key_handle,
                )?;

                let direction_class = find_class(
                    env,
                    ClassName("org.signal.libsignal.protocol.state.IdentityKeyStore$Direction"),
                ).check_exceptions(env, "isTrustedIdentity")?;
                let field_name = match direction {
                    Direction::Sending => "SENDING",
                    Direction::Receiving => "RECEIVING",
                };

                let field_value: JObject = env
                    .get_static_field(
                        direction_class,
                        field_name,
                        jni_signature!(org.signal.libsignal.protocol.state.IdentityKeyStore::Direction),
                    )
                    .check_exceptions(env, field_name)?
                    .try_into()
                    .expect("already checked type");

                let callback_args = jni_args!((
                    address_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
                    key_jobject => org.signal.libsignal.protocol.IdentityKey,
                    field_value => org.signal.libsignal.protocol.state.IdentityKeyStore::Direction,
                ) -> boolean);
                let result: jboolean =
                    call_method_checked(env, self.store, "isTrustedIdentity", callback_args)?;

                Ok(result != 0)
            })
    }

    fn do_get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, BridgeOrProtocolError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "getIdentity", |env| {
                let address_jobject = protocol_address_to_jobject(env, address)?;
                let callback_args = jni_args!((
                    address_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
                ) -> org.signal.libsignal.protocol.IdentityKey);

                let bits =
                    get_object_with_serialization(env, self.store, callback_args, "getIdentity")?;

                match bits {
                    None => Ok(None),
                    Some(k) => Ok(Some(IdentityKey::decode(&k)?)),
                }
            })
    }
}

#[async_trait(? Send)]
impl IdentityKeyStore for JniIdentityKeyStore<'_> {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.do_get_identity_key_pair()?)
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .do_get_local_registration_id()
            .map_err(BridgeOrProtocolError::from)?)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        Ok(self
            .do_save_identity(address, identity)
            .map_err(BridgeOrProtocolError::from)?)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self
            .do_is_trusted_identity(address, identity, direction)
            .map_err(BridgeOrProtocolError::from)?)
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self.do_get_identity(address)?)
    }
}
