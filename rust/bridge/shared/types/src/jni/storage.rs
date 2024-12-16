//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cell::RefCell;

use async_trait::async_trait;
use uuid::Uuid;

use super::*;

pub type JavaIdentityKeyStore<'a> = JObject<'a>;
pub type JavaPreKeyStore<'a> = JObject<'a>;
pub type JavaSignedPreKeyStore<'a> = JObject<'a>;
pub type JavaKyberPreKeyStore<'a> = JObject<'a>;
pub type JavaSessionStore<'a> = JObject<'a>;
pub type JavaSenderKeyStore<'a> = JObject<'a>;

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

impl JniIdentityKeyStore<'_> {
    fn do_get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalJniError> {
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

    fn do_get_local_registration_id(&self) -> Result<u32, SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "getLocalRegistrationId", |env| {
                let i: jint = call_method_checked(
                    env,
                    self.store,
                    "getLocalRegistrationId",
                    jni_args!(() -> int),
                )?;
                Ok(u32::convert_from(env, &i)?)
            })
    }

    fn do_save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalJniError> {
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
                ) -> boolean);
                let result: jboolean =
                    call_method_checked(env, self.store, "saveIdentity", callback_args)?;
                Ok(result != 0)
            })
    }

    fn do_is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalJniError> {
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
                )?;
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
    ) -> Result<Option<IdentityKey>, SignalJniError> {
        self.env.borrow_mut().with_local_frame(
            8,
            "getIdentity",
            |env| -> SignalJniResult<Option<IdentityKey>> {
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
            },
        )
    }
}

#[async_trait(? Send)]
impl IdentityKeyStore for JniIdentityKeyStore<'_> {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.do_get_identity_key_pair()?)
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.do_get_local_registration_id()?)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.do_save_identity(address, identity)?)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.do_is_trusted_identity(address, identity, direction)?)
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self.do_get_identity(address)?)
    }
}

pub struct JniPreKeyStore<'a> {
    env: RefCell<EnvHandle<'a>>,
    store: &'a JObject<'a>,
}

impl<'a> JniPreKeyStore<'a> {
    pub fn new<'context: 'a>(
        env: &mut JNIEnv<'context>,
        store: &'a JObject<'a>,
    ) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            store,
            ClassName("org.signal.libsignal.protocol.state.PreKeyStore"),
        )?;
        Ok(Self {
            env: EnvHandle::new(env).into(),
            store,
        })
    }
}

impl JniPreKeyStore<'_> {
    fn do_get_pre_key(&self, prekey_id: u32) -> Result<PreKeyRecord, SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "loadPreKey", |env| {
                let callback_args = jni_args!((
            prekey_id.convert_into(env)? => int
        ) -> org.signal.libsignal.protocol.state.PreKeyRecord);
                let pk: Option<PreKeyRecord> =
                    get_object_with_native_handle(env, self.store, callback_args, "loadPreKey")?;
                match pk {
                    Some(pk) => Ok(pk),
                    None => Err(SignalJniError::Protocol(
                        SignalProtocolError::InvalidPreKeyId,
                    )),
                }
            })
    }

    fn do_save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
    ) -> Result<(), SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "storePreKey", |env| {
                let record_handle = record.clone().convert_into(env)?;
                let jobject_record = jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.state.PreKeyRecord"),
                    record_handle,
                )?;
                let callback_args = jni_args!((
                    prekey_id.convert_into(env)? => int,
                    jobject_record => org.signal.libsignal.protocol.state.PreKeyRecord
                ) -> void);
                call_method_checked(env, self.store, "storePreKey", callback_args)?;
                Ok(())
            })
    }

    fn do_remove_pre_key(&mut self, prekey_id: u32) -> Result<(), SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "removePreKey", |env| {
                let java_id = prekey_id.convert_into(env)?;
                call_method_checked(
                    env,
                    self.store,
                    "removePreKey",
                    jni_args!((java_id => int) -> void),
                )?;
                Ok(())
            })
    }
}

#[async_trait(? Send)]
impl PreKeyStore for JniPreKeyStore<'_> {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_pre_key(prekey_id.into())?)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_pre_key(prekey_id.into(), record)?)
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        Ok(self.do_remove_pre_key(prekey_id.into())?)
    }
}

pub struct JniSignedPreKeyStore<'a> {
    env: RefCell<EnvHandle<'a>>,
    store: &'a JObject<'a>,
}

impl<'a> JniSignedPreKeyStore<'a> {
    pub fn new<'context: 'a>(
        env: &mut JNIEnv<'context>,
        store: &'a JObject<'a>,
    ) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            store,
            ClassName("org.signal.libsignal.protocol.state.SignedPreKeyStore"),
        )?;
        Ok(Self {
            env: EnvHandle::new(env).into(),
            store,
        })
    }
}

impl JniSignedPreKeyStore<'_> {
    fn do_get_signed_pre_key(&self, prekey_id: u32) -> Result<SignedPreKeyRecord, SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "loadSignedPreKey", |env| {
                let callback_args = jni_args!((
            prekey_id.convert_into(env)? => int
        ) -> org.signal.libsignal.protocol.state.SignedPreKeyRecord);
                let spk: Option<SignedPreKeyRecord> = get_object_with_native_handle(
                    env,
                    self.store,
                    callback_args,
                    "loadSignedPreKey",
                )?;
                match spk {
                    Some(spk) => Ok(spk),
                    None => Err(SignalJniError::Protocol(
                        SignalProtocolError::InvalidSignedPreKeyId,
                    )),
                }
            })
    }

    fn do_save_signed_pre_key(
        &mut self,
        prekey_id: u32,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "storeSignedPreKey", |env| {
                let record_handle = record.clone().convert_into(env)?;
                let jobject_record = jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.state.SignedPreKeyRecord"),
                    record_handle,
                )?;
                let callback_args = jni_args!((
                    prekey_id.convert_into(env)? => int,
                    jobject_record => org.signal.libsignal.protocol.state.SignedPreKeyRecord
                ) -> void);
                call_method_checked(env, self.store, "storeSignedPreKey", callback_args)?;
                Ok(())
            })
    }
}

#[async_trait(? Send)]
impl SignedPreKeyStore for JniSignedPreKeyStore<'_> {
    async fn get_signed_pre_key(
        &self,
        prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_signed_pre_key(prekey_id.into())?)
    }

    async fn save_signed_pre_key(
        &mut self,
        prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_signed_pre_key(prekey_id.into(), record)?)
    }
}

pub struct JniKyberPreKeyStore<'a> {
    env: RefCell<EnvHandle<'a>>,
    store: &'a JObject<'a>,
}

impl<'a> JniKyberPreKeyStore<'a> {
    pub fn new<'context: 'a>(
        env: &mut JNIEnv<'context>,
        store: &'a JObject<'a>,
    ) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            store,
            ClassName("org.signal.libsignal.protocol.state.KyberPreKeyStore"),
        )?;
        Ok(Self {
            env: EnvHandle::new(env).into(),
            store,
        })
    }
}

impl JniKyberPreKeyStore<'_> {
    fn do_get_kyber_pre_key(&self, prekey_id: u32) -> Result<KyberPreKeyRecord, SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "loadKyberPreKey", |env| {
                let callback_args = jni_args!((
            prekey_id.convert_into(env)? => int
        ) -> org.signal.libsignal.protocol.state.KyberPreKeyRecord);
                let kpk: Option<KyberPreKeyRecord> = get_object_with_native_handle(
                    env,
                    self.store,
                    callback_args,
                    "loadKyberPreKey",
                )?;
                match kpk {
                    Some(kpk) => Ok(kpk),
                    None => Err(SignalJniError::Protocol(
                        SignalProtocolError::InvalidKyberPreKeyId,
                    )),
                }
            })
    }

    fn do_save_kyber_pre_key(
        &mut self,
        prekey_id: u32,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "storeKyberPreKey", |env| {
                let record_handle = record.clone().convert_into(env)?;
                let jobject_record = jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.state.KyberPreKeyRecord"),
                    record_handle,
                )?;
                let callback_args = jni_args!((
                    prekey_id.convert_into(env)? => int,
                    jobject_record => org.signal.libsignal.protocol.state.KyberPreKeyRecord
                ) -> void);
                call_method_checked(env, self.store, "storeKyberPreKey", callback_args)?;
                Ok(())
            })
    }

    fn do_mark_kyber_pre_key_used(&mut self, prekey_id: u32) -> Result<(), SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "markKyberPreKeyUsed", |env| {
                let java_id = prekey_id.convert_into(env)?;
                call_method_checked(
                    env,
                    self.store,
                    "markKyberPreKeyUsed",
                    jni_args!((java_id => int) -> void),
                )?;
                Ok(())
            })
    }
}

#[async_trait(? Send)]
impl KyberPreKeyStore for JniKyberPreKeyStore<'_> {
    async fn get_kyber_pre_key(
        &self,
        prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_kyber_pre_key(prekey_id.into())?)
    }

    async fn save_kyber_pre_key(
        &mut self,
        prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_kyber_pre_key(prekey_id.into(), record)?)
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_mark_kyber_pre_key_used(prekey_id.into())?)
    }
}

pub struct JniSessionStore<'a> {
    env: RefCell<EnvHandle<'a>>,
    store: &'a JObject<'a>,
}

impl<'a> JniSessionStore<'a> {
    pub fn new<'context: 'a>(
        env: &mut JNIEnv<'context>,
        store: &'a JObject<'a>,
    ) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            store,
            ClassName("org.signal.libsignal.protocol.state.SessionStore"),
        )?;
        Ok(Self {
            env: EnvHandle::new(env).into(),
            store,
        })
    }
}

impl JniSessionStore<'_> {
    fn do_load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "loadSession", |env| {
                let address_jobject = protocol_address_to_jobject(env, address)?;

                let callback_args = jni_args!((
                    address_jobject => org.signal.libsignal.protocol.SignalProtocolAddress
                ) -> org.signal.libsignal.protocol.state.SessionRecord);
                get_object_with_native_handle(env, self.store, callback_args, "loadSession")
            })
    }

    fn do_store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "storeSession", |env| {
                let address_jobject = protocol_address_to_jobject(env, address)?;
                let record_handle = record.clone().convert_into(env)?;
                let session_jobject = jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.state.SessionRecord"),
                    record_handle,
                )?;

                let callback_args = jni_args!((
                    address_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
                    session_jobject => org.signal.libsignal.protocol.state.SessionRecord,
                ) -> void);
                call_method_checked(env, self.store, "storeSession", callback_args)?;
                Ok(())
            })
    }
}

#[async_trait(? Send)]
impl SessionStore for JniSessionStore<'_> {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        Ok(self.do_load_session(address)?)
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_session(address, record)?)
    }
}

pub struct JniSenderKeyStore<'a> {
    env: RefCell<EnvHandle<'a>>,
    store: &'a JObject<'a>,
}

impl<'a> JniSenderKeyStore<'a> {
    pub fn new<'context: 'a>(
        env: &mut JNIEnv<'context>,
        store: &'a JObject<'a>,
    ) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            store,
            ClassName("org.signal.libsignal.protocol.groups.state.SenderKeyStore"),
        )?;
        Ok(Self {
            env: EnvHandle::new(env).into(),
            store,
        })
    }
}

impl JniSenderKeyStore<'_> {
    fn do_store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "storeSenderKey", |env| {
                let sender_jobject = protocol_address_to_jobject(env, sender)?;
                let distribution_id_jobject = distribution_id.convert_into(env)?;
                let record_handle = record.clone().convert_into(env)?;
                let sender_key_record_jobject = jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.groups.state.SenderKeyRecord"),
                    record_handle,
                )?;

                let callback_args = jni_args!((
                    sender_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
                    distribution_id_jobject => java.util.UUID,
                    sender_key_record_jobject => org.signal.libsignal.protocol.groups.state.SenderKeyRecord,
                ) -> void);
                call_method_checked(env, self.store, "storeSenderKey", callback_args)?;

                Ok(())
            })
    }

    fn do_load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalJniError> {
        self.env
            .borrow_mut()
            .with_local_frame(8, "loadSenderKey", |env| {
                let sender_jobject = protocol_address_to_jobject(env, sender)?;
                let distribution_id_jobject = distribution_id.convert_into(env)?;
                let callback_args = jni_args!((
                    sender_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
                    distribution_id_jobject => java.util.UUID,
                ) -> org.signal.libsignal.protocol.groups.state.SenderKeyRecord);
                get_object_with_native_handle(env, self.store, callback_args, "loadSenderKey")
            })
    }
}

#[async_trait(? Send)]
impl SenderKeyStore for JniSenderKeyStore<'_> {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_sender_key(sender, distribution_id, record)?)
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        Ok(self.do_load_sender_key(sender, distribution_id)?)
    }
}
