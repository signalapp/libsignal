//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;
use async_trait::async_trait;
use uuid::Uuid;

pub type JavaIdentityKeyStore<'a> = JObject<'a>;
pub type JavaPreKeyStore<'a> = JObject<'a>;
pub type JavaSignedPreKeyStore<'a> = JObject<'a>;
pub type JavaKyberPreKeyStore<'a> = JObject<'a>;
pub type JavaSessionStore<'a> = JObject<'a>;
pub type JavaSenderKeyStore<'a> = JObject<'a>;

pub struct JniIdentityKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniIdentityKeyStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            env,
            store,
            jni_class_name!(org.signal.libsignal.protocol.state.IdentityKeyStore),
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniIdentityKeyStore<'a> {
    fn do_get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalJniError> {
        let callback_args = jni_args!(() -> org.signal.libsignal.protocol.IdentityKeyPair);
        let bits = get_object_with_serialization(
            self.env,
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
    }

    fn do_get_local_registration_id(&self) -> Result<u32, SignalJniError> {
        let i: jint = call_method_checked(
            self.env,
            self.store,
            "getLocalRegistrationId",
            jni_args!(() -> int),
        )?;
        u32::convert_from(self.env, i)
    }

    fn do_save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let key_jobject = jobject_from_native_handle(
            self.env,
            jni_class_name!(org.signal.libsignal.protocol.IdentityKey),
            identity.public_key().convert_into(self.env)?,
        )?;
        let callback_args = jni_args!((
            address_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
            key_jobject => org.signal.libsignal.protocol.IdentityKey
        ) -> boolean);
        let result: jboolean =
            call_method_checked(self.env, self.store, "saveIdentity", callback_args)?;
        Ok(result != 0)
    }

    fn do_is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let key_jobject = jobject_from_native_handle(
            self.env,
            jni_class_name!(org.signal.libsignal.protocol.IdentityKey),
            identity.public_key().convert_into(self.env)?,
        )?;

        let direction_class = self.env.find_class(
            jni_class_name!(org.signal.libsignal.protocol.state.IdentityKeyStore::Direction),
        )?;
        let field_name = match direction {
            Direction::Sending => "SENDING",
            Direction::Receiving => "RECEIVING",
        };

        let field_value: JObject = self
            .env
            .get_static_field(
                direction_class,
                field_name,
                jni_signature!(org.signal.libsignal.protocol.state.IdentityKeyStore::Direction),
            )?
            .try_into()
            .expect("already checked type");

        let callback_args = jni_args!((
            address_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
            key_jobject => org.signal.libsignal.protocol.IdentityKey,
            field_value => org.signal.libsignal.protocol.state.IdentityKeyStore::Direction,
        ) -> boolean);
        let result: jboolean =
            call_method_checked(self.env, self.store, "isTrustedIdentity", callback_args)?;

        Ok(result != 0)
    }

    fn do_get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalJniError> {
        with_local_frame_no_jobject_result(
            self.env,
            64,
            || -> SignalJniResult<Option<IdentityKey>> {
                let address_jobject = protocol_address_to_jobject(self.env, address)?;
                let callback_args = jni_args!((
                    address_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
                ) -> org.signal.libsignal.protocol.IdentityKey);

                let bits = get_object_with_serialization(
                    self.env,
                    self.store,
                    callback_args,
                    "getIdentity",
                )?;

                match bits {
                    None => Ok(None),
                    Some(k) => Ok(Some(IdentityKey::decode(&k)?)),
                }
            },
        )
    }
}

#[async_trait(? Send)]
impl<'a> IdentityKeyStore for JniIdentityKeyStore<'a> {
    async fn get_identity_key_pair(
        &self,
        _ctx: Context,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.do_get_identity_key_pair()?)
    }

    async fn get_local_registration_id(&self, _ctx: Context) -> Result<u32, SignalProtocolError> {
        Ok(self.do_get_local_registration_id()?)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.do_save_identity(address, identity)?)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.do_is_trusted_identity(address, identity, direction)?)
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self.do_get_identity(address)?)
    }
}

pub struct JniPreKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniPreKeyStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            env,
            store,
            jni_class_name!(org.signal.libsignal.protocol.state.PreKeyStore),
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniPreKeyStore<'a> {
    fn do_get_pre_key(&self, prekey_id: u32) -> Result<PreKeyRecord, SignalJniError> {
        let callback_args = jni_args!((
            prekey_id.convert_into(self.env)? => int
        ) -> org.signal.libsignal.protocol.state.PreKeyRecord);
        let pk: Option<PreKeyRecord> =
            get_object_with_native_handle(self.env, self.store, callback_args, "loadPreKey")?;
        match pk {
            Some(pk) => Ok(pk),
            None => Err(SignalJniError::Signal(SignalProtocolError::InvalidPreKeyId)),
        }
    }

    fn do_save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
    ) -> Result<(), SignalJniError> {
        let jobject_record = jobject_from_native_handle(
            self.env,
            jni_class_name!(org.signal.libsignal.protocol.state.PreKeyRecord),
            record.clone().convert_into(self.env)?,
        )?;
        let callback_args = jni_args!((
            prekey_id.convert_into(self.env)? => int,
            jobject_record => org.signal.libsignal.protocol.state.PreKeyRecord
        ) -> void);
        call_method_checked(self.env, self.store, "storePreKey", callback_args)?;
        Ok(())
    }

    fn do_remove_pre_key(&mut self, prekey_id: u32) -> Result<(), SignalJniError> {
        call_method_checked(
            self.env,
            self.store,
            "removePreKey",
            jni_args!((prekey_id.convert_into(self.env)? => int) -> void),
        )?;
        Ok(())
    }
}

#[async_trait(? Send)]
impl<'a> PreKeyStore for JniPreKeyStore<'a> {
    async fn get_pre_key(
        &self,
        prekey_id: PreKeyId,
        _ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_pre_key(prekey_id.into())?)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_pre_key(prekey_id.into(), record)?)
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_remove_pre_key(prekey_id.into())?)
    }
}

pub struct JniSignedPreKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniSignedPreKeyStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            env,
            store,
            jni_class_name!(org.signal.libsignal.protocol.state.SignedPreKeyStore),
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSignedPreKeyStore<'a> {
    fn do_get_signed_pre_key(&self, prekey_id: u32) -> Result<SignedPreKeyRecord, SignalJniError> {
        let callback_args = jni_args!((
            prekey_id.convert_into(self.env)? => int
        ) -> org.signal.libsignal.protocol.state.SignedPreKeyRecord);
        let spk: Option<SignedPreKeyRecord> =
            get_object_with_native_handle(self.env, self.store, callback_args, "loadSignedPreKey")?;
        match spk {
            Some(spk) => Ok(spk),
            None => Err(SignalJniError::Signal(
                SignalProtocolError::InvalidSignedPreKeyId,
            )),
        }
    }

    fn do_save_signed_pre_key(
        &mut self,
        prekey_id: u32,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalJniError> {
        let jobject_record = jobject_from_native_handle(
            self.env,
            jni_class_name!(org.signal.libsignal.protocol.state.SignedPreKeyRecord),
            record.clone().convert_into(self.env)?,
        )?;
        let callback_args = jni_args!((
            prekey_id.convert_into(self.env)? => int,
            jobject_record => org.signal.libsignal.protocol.state.SignedPreKeyRecord
        ) -> void);
        call_method_checked(self.env, self.store, "storeSignedPreKey", callback_args)?;
        Ok(())
    }
}

#[async_trait(? Send)]
impl<'a> SignedPreKeyStore for JniSignedPreKeyStore<'a> {
    async fn get_signed_pre_key(
        &self,
        prekey_id: SignedPreKeyId,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_signed_pre_key(prekey_id.into())?)
    }

    async fn save_signed_pre_key(
        &mut self,
        prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_signed_pre_key(prekey_id.into(), record)?)
    }
}

pub struct JniKyberPreKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniKyberPreKeyStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            env,
            store,
            jni_class_name!(org.signal.libsignal.protocol.state.KyberPreKeyStore),
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniKyberPreKeyStore<'a> {
    fn do_get_kyber_pre_key(&self, prekey_id: u32) -> Result<KyberPreKeyRecord, SignalJniError> {
        let callback_args = jni_args!((
            prekey_id.convert_into(self.env)? => int
        ) -> org.signal.libsignal.protocol.state.KyberPreKeyRecord);
        let kpk: Option<KyberPreKeyRecord> =
            get_object_with_native_handle(self.env, self.store, callback_args, "loadKyberPreKey")?;
        match kpk {
            Some(kpk) => Ok(kpk),
            None => Err(SignalJniError::Signal(
                SignalProtocolError::InvalidKyberPreKeyId,
            )),
        }
    }

    fn do_save_kyber_pre_key(
        &mut self,
        prekey_id: u32,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalJniError> {
        let jobject_record = jobject_from_native_handle(
            self.env,
            jni_class_name!(org.signal.libsignal.protocol.state.KyberPreKeyRecord),
            record.clone().convert_into(self.env)?,
        )?;
        let callback_args = jni_args!((
            prekey_id.convert_into(self.env)? => int,
            jobject_record => org.signal.libsignal.protocol.state.KyberPreKeyRecord
        ) -> void);
        call_method_checked(self.env, self.store, "storeKyberPreKey", callback_args)?;
        Ok(())
    }

    fn do_mark_kyber_pre_key_used(&mut self, prekey_id: u32) -> Result<(), SignalJniError> {
        call_method_checked(
            self.env,
            self.store,
            "markKyberPreKeyUsed",
            jni_args!((prekey_id.convert_into(self.env)? => int) -> void),
        )?;
        Ok(())
    }
}

#[async_trait(? Send)]
impl<'a> KyberPreKeyStore for JniKyberPreKeyStore<'a> {
    async fn get_kyber_pre_key(
        &self,
        prekey_id: KyberPreKeyId,
        _ctx: Context,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_kyber_pre_key(prekey_id.into())?)
    }

    async fn save_kyber_pre_key(
        &mut self,
        prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_kyber_pre_key(prekey_id.into(), record)?)
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        prekey_id: KyberPreKeyId,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_mark_kyber_pre_key_used(prekey_id.into())?)
    }
}

pub struct JniSessionStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniSessionStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            env,
            store,
            jni_class_name!(org.signal.libsignal.protocol.state.SessionStore),
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSessionStore<'a> {
    fn do_load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;

        let callback_args = jni_args!((
            address_jobject => org.signal.libsignal.protocol.SignalProtocolAddress
        ) -> org.signal.libsignal.protocol.state.SessionRecord);
        get_object_with_native_handle(self.env, self.store, callback_args, "loadSession")
    }

    fn do_store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let session_jobject = jobject_from_native_handle(
            self.env,
            jni_class_name!(org.signal.libsignal.protocol.state.SessionRecord),
            record.clone().convert_into(self.env)?,
        )?;

        let callback_args = jni_args!((
            address_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
            session_jobject => org.signal.libsignal.protocol.state.SessionRecord,
        ) -> void);
        call_method_checked(self.env, self.store, "storeSession", callback_args)?;
        Ok(())
    }
}

#[async_trait(? Send)]
impl<'a> SessionStore for JniSessionStore<'a> {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        Ok(self.do_load_session(address)?)
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_session(address, record)?)
    }
}

pub struct JniSenderKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniSenderKeyStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            env,
            store,
            jni_class_name!(org.signal.libsignal.protocol.groups.state.SenderKeyStore),
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSenderKeyStore<'a> {
    fn do_store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalJniError> {
        let sender_jobject = protocol_address_to_jobject(self.env, sender)?;
        let distribution_id_jobject = distribution_id.convert_into(self.env)?;
        let sender_key_record_jobject = jobject_from_native_handle(
            self.env,
            jni_class_name!(org.signal.libsignal.protocol.groups.state.SenderKeyRecord),
            record.clone().convert_into(self.env)?,
        )?;

        let callback_args = jni_args!((
            sender_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
            distribution_id_jobject => java.util.UUID,
            sender_key_record_jobject => org.signal.libsignal.protocol.groups.state.SenderKeyRecord,
        ) -> void);
        call_method_checked(self.env, self.store, "storeSenderKey", callback_args)?;

        Ok(())
    }

    fn do_load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalJniError> {
        let sender_jobject = protocol_address_to_jobject(self.env, sender)?;
        let distribution_id_jobject = distribution_id.convert_into(self.env)?;
        let callback_args = jni_args!((
            sender_jobject => org.signal.libsignal.protocol.SignalProtocolAddress,
            distribution_id_jobject => java.util.UUID,
        ) -> org.signal.libsignal.protocol.groups.state.SenderKeyRecord);
        get_object_with_native_handle(self.env, self.store, callback_args, "loadSenderKey")
    }
}

#[async_trait(? Send)]
impl<'a> SenderKeyStore for JniSenderKeyStore<'a> {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_sender_key(sender, distribution_id, record)?)
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        Ok(self.do_load_sender_key(sender, distribution_id)?)
    }
}
