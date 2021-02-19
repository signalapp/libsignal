//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]

use async_trait::async_trait;
use jni::objects::{JClass, JObject, JValue};
use jni::sys::{jbyteArray, jlongArray, jobject};
use jni::JNIEnv;
use std::convert::TryFrom;

use libsignal_bridge::jni::*;
use libsignal_protocol::*;

pub mod logging;
mod util;

use crate::util::*;

type JavaSessionStore<'a> = JObject<'a>;
type JavaIdentityKeyStore<'a> = JObject<'a>;
type JavaPreKeyStore<'a> = JObject<'a>;
type JavaSignedPreKeyStore<'a> = JObject<'a>;

type JavaCiphertextMessage = jobject;

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_IdentityKeyPair_1Deserialize(
    env: JNIEnv,
    _class: JClass,
    data: jbyteArray,
) -> jlongArray {
    run_ffi_safe(&env, || {
        let data = env.convert_byte_array(data)?;
        let key = IdentityKeyPair::try_from(data.as_ref())?;

        let public_key_handle = box_object(Ok(*key.identity_key().public_key()))?;
        let private_key_handle = box_object(Ok(*key.private_key()))?;
        let tuple = [public_key_handle, private_key_handle];

        let result = env.new_long_array(2)?;
        env.set_long_array_region(result, 0, &tuple)?;
        Ok(result)
    })
}

fn protocol_address_to_jobject<'a>(
    env: &'a JNIEnv,
    address: &ProtocolAddress,
) -> Result<JObject<'a>, SignalJniError> {
    let address_class = env.find_class("org/whispersystems/libsignal/SignalProtocolAddress")?;
    let address_ctor_args = [
        JObject::from(env.new_string(address.name())?).into(),
        JValue::from(jint_from_u32(Ok(address.device_id()))?),
    ];

    let address_ctor_sig = "(Ljava/lang/String;I)V";
    let address_jobject = env.new_object(address_class, address_ctor_sig, &address_ctor_args)?;
    Ok(address_jobject)
}

pub struct JniIdentityKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniIdentityKeyStore<'a> {
    fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/IdentityKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniIdentityKeyStore<'a> {
    fn do_get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalJniError> {
        let callback_sig = "()Lorg/whispersystems/libsignal/IdentityKeyPair;";
        let bits = get_object_with_serialization(
            self.env,
            self.store,
            &[],
            callback_sig,
            "getIdentityKeyPair",
        )?;

        match bits {
            None => Err(SignalJniError::Signal(SignalProtocolError::InternalError(
                "getIdentityKeyPair returned null",
            ))),
            Some(k) => Ok(IdentityKeyPair::try_from(k.as_ref())?),
        }
    }

    fn do_get_local_registration_id(&self) -> Result<u32, SignalJniError> {
        let callback_sig = "()I";

        let rvalue = call_method_checked(
            self.env,
            self.store,
            "getLocalRegistrationId",
            callback_sig,
            &[],
        )?;
        match rvalue {
            JValue::Int(i) => jint_to_u32(i),
            _ => Err(SignalJniError::UnexpectedJniResultType(
                "getLocalRegistrationId",
                rvalue.type_name(),
            )),
        }
    }

    fn do_save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let key_jobject = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/IdentityKey",
            identity.serialize().as_ref(),
        )?;
        let callback_sig = "(Lorg/whispersystems/libsignal/SignalProtocolAddress;Lorg/whispersystems/libsignal/IdentityKey;)Z";
        let callback_args = [address_jobject.into(), key_jobject.into()];
        let result = call_method_checked(
            self.env,
            self.store,
            "saveIdentity",
            callback_sig,
            &callback_args,
        )?;

        match result {
            JValue::Bool(b) => Ok(b != 0),
            _ => Err(SignalJniError::UnexpectedJniResultType(
                "saveIdentity",
                result.type_name(),
            )),
        }
    }

    fn do_is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let key_jobject = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/IdentityKey",
            identity.serialize().as_ref(),
        )?;

        let direction_class = self
            .env
            .find_class("org/whispersystems/libsignal/state/IdentityKeyStore$Direction")?;
        let field_name = match direction {
            Direction::Sending => "SENDING",
            Direction::Receiving => "RECEIVING",
        };

        let field_value = self.env.get_static_field(
            direction_class,
            field_name,
            "Lorg/whispersystems/libsignal/state/IdentityKeyStore$Direction;",
        )?;

        let callback_sig = "(Lorg/whispersystems/libsignal/SignalProtocolAddress;Lorg/whispersystems/libsignal/IdentityKey;Lorg/whispersystems/libsignal/state/IdentityKeyStore$Direction;)Z";
        let callback_args = [address_jobject.into(), key_jobject.into(), field_value];
        let result = call_method_checked(
            self.env,
            self.store,
            "isTrustedIdentity",
            callback_sig,
            &callback_args,
        )?;

        match result {
            JValue::Bool(b) => Ok(b != 0),
            _ => Err(SignalJniError::UnexpectedJniResultType(
                "isTrustedIdentity",
                result.type_name(),
            )),
        }
    }

    fn do_get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let callback_sig = "(Lorg/whispersystems/libsignal/SignalProtocolAddress;)Lorg/whispersystems/libsignal/IdentityKey;";
        let callback_args = [address_jobject.into()];

        let bits = get_object_with_serialization(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "getIdentity",
        )?;

        match bits {
            None => Ok(None),
            Some(k) => Ok(Some(IdentityKey::decode(&k)?)),
        }
    }
}

#[async_trait(?Send)]
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
    fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/PreKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniPreKeyStore<'a> {
    fn do_get_pre_key(&self, prekey_id: u32) -> Result<PreKeyRecord, SignalJniError> {
        let callback_sig = "(I)Lorg/whispersystems/libsignal/state/PreKeyRecord;";
        let callback_args = [JValue::from(jint_from_u32(Ok(prekey_id))?)];
        let pk = get_object_with_native_handle::<PreKeyRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadPreKey",
        )?;
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
        let jobject_record = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/state/PreKeyRecord",
            &record.serialize()?,
        )?;
        let callback_sig = "(I,Lorg/whispersystems/libsignal/state/PreKeyRecord;)V";
        let callback_args = [
            JValue::from(jint_from_u32(Ok(prekey_id))?),
            jobject_record.into(),
        ];
        call_method_checked(
            self.env,
            self.store,
            "storePreKey",
            callback_sig,
            &callback_args,
        )?;
        Ok(())
    }

    fn do_remove_pre_key(&mut self, prekey_id: u32) -> Result<(), SignalJniError> {
        let callback_sig = "(I)V";
        let callback_args = [JValue::from(jint_from_u32(Ok(prekey_id))?)];
        call_method_checked(
            self.env,
            self.store,
            "removePreKey",
            callback_sig,
            &callback_args,
        )?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> PreKeyStore for JniPreKeyStore<'a> {
    async fn get_pre_key(
        &self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_pre_key(prekey_id)?)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_pre_key(prekey_id, record)?)
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_remove_pre_key(prekey_id)?)
    }
}

pub struct JniSignedPreKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniSignedPreKeyStore<'a> {
    fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/SignedPreKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSignedPreKeyStore<'a> {
    fn do_get_signed_pre_key(&self, prekey_id: u32) -> Result<SignedPreKeyRecord, SignalJniError> {
        let callback_sig = "(I)Lorg/whispersystems/libsignal/state/SignedPreKeyRecord;";
        let callback_args = [JValue::from(jint_from_u32(Ok(prekey_id))?)];
        let spk = get_object_with_native_handle::<SignedPreKeyRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadSignedPreKey",
        )?;
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
        let jobject_record = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/state/SignedPreKeyRecord",
            &record.serialize()?,
        )?;
        let callback_sig = "(I,Lorg/whispersystems/libsignal/state/SignedPreKeyRecord;)V";
        let callback_args = [
            JValue::from(jint_from_u32(Ok(prekey_id))?),
            jobject_record.into(),
        ];
        call_method_checked(
            self.env,
            self.store,
            "storeSignedPreKey",
            callback_sig,
            &callback_args,
        )?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> SignedPreKeyStore for JniSignedPreKeyStore<'a> {
    async fn get_signed_pre_key(
        &self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_signed_pre_key(prekey_id)?)
    }

    async fn save_signed_pre_key(
        &mut self,
        prekey_id: u32,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_signed_pre_key(prekey_id, record)?)
    }
}

pub struct JniSessionStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniSessionStore<'a> {
    fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/SessionStore",
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

        let callback_sig = "(Lorg/whispersystems/libsignal/SignalProtocolAddress;)Lorg/whispersystems/libsignal/state/SessionRecord;";
        let callback_args = [address_jobject.into()];
        get_object_with_native_handle::<SessionRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadSession",
        )
    }

    fn do_store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let session_jobject = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/state/SessionRecord",
            &record.serialize()?,
        )?;

        let callback_sig = "(Lorg/whispersystems/libsignal/SignalProtocolAddress;Lorg/whispersystems/libsignal/state/SessionRecord;)V";
        let callback_args = [address_jobject.into(), session_jobject.into()];
        call_method_checked(
            self.env,
            self.store,
            "storeSession",
            callback_sig,
            &callback_args,
        )?;
        Ok(())
    }
}

#[async_trait(?Send)]
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

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionBuilder_1ProcessPreKeyBundle(
    env: JNIEnv,
    _class: JClass,
    bundle: ObjectHandle,
    protocol_address: ObjectHandle,
    session_store: JavaSessionStore,
    identity_key_store: JavaIdentityKeyStore,
) {
    run_ffi_safe(&env, || {
        let bundle = native_handle_cast::<PreKeyBundle>(bundle)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;

        let mut identity_key_store = JniIdentityKeyStore::new(&env, identity_key_store)?;
        let mut session_store = JniSessionStore::new(&env, session_store)?;

        let mut csprng = rand::rngs::OsRng;
        expect_ready(process_prekey_bundle(
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            bundle,
            &mut csprng,
            None,
        ))?;

        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionCipher_1EncryptMessage(
    env: JNIEnv,
    _class: JClass,
    message: jbyteArray,
    protocol_address: ObjectHandle,
    session_store: JavaSessionStore,
    identity_key_store: JavaIdentityKeyStore,
) -> JavaCiphertextMessage {
    run_ffi_safe(&env, || {
        let message = env.convert_byte_array(message)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;

        let mut identity_key_store = JniIdentityKeyStore::new(&env, identity_key_store)?;
        let mut session_store = JniSessionStore::new(&env, session_store)?;

        let ctext = expect_ready(message_encrypt(
            &message,
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            None,
        ))?;

        let obj = match ctext {
            CiphertextMessage::SignalMessage(m) => jobject_from_native_handle(
                &env,
                "org/whispersystems/libsignal/protocol/SignalMessage",
                box_object::<SignalMessage>(Ok(m))?,
            ),
            CiphertextMessage::PreKeySignalMessage(m) => jobject_from_native_handle(
                &env,
                "org/whispersystems/libsignal/protocol/PreKeySignalMessage",
                box_object::<PreKeySignalMessage>(Ok(m))?,
            ),
            _ => Err(SignalJniError::Signal(SignalProtocolError::InternalError(
                "Unexpected result type from message_encrypt",
            ))),
        };

        Ok(obj?.into_inner())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionCipher_1DecryptSignalMessage(
    env: JNIEnv,
    _class: JClass,
    message: ObjectHandle,
    protocol_address: ObjectHandle,
    session_store: JavaSessionStore,
    identity_key_store: JavaIdentityKeyStore,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let message = native_handle_cast::<SignalMessage>(message)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;

        let mut identity_key_store = JniIdentityKeyStore::new(&env, identity_key_store)?;
        let mut session_store = JniSessionStore::new(&env, session_store)?;

        let mut csprng = rand::rngs::OsRng;
        let ptext = expect_ready(message_decrypt_signal(
            &message,
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            &mut csprng,
            None,
        ))?;

        to_jbytearray(&env, Ok(ptext))
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SessionCipher_1DecryptPreKeySignalMessage(
    env: JNIEnv,
    _class: JClass,
    message: ObjectHandle,
    protocol_address: ObjectHandle,
    session_store: JavaSessionStore,
    identity_key_store: JavaIdentityKeyStore,
    prekey_store: JavaPreKeyStore,
    signed_prekey_store: JavaSignedPreKeyStore,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let message = native_handle_cast::<PreKeySignalMessage>(message)?;
        let protocol_address = native_handle_cast::<ProtocolAddress>(protocol_address)?;
        let mut identity_key_store = JniIdentityKeyStore::new(&env, identity_key_store)?;
        let mut session_store = JniSessionStore::new(&env, session_store)?;
        let mut prekey_store = JniPreKeyStore::new(&env, prekey_store)?;
        let mut signed_prekey_store = JniSignedPreKeyStore::new(&env, signed_prekey_store)?;

        let mut csprng = rand::rngs::OsRng;
        let ptext = expect_ready(message_decrypt_prekey(
            &message,
            &protocol_address,
            &mut session_store,
            &mut identity_key_store,
            &mut prekey_store,
            &mut signed_prekey_store,
            &mut csprng,
            None,
        ))?;

        to_jbytearray(&env, Ok(ptext))
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SealedSessionCipher_1Encrypt(
    env: JNIEnv,
    _class: JClass,
    destination: ObjectHandle,
    sender_cert: ObjectHandle,
    ptext: jbyteArray,
    session_store: JavaSessionStore,
    identity_store: JavaIdentityKeyStore,
) -> jbyteArray {
    run_ffi_safe(&env, || {
        let destination = native_handle_cast::<ProtocolAddress>(destination)?;
        let sender_cert = native_handle_cast::<SenderCertificate>(sender_cert)?;
        let ptext = env.convert_byte_array(ptext)?;

        let mut identity_store = JniIdentityKeyStore::new(&env, identity_store)?;
        let mut session_store = JniSessionStore::new(&env, session_store)?;

        let mut rng = rand::rngs::OsRng;

        let ctext = expect_ready(sealed_sender_encrypt(
            destination,
            sender_cert,
            &ptext,
            &mut session_store,
            &mut identity_store,
            None,
            &mut rng,
        ))?;
        to_jbytearray(&env, Ok(ctext))
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_client_internal_Native_SealedSessionCipher_1DecryptToUsmc(
    env: JNIEnv,
    _class: JClass,
    ctext: jbyteArray,
    identity_store: JavaIdentityKeyStore,
) -> ObjectHandle {
    run_ffi_safe(&env, || {
        let ctext = env.convert_byte_array(ctext)?;
        let mut identity_store = JniIdentityKeyStore::new(&env, identity_store)?;

        let usmc = expect_ready(sealed_sender_decrypt_to_usmc(
            &ctext,
            &mut identity_store,
            None,
        ))?;

        box_object::<UnidentifiedSenderMessageContent>(Ok(usmc))
    })
}
