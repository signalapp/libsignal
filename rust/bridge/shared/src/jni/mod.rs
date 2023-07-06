//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

extern crate jni_crate as jni;

use jni::objects::{JThrowable, JValue};
use jni::sys::jobject;

use attest::hsm_enclave::Error as HsmEnclaveError;
use attest::sgx_session::Error as SgxError;
use device_transfer::Error as DeviceTransferError;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use signal_pin::Error as PinError;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt::Display;

pub(crate) use jni::objects::{AutoArray, JClass, JObject, JString, ReleaseMode};
pub(crate) use jni::sys::{jboolean, jbyteArray, jint, jlong, jlongArray, jstring};
pub(crate) use jni::JNIEnv;

#[macro_use]
mod args;
pub use args::*;

#[macro_use]
mod convert;
pub use convert::*;

mod error;
pub use error::*;

mod io;
pub use io::*;

mod storage;
pub use storage::*;

use usernames::{UsernameError, UsernameLinkError};

/// The type of boxed Rust values, as surfaced in JavaScript.
pub type ObjectHandle = jlong;

pub type JavaObject<'a> = JObject<'a>;
pub type JavaUUID<'a> = JObject<'a>;
pub type JavaReturnUUID = jobject;
pub type JavaCiphertextMessage<'a> = JObject<'a>;
pub type JavaReturnCiphertextMessage = jobject;
pub type JavaReturnMap = jobject;

/// Translates errors into Java exceptions.
///
/// Exceptions thrown in callbacks will be rethrown; all other errors will be mapped to an
/// appropriate Java exception class and thrown.
fn throw_error(env: &JNIEnv, error: SignalJniError) {
    fn try_throw<E: Display>(env: &JNIEnv, throwable: Result<JObject, E>, error: SignalJniError) {
        match throwable {
            Err(failure) => log::error!("failed to create exception for {}: {}", error, failure),
            Ok(throwable) => {
                let result = env.throw(JThrowable::from(throwable));
                if let Err(failure) = result {
                    log::error!("failed to throw exception for {}: {}", error, failure);
                }
            }
        }
    }

    // Handle special cases first.
    let error = match error {
        SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(
            callback,
            exception,
        )) => {
            // The usual way to write this code would be to match on the result of Error::downcast.
            // However, the "failure" result, which is intended to return the original type back,
            // only supports Send and Sync as additional traits. For anything else, we have to test first.
            if <dyn Error>::is::<ThrownException>(&*exception) {
                let exception =
                    <dyn Error>::downcast::<ThrownException>(exception).expect("just checked");
                if let Err(e) = env.throw(exception.as_obj()) {
                    log::error!("failed to rethrow exception from {}: {}", callback, e);
                }
                return;
            }

            // Fall through to generic handling below.
            SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(
                callback, exception,
            ))
        }

        SignalJniError::Signal(SignalProtocolError::UntrustedIdentity(ref addr)) => {
            let result = env.throw_new(
                jni_class_name!(org.signal.libsignal.protocol.UntrustedIdentityException),
                addr.name(),
            );
            if let Err(e) = result {
                log::error!("failed to throw exception for {}: {}", error, e);
            }
            return;
        }

        SignalJniError::Signal(SignalProtocolError::SessionNotFound(ref addr)) => {
            let throwable = protocol_address_to_jobject(env, addr)
                .and_then(|addr_object| Ok((addr_object, env.new_string(error.to_string())?)))
                .and_then(|(addr_object, message)| {
                    let args = jni_args!((
                        addr_object => org.signal.libsignal.protocol.SignalProtocolAddress,
                        message => java.lang.String,
                    ) -> void);
                    Ok(env.new_object(
                        jni_class_name!(org.signal.libsignal.protocol.NoSessionException),
                        args.sig,
                        &args.args,
                    )?)
                });

            try_throw(env, throwable, error);
            return;
        }

        SignalJniError::Signal(SignalProtocolError::InvalidRegistrationId(ref addr, _value)) => {
            let throwable = protocol_address_to_jobject(env, addr)
                .and_then(|addr_object| Ok((addr_object, env.new_string(error.to_string())?)))
                .and_then(|(addr_object, message)| {
                    let args = jni_args!((
                        addr_object => org.signal.libsignal.protocol.SignalProtocolAddress,
                        message => java.lang.String,
                    ) -> void);
                    Ok(env.new_object(
                        jni_class_name!(
                            org.signal.libsignal.protocol.InvalidRegistrationIdException
                        ),
                        args.sig,
                        &args.args,
                    )?)
                });

            try_throw(env, throwable, error);
            return;
        }

        SignalJniError::Signal(SignalProtocolError::InvalidSenderKeySession {
            distribution_id,
        }) => {
            let throwable = distribution_id
                .convert_into(env)
                .and_then(|distribution_id_obj| {
                    Ok((distribution_id_obj, env.new_string(error.to_string())?))
                })
                .and_then(|(distribution_id_obj, message)| {
                    let args = jni_args!((
                        distribution_id_obj => java.util.UUID,
                        message => java.lang.String,
                    ) -> void);
                    Ok(env.new_object(
                        jni_class_name!(
                            org.signal
                                .libsignal
                                .protocol
                                .groups
                                .InvalidSenderKeySessionException
                        ),
                        args.sig,
                        &args.args,
                    )?)
                });

            try_throw(env, throwable, error);
            return;
        }

        SignalJniError::Signal(SignalProtocolError::FingerprintVersionMismatch(theirs, ours)) => {
            let args = jni_args!((theirs as jint => int, ours as jint => int) -> void);
            let throwable = env.new_object(
                jni_class_name!(
                    org.signal
                        .libsignal
                        .protocol
                        .fingerprint
                        .FingerprintVersionMismatchException
                ),
                args.sig,
                &args.args,
            );

            try_throw(env, throwable, error);
            return;
        }

        SignalJniError::Signal(SignalProtocolError::SealedSenderSelfSend) => {
            let throwable = env.new_object(
                jni_class_name!(org.signal.libsignal.metadata.SelfSendException),
                jni_signature!(() -> void),
                &[],
            );

            try_throw(env, throwable, error);
            return;
        }

        SignalJniError::UnexpectedPanic(_)
        | SignalJniError::BadJniParameter(_)
        | SignalJniError::UnexpectedJniResultType(_, _) => {
            // java.lang.AssertionError has a slightly different signature.
            let throwable = env.new_string(error.to_string()).and_then(|message| {
                let args = jni_args!((message => java.lang.Object) -> void);
                env.new_object(
                    jni_class_name!(java.lang.AssertionError),
                    args.sig,
                    &args.args,
                )
            });

            try_throw(env, throwable, error);
            return;
        }

        e => e,
    };

    let exception_type = match error {
        SignalJniError::NullHandle => jni_class_name!(java.lang.NullPointerException),

        SignalJniError::Signal(SignalProtocolError::InvalidState(_, _))
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidState) => {
            jni_class_name!(java.lang.IllegalStateException)
        }

        SignalJniError::Signal(SignalProtocolError::InvalidArgument(_))
        | SignalJniError::SignalCrypto(SignalCryptoError::UnknownAlgorithm(_, _))
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidInputSize)
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidNonceSize)
        | SignalJniError::IncorrectArrayLength { .. } => {
            jni_class_name!(java.lang.IllegalArgumentException)
        }

        SignalJniError::IntegerOverflow(_)
        | SignalJniError::Jni(_)
        | SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(_, _))
        | SignalJniError::Signal(SignalProtocolError::FfiBindingError(_))
        | SignalJniError::DeviceTransfer(DeviceTransferError::InternalError(_))
        | SignalJniError::DeviceTransfer(DeviceTransferError::KeyDecodingFailed) => {
            jni_class_name!(java.lang.RuntimeException)
        }

        SignalJniError::Signal(SignalProtocolError::DuplicatedMessage(_, _)) => {
            jni_class_name!(org.signal.libsignal.protocol.DuplicateMessageException)
        }

        SignalJniError::Signal(SignalProtocolError::InvalidPreKeyId)
        | SignalJniError::Signal(SignalProtocolError::InvalidSignedPreKeyId)
        | SignalJniError::Signal(SignalProtocolError::InvalidKyberPreKeyId) => {
            jni_class_name!(org.signal.libsignal.protocol.InvalidKeyIdException)
        }

        SignalJniError::Signal(SignalProtocolError::NoKeyTypeIdentifier)
        | SignalJniError::Signal(SignalProtocolError::SignatureValidationFailed)
        | SignalJniError::Signal(SignalProtocolError::BadKeyType(_))
        | SignalJniError::Signal(SignalProtocolError::BadKeyLength(_, _))
        | SignalJniError::Signal(SignalProtocolError::InvalidMacKeyLength(_))
        | SignalJniError::Signal(SignalProtocolError::BadKEMKeyType(_))
        | SignalJniError::Signal(SignalProtocolError::WrongKEMKeyType(_, _))
        | SignalJniError::Signal(SignalProtocolError::BadKEMKeyLength(_, _))
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidKeySize) => {
            jni_class_name!(org.signal.libsignal.protocol.InvalidKeyException)
        }

        SignalJniError::Signal(SignalProtocolError::NoSenderKeyState { .. }) => {
            jni_class_name!(org.signal.libsignal.protocol.NoSessionException)
        }

        SignalJniError::Signal(SignalProtocolError::InvalidSessionStructure(_)) => {
            jni_class_name!(org.signal.libsignal.protocol.InvalidSessionException)
        }

        SignalJniError::Signal(SignalProtocolError::InvalidMessage(..))
        | SignalJniError::Signal(SignalProtocolError::CiphertextMessageTooShort(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidProtobufEncoding)
        | SignalJniError::Signal(SignalProtocolError::InvalidSealedSenderMessage(_))
        | SignalJniError::Signal(SignalProtocolError::BadKEMCiphertextLength(_, _))
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidTag) => {
            jni_class_name!(org.signal.libsignal.protocol.InvalidMessageException)
        }

        SignalJniError::Signal(SignalProtocolError::UnrecognizedCiphertextVersion(_))
        | SignalJniError::Signal(SignalProtocolError::UnrecognizedMessageVersion(_))
        | SignalJniError::Signal(SignalProtocolError::UnknownSealedSenderVersion(_)) => {
            jni_class_name!(org.signal.libsignal.protocol.InvalidVersionException)
        }

        SignalJniError::Signal(SignalProtocolError::LegacyCiphertextVersion(_)) => {
            jni_class_name!(org.signal.libsignal.protocol.LegacyMessageException)
        }

        SignalJniError::Signal(SignalProtocolError::FingerprintParsingError) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .protocol
                    .fingerprint
                    .FingerprintParsingException
            )
        }

        SignalJniError::Signal(SignalProtocolError::SealedSenderSelfSend)
        | SignalJniError::Signal(SignalProtocolError::UntrustedIdentity(_))
        | SignalJniError::Signal(SignalProtocolError::FingerprintVersionMismatch(_, _))
        | SignalJniError::Signal(SignalProtocolError::SessionNotFound(..))
        | SignalJniError::Signal(SignalProtocolError::InvalidRegistrationId(..))
        | SignalJniError::Signal(SignalProtocolError::InvalidSenderKeySession { .. })
        | SignalJniError::UnexpectedPanic(_)
        | SignalJniError::BadJniParameter(_)
        | SignalJniError::UnexpectedJniResultType(_, _) => {
            unreachable!("already handled in prior match")
        }

        SignalJniError::HsmEnclave(HsmEnclaveError::HSMHandshakeError(_))
        | SignalJniError::HsmEnclave(HsmEnclaveError::HSMCommunicationError(_)) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .hsmenclave
                    .EnclaveCommunicationFailureException
            )
        }
        SignalJniError::HsmEnclave(HsmEnclaveError::TrustedCodeError) => {
            jni_class_name!(org.signal.libsignal.hsmenclave.TrustedCodeMismatchException)
        }
        SignalJniError::HsmEnclave(HsmEnclaveError::InvalidPublicKeyError)
        | SignalJniError::HsmEnclave(HsmEnclaveError::InvalidCodeHashError) => {
            jni_class_name!(java.lang.IllegalArgumentException)
        }
        SignalJniError::HsmEnclave(HsmEnclaveError::InvalidBridgeStateError) => {
            jni_class_name!(java.lang.IllegalStateException)
        }

        SignalJniError::Sgx(SgxError::NoiseHandshakeError(_))
        | SignalJniError::Sgx(SgxError::NoiseError(_)) => {
            jni_class_name!(org.signal.libsignal.attest.SgxCommunicationFailureException)
        }
        SignalJniError::Sgx(SgxError::DcapError(_)) => {
            jni_class_name!(org.signal.libsignal.attest.DcapException)
        }
        SignalJniError::Sgx(SgxError::AttestationDataError { .. }) => {
            jni_class_name!(org.signal.libsignal.attest.AttestationDataException)
        }
        SignalJniError::Sgx(SgxError::InvalidBridgeStateError) => {
            jni_class_name!(java.lang.IllegalStateException)
        }

        SignalJniError::Pin(PinError::Argon2Error(_))
        | SignalJniError::Pin(PinError::DecodingError(_))
        | SignalJniError::Pin(PinError::MrenclaveLookupError) => {
            jni_class_name!(java.lang.IllegalArgumentException)
        }

        SignalJniError::ZkGroupDeserializationFailure(_) => {
            jni_class_name!(org.signal.libsignal.zkgroup.InvalidInputException)
        }

        SignalJniError::ZkGroupVerificationFailure(_) => {
            jni_class_name!(org.signal.libsignal.zkgroup.VerificationFailedException)
        }

        SignalJniError::UsernameError(UsernameError::CannotBeEmpty) => {
            jni_class_name!(org.signal.libsignal.usernames.CannotBeEmptyException)
        }

        SignalJniError::UsernameError(UsernameError::CannotStartWithDigit) => {
            jni_class_name!(org.signal.libsignal.usernames.CannotStartWithDigitException)
        }

        SignalJniError::UsernameError(UsernameError::MissingSeparator) => {
            jni_class_name!(org.signal.libsignal.usernames.MissingSeparatorException)
        }

        SignalJniError::UsernameError(UsernameError::BadDiscriminator) => {
            jni_class_name!(org.signal.libsignal.usernames.BadDiscriminatorException)
        }

        SignalJniError::UsernameError(UsernameError::BadNicknameCharacter) => {
            jni_class_name!(org.signal.libsignal.usernames.BadNicknameCharacterException)
        }

        SignalJniError::UsernameError(UsernameError::NicknameTooShort) => {
            jni_class_name!(org.signal.libsignal.usernames.NicknameTooShortException)
        }

        SignalJniError::UsernameError(UsernameError::NicknameTooLong) => {
            jni_class_name!(org.signal.libsignal.usernames.NicknameTooLongException)
        }

        SignalJniError::UsernameError(UsernameError::ProofVerificationFailure) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .usernames
                    .ProofVerificationFailureException
            )
        }

        SignalJniError::UsernameLinkError(UsernameLinkError::InputDataTooLong) => {
            jni_class_name!(org.signal.libsignal.usernames.UsernameLinkInputDataTooLong)
        }

        SignalJniError::UsernameLinkError(UsernameLinkError::InvalidEntropyDataLength) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .usernames
                    .UsernameLinkInvalidEntropyDataLength
            )
        }

        SignalJniError::UsernameLinkError(_) => {
            jni_class_name!(org.signal.libsignal.usernames.UsernameLinkInvalidLinkData)
        }

        SignalJniError::Io(_) => {
            jni_class_name!(java.io.IOException)
        }

        #[cfg(feature = "signal-media")]
        SignalJniError::MediaSanitizeParse(_) => {
            jni_class_name!(org.signal.libsignal.media.ParseException)
        }
    };

    if let Err(e) = env.throw_new(exception_type, error.to_string()) {
        log::error!("failed to throw exception for {}: {}", error, e);
    }
}

/// Provides a dummy value to return when an exception is thrown.
pub trait JniDummyValue {
    fn dummy_value() -> Self;
}

impl JniDummyValue for ObjectHandle {
    fn dummy_value() -> Self {
        0
    }
}

impl JniDummyValue for jint {
    fn dummy_value() -> Self {
        0
    }
}

impl JniDummyValue for jobject {
    fn dummy_value() -> Self {
        std::ptr::null_mut()
    }
}

impl JniDummyValue for jboolean {
    fn dummy_value() -> Self {
        0
    }
}

impl JniDummyValue for () {
    fn dummy_value() -> Self {}
}

#[inline(always)]
pub fn run_ffi_safe<F: FnOnce() -> Result<R, SignalJniError> + std::panic::UnwindSafe, R>(
    env: &JNIEnv,
    f: F,
) -> R
where
    R: JniDummyValue,
{
    match std::panic::catch_unwind(f) {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            throw_error(env, e);
            R::dummy_value()
        }
        Err(r) => {
            throw_error(env, SignalJniError::UnexpectedPanic(r));
            R::dummy_value()
        }
    }
}

pub unsafe fn native_handle_cast<T>(
    handle: ObjectHandle,
) -> Result<&'static mut T, SignalJniError> {
    /*
    Should we try testing the encoded pointer for sanity here, beyond
    being null? For example verifying that lowest bits are zero,
    highest bits are zero, greater than 64K, etc?
    */
    if handle == 0 {
        return Err(SignalJniError::NullHandle);
    }

    Ok(&mut *(handle as *mut T))
}

/// Calls a passed in function with a local frame of capacity that's passed in. Basically just
/// the jni with_local_frame except with the result type changed to use SignalJniError instead.
pub fn with_local_frame<'a, F>(env: &'a JNIEnv, capacity: i32, f: F) -> SignalJniResult<JObject<'a>>
where
    F: FnOnce() -> SignalJniResult<JObject<'a>>,
{
    env.push_local_frame(capacity)?;
    let res = f();
    match res {
        Ok(obj) => Ok(env.pop_local_frame(obj)?),
        Err(e) => {
            env.pop_local_frame(JObject::null())?;
            Err(e)
        }
    }
}

/// Calls a passed in function with a local frame of capacity that's passed in. Basically just
/// the jni with_local_frame except with the result type changed to use SignalJniError instead.
pub fn with_local_frame_no_jobject_result<F, T>(
    env: &JNIEnv,
    capacity: i32,
    f: F,
) -> SignalJniResult<T>
where
    F: FnOnce() -> SignalJniResult<T>,
{
    env.push_local_frame(capacity)?;
    let res = f();
    env.pop_local_frame(JObject::null())?;
    res
}

/// Calls a method and translates any thrown exceptions to
/// [`SignalProtocolError::ApplicationCallbackError`].
///
/// Wraps [`JNIEnv::call_method`]; all arguments are the same.
/// The result must have the correct type, or [`SignalJniError::UnexpectedJniResultType`] will be
/// returned instead.
pub fn call_method_checked<'a, O: Into<JObject<'a>>, R: TryFrom<JValue<'a>>, const LEN: usize>(
    env: &JNIEnv<'a>,
    obj: O,
    fn_name: &'static str,
    args: JniArgs<'a, R, LEN>,
) -> Result<R, SignalJniError> {
    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    let result = env.call_method(obj, fn_name, args.sig, &args.args);

    let throwable = env.exception_occurred()?;
    if **throwable == *JObject::null() {
        let result = result?;
        result
            .try_into()
            .map_err(|_| SignalJniError::UnexpectedJniResultType(fn_name, result.type_name()))
    } else {
        env.exception_clear()?;

        Err(SignalProtocolError::ApplicationCallbackError(
            fn_name,
            Box::new(ThrownException::new(env, throwable)?),
        )
        .into())
    }
}

/// Constructs a Java object from the given boxed Rust value.
///
/// Assumes there's a corresponding constructor that takes a single `long` to represent the address.
pub fn jobject_from_native_handle<'a>(
    env: &'a JNIEnv,
    class_name: &str,
    boxed_handle: ObjectHandle,
) -> Result<JObject<'a>, SignalJniError> {
    let class_type = env.find_class(class_name)?;
    let args = jni_args!((
        boxed_handle => long,
    ) -> void);
    Ok(env.new_object(class_type, args.sig, &args.args)?)
}

/// Constructs a Java SignalProtocolAddress from a ProtocolAddress value.
///
/// A convenience wrapper around `jobject_from_native_handle` for SignalProtocolAddress.
fn protocol_address_to_jobject<'a>(
    env: &'a JNIEnv,
    address: &ProtocolAddress,
) -> Result<JObject<'a>, SignalJniError> {
    jobject_from_native_handle(
        env,
        jni_class_name!(org.signal.libsignal.protocol.SignalProtocolAddress),
        address.clone().convert_into(env)?,
    )
}

/// Verifies that a Java object is a non-`null` instance of the given class.
pub fn check_jobject_type(
    env: &JNIEnv,
    obj: JObject,
    class_name: &'static str,
) -> Result<(), SignalJniError> {
    if obj.is_null() {
        return Err(SignalJniError::NullHandle);
    }

    let class = env.find_class(class_name)?;

    if !env.is_instance_of(obj, class)? {
        return Err(SignalJniError::BadJniParameter(class_name));
    }

    Ok(())
}

/// Calls a method, then clones the Rust value from the result.
///
/// The method is assumed to return a type with a `long nativeHandle()` method, which in turn must
/// produce a boxed Rust value.
pub fn get_object_with_native_handle<T: 'static + Clone, const LEN: usize>(
    env: &JNIEnv,
    store_obj: JObject,
    callback_args: JniArgs<JObject, LEN>,
    callback_fn: &'static str,
) -> Result<Option<T>, SignalJniError> {
    with_local_frame_no_jobject_result(env, 64, || -> SignalJniResult<Option<T>> {
        let obj = call_method_checked(env, store_obj, callback_fn, callback_args)?;
        if obj.is_null() {
            return Ok(None);
        }

        let handle: jlong = env
            .get_field(obj, "unsafeHandle", jni_signature!(long))?
            .try_into()?;
        if handle == 0 {
            return Ok(None);
        }

        let object = unsafe { native_handle_cast::<T>(handle)? };
        Ok(Some(object.clone()))
    })
}

/// Calls a method, then serializes the result.
///
/// The method is assumed to return a type with a `byte[] serialize()` method.
pub fn get_object_with_serialization<const LEN: usize>(
    env: &JNIEnv,
    store_obj: JObject,
    callback_args: JniArgs<JObject, LEN>,
    callback_fn: &'static str,
) -> Result<Option<Vec<u8>>, SignalJniError> {
    with_local_frame_no_jobject_result(env, 64, || -> SignalJniResult<Option<Vec<u8>>> {
        let obj = call_method_checked(env, store_obj, callback_fn, callback_args)?;

        if obj.is_null() {
            return Ok(None);
        }

        let bytes = call_method_checked(env, obj, "serialize", jni_args!(() -> [byte]))?;

        Ok(Some(env.convert_byte_array(*bytes)?))
    })
}

/// Like [CiphertextMessage], but non-owning.
///
/// Java has an interface for CiphertextMessage instead of an opaque handle, so we need to do extra
/// work to bridge it back to Rust.
#[derive(Clone, Copy)]
pub enum CiphertextMessageRef<'a> {
    SignalMessage(&'a SignalMessage),
    PreKeySignalMessage(&'a PreKeySignalMessage),
    SenderKeyMessage(&'a SenderKeyMessage),
    PlaintextContent(&'a PlaintextContent),
}

impl<'a> CiphertextMessageRef<'a> {
    pub fn message_type(self) -> CiphertextMessageType {
        match self {
            CiphertextMessageRef::SignalMessage(_) => CiphertextMessageType::Whisper,
            CiphertextMessageRef::PreKeySignalMessage(_) => CiphertextMessageType::PreKey,
            CiphertextMessageRef::SenderKeyMessage(_) => CiphertextMessageType::SenderKey,
            CiphertextMessageRef::PlaintextContent(_) => CiphertextMessageType::Plaintext,
        }
    }

    pub fn serialize(self) -> &'a [u8] {
        match self {
            CiphertextMessageRef::SignalMessage(x) => x.serialized(),
            CiphertextMessageRef::PreKeySignalMessage(x) => x.serialized(),
            CiphertextMessageRef::SenderKeyMessage(x) => x.serialized(),
            CiphertextMessageRef::PlaintextContent(x) => x.serialized(),
        }
    }
}

/// Used by [`bridge_handle`](crate::support::bridge_handle).
///
/// Not intended to be invoked directly.
macro_rules! jni_bridge_destroy {
    ( $typ:ty as $jni_name:ident ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<
                Java_org_signal_libsignal_internal_Native_ $jni_name _1Destroy
            >](
                _env: jni::JNIEnv,
                _class: jni::JClass,
                handle: jni::ObjectHandle,
            ) {
                if handle != 0 {
                    let _boxed_value = Box::from_raw(handle as *mut $typ);
                }
            }
        }
    };
}
