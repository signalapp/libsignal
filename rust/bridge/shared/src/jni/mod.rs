//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::marker::PhantomData;

use attest::enclave::Error as SgxError;
use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use jni::objects::{GlobalRef, JThrowable, JValue, JValueOwned};
use jni::JavaVM;
use libsignal_protocol::*;
use once_cell::sync::OnceCell;
use signal_crypto::Error as SignalCryptoError;
use signal_pin::Error as PinError;

pub(crate) use jni::objects::{
    AutoElements, JByteArray, JClass, JLongArray, JObject, JObjectArray, JString, ReleaseMode,
};
pub(crate) use jni::sys::{jboolean, jint, jlong};
pub(crate) use jni::JNIEnv;

#[macro_use]
mod args;
pub use args::*;

#[macro_use]
mod convert;
pub use convert::*;

mod error;
pub use error::*;

mod futures;
pub use futures::*;

mod io;
pub use io::*;

mod storage;
pub use storage::*;

use usernames::{UsernameError, UsernameLinkError};

/// The type of boxed Rust values, as surfaced in JavaScript.
pub type ObjectHandle = jlong;

pub type JavaObject<'a> = JObject<'a>;
pub type JavaUUID<'a> = JObject<'a>;
pub type JavaCiphertextMessage<'a> = JObject<'a>;
pub type JavaMap<'a> = JObject<'a>;

/// A Java wrapper for a `CompletableFuture` type.
#[derive(Default)]
#[repr(transparent)] // Ensures that the representation is the same as JObject.
pub struct JavaCompletableFuture<'a, T> {
    future_object: JObject<'a>,
    result: PhantomData<fn(T)>,
}

impl<'a, T> From<JObject<'a>> for JavaCompletableFuture<'a, T> {
    fn from(future_object: JObject<'a>) -> Self {
        Self {
            future_object,
            result: PhantomData,
        }
    }
}

impl<'a, T> From<JavaCompletableFuture<'a, T>> for JObject<'a> {
    fn from(value: JavaCompletableFuture<'a, T>) -> Self {
        value.future_object
    }
}

fn convert_to_exception<'a, F>(env: &mut JNIEnv<'a>, error: SignalJniError, consume: F)
where
    F: FnOnce(&mut JNIEnv<'a>, Result<JThrowable<'a>, BridgeLayerError>, &dyn Display),
{
    // Handle special cases first.
    let error = match error {
        SignalJniError::Bridge(BridgeLayerError::CallbackException(callback, exception)) => {
            let throwable = env.new_local_ref(exception.as_obj()).map(JThrowable::from);
            consume(
                env,
                throwable.map_err(Into::into),
                &format!("error in method call '{callback}'"),
            );
            return;
        }
        SignalJniError::Io(error) if error.kind() == std::io::ErrorKind::Other => {
            let thrown_exception = error
                .get_ref()
                .and_then(|e| e.downcast_ref::<ThrownException>())
                .map(ThrownException::as_obj);

            if let Some(exception) = thrown_exception {
                consume(
                    env,
                    env.new_local_ref::<&JObject>(exception.as_ref())
                        .map(Into::into)
                        .map_err(Into::into),
                    &"error in callback".to_string(),
                );
                return;
            }
            SignalJniError::Io(error)
        }

        SignalJniError::Protocol(SignalProtocolError::ApplicationCallbackError(
            callback,
            exception,
        )) => {
            // The usual way to write this code would be to match on the result of Error::downcast.
            // However, the "failure" result, which is intended to return the original type back,
            // only supports Send and Sync as additional traits. For anything else, we have to test first.
            if <dyn Error>::is::<ThrownException>(&*exception) {
                let exception =
                    <dyn Error>::downcast::<ThrownException>(exception).expect("just checked");
                convert_to_exception(
                    env,
                    SignalJniError::Bridge(BridgeLayerError::CallbackException(
                        callback, *exception,
                    )),
                    consume,
                );
                return;
            }

            // Fall through to generic handling below.
            SignalJniError::Protocol(SignalProtocolError::ApplicationCallbackError(
                callback, exception,
            ))
        }

        SignalJniError::Protocol(SignalProtocolError::UntrustedIdentity(ref addr)) => {
            let throwable = env.new_string(addr.name()).and_then(|addr_name| {
                Ok(new_object(
                    env,
                    jni_class_name!(org.signal.libsignal.protocol.UntrustedIdentityException),
                    jni_args!((addr_name => java.lang.String) -> void),
                )?
                .into())
            });

            consume(env, throwable.map_err(Into::into), &error);
            return;
        }

        SignalJniError::Protocol(SignalProtocolError::SessionNotFound(ref addr)) => {
            let throwable = protocol_address_to_jobject(env, addr)
                .and_then(|addr_object| Ok((addr_object, env.new_string(error.to_string())?)))
                .and_then(|(addr_object, message)| {
                    Ok(new_object(
                        env,
                        jni_class_name!(org.signal.libsignal.protocol.NoSessionException),
                        jni_args!((
                            addr_object => org.signal.libsignal.protocol.SignalProtocolAddress,
                            message => java.lang.String,
                        ) -> void),
                    )?
                    .into())
                });

            consume(env, throwable, &error);
            return;
        }

        SignalJniError::Protocol(SignalProtocolError::InvalidRegistrationId(ref addr, _value)) => {
            let throwable = protocol_address_to_jobject(env, addr)
                .and_then(|addr_object| Ok((addr_object, env.new_string(error.to_string())?)))
                .and_then(|(addr_object, message)| {
                    Ok(new_object(
                        env,
                        jni_class_name!(
                            org.signal.libsignal.protocol.InvalidRegistrationIdException
                        ),
                        jni_args!((
                            addr_object => org.signal.libsignal.protocol.SignalProtocolAddress,
                            message => java.lang.String,
                        ) -> void),
                    )?
                    .into())
                });

            consume(env, throwable, &error);
            return;
        }

        SignalJniError::Protocol(SignalProtocolError::InvalidSenderKeySession {
            distribution_id,
        }) => {
            let throwable = distribution_id
                .convert_into(env)
                .and_then(|distribution_id_obj| {
                    Ok((distribution_id_obj, env.new_string(error.to_string())?))
                })
                .and_then(|(distribution_id_obj, message)| {
                    Ok(new_object(
                        env,
                        jni_class_name!(
                            org.signal
                                .libsignal
                                .protocol
                                .groups
                                .InvalidSenderKeySessionException
                        ),
                        jni_args!((
                            distribution_id_obj => java.util.UUID,
                            message => java.lang.String,
                        ) -> void),
                    )?
                    .into())
                });

            consume(env, throwable, &error);
            return;
        }

        SignalJniError::Protocol(SignalProtocolError::FingerprintVersionMismatch(theirs, ours)) => {
            let throwable = new_object(
                env,
                jni_class_name!(
                    org.signal
                        .libsignal
                        .protocol
                        .fingerprint
                        .FingerprintVersionMismatchException
                ),
                jni_args!((theirs as jint => int, ours as jint => int) -> void),
            )
            .map(JThrowable::from);

            consume(env, throwable.map_err(Into::into), &error);
            return;
        }

        SignalJniError::Protocol(SignalProtocolError::SealedSenderSelfSend) => {
            let throwable = new_object(
                env,
                jni_class_name!(org.signal.libsignal.metadata.SelfSendException),
                jni_args!(() -> void),
            )
            .map(JThrowable::from);

            consume(env, throwable.map_err(Into::into), &error);
            return;
        }

        SignalJniError::Bridge(BridgeLayerError::UnexpectedPanic(_))
        | SignalJniError::Bridge(BridgeLayerError::BadJniParameter(_))
        | SignalJniError::Bridge(BridgeLayerError::UnexpectedJniResultType(_, _)) => {
            // java.lang.AssertionError has a slightly different signature.
            let throwable = env.new_string(error.to_string()).and_then(|message| {
                Ok(new_object(
                    env,
                    jni_class_name!(java.lang.AssertionError),
                    jni_args!((message => java.lang.Object) -> void),
                )?
                .into())
            });

            consume(env, throwable.map_err(Into::into), &error);
            return;
        }

        e => e,
    };

    let exception_type = match &error {
        SignalJniError::Bridge(BridgeLayerError::NullPointer(_)) => {
            jni_class_name!(java.lang.NullPointerException)
        }

        SignalJniError::Protocol(SignalProtocolError::InvalidState(_, _)) => {
            jni_class_name!(java.lang.IllegalStateException)
        }

        SignalJniError::Protocol(SignalProtocolError::InvalidArgument(_))
        | SignalJniError::SignalCrypto(SignalCryptoError::UnknownAlgorithm(_, _))
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidInputSize)
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidNonceSize)
        | SignalJniError::Bridge(BridgeLayerError::BadArgument(_))
        | SignalJniError::Bridge(BridgeLayerError::IncorrectArrayLength { .. }) => {
            jni_class_name!(java.lang.IllegalArgumentException)
        }

        SignalJniError::Bridge(BridgeLayerError::IntegerOverflow(_))
        | SignalJniError::Bridge(BridgeLayerError::Jni(_))
        | SignalJniError::Protocol(SignalProtocolError::ApplicationCallbackError(_, _))
        | SignalJniError::Protocol(SignalProtocolError::FfiBindingError(_))
        | SignalJniError::DeviceTransfer(DeviceTransferError::InternalError(_))
        | SignalJniError::DeviceTransfer(DeviceTransferError::KeyDecodingFailed) => {
            jni_class_name!(java.lang.RuntimeException)
        }

        SignalJniError::Protocol(SignalProtocolError::DuplicatedMessage(_, _)) => {
            jni_class_name!(org.signal.libsignal.protocol.DuplicateMessageException)
        }

        SignalJniError::Protocol(SignalProtocolError::InvalidPreKeyId)
        | SignalJniError::Protocol(SignalProtocolError::InvalidSignedPreKeyId)
        | SignalJniError::Protocol(SignalProtocolError::InvalidKyberPreKeyId) => {
            jni_class_name!(org.signal.libsignal.protocol.InvalidKeyIdException)
        }

        SignalJniError::Protocol(SignalProtocolError::NoKeyTypeIdentifier)
        | SignalJniError::Protocol(SignalProtocolError::SignatureValidationFailed)
        | SignalJniError::Protocol(SignalProtocolError::BadKeyType(_))
        | SignalJniError::Protocol(SignalProtocolError::BadKeyLength(_, _))
        | SignalJniError::Protocol(SignalProtocolError::InvalidMacKeyLength(_))
        | SignalJniError::Protocol(SignalProtocolError::BadKEMKeyType(_))
        | SignalJniError::Protocol(SignalProtocolError::WrongKEMKeyType(_, _))
        | SignalJniError::Protocol(SignalProtocolError::BadKEMKeyLength(_, _))
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidKeySize) => {
            jni_class_name!(org.signal.libsignal.protocol.InvalidKeyException)
        }

        SignalJniError::Protocol(SignalProtocolError::NoSenderKeyState { .. }) => {
            jni_class_name!(org.signal.libsignal.protocol.NoSessionException)
        }

        SignalJniError::Protocol(SignalProtocolError::InvalidSessionStructure(_)) => {
            jni_class_name!(org.signal.libsignal.protocol.InvalidSessionException)
        }

        SignalJniError::Protocol(SignalProtocolError::InvalidMessage(..))
        | SignalJniError::Protocol(SignalProtocolError::CiphertextMessageTooShort(_))
        | SignalJniError::Protocol(SignalProtocolError::InvalidProtobufEncoding)
        | SignalJniError::Protocol(SignalProtocolError::InvalidSealedSenderMessage(_))
        | SignalJniError::Protocol(SignalProtocolError::BadKEMCiphertextLength(_, _))
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidTag) => {
            jni_class_name!(org.signal.libsignal.protocol.InvalidMessageException)
        }

        SignalJniError::Protocol(SignalProtocolError::UnrecognizedCiphertextVersion(_))
        | SignalJniError::Protocol(SignalProtocolError::UnrecognizedMessageVersion(_))
        | SignalJniError::Protocol(SignalProtocolError::UnknownSealedSenderVersion(_)) => {
            jni_class_name!(org.signal.libsignal.protocol.InvalidVersionException)
        }

        SignalJniError::Protocol(SignalProtocolError::LegacyCiphertextVersion(_)) => {
            jni_class_name!(org.signal.libsignal.protocol.LegacyMessageException)
        }

        SignalJniError::Protocol(SignalProtocolError::FingerprintParsingError) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .protocol
                    .fingerprint
                    .FingerprintParsingException
            )
        }

        SignalJniError::Protocol(SignalProtocolError::SealedSenderSelfSend)
        | SignalJniError::Protocol(SignalProtocolError::UntrustedIdentity(_))
        | SignalJniError::Protocol(SignalProtocolError::FingerprintVersionMismatch(_, _))
        | SignalJniError::Protocol(SignalProtocolError::SessionNotFound(..))
        | SignalJniError::Protocol(SignalProtocolError::InvalidRegistrationId(..))
        | SignalJniError::Protocol(SignalProtocolError::InvalidSenderKeySession { .. })
        | SignalJniError::Bridge(BridgeLayerError::BadJniParameter(_))
        | SignalJniError::Bridge(BridgeLayerError::UnexpectedJniResultType(_, _))
        | SignalJniError::Bridge(BridgeLayerError::CallbackException(_, _))
        | SignalJniError::Bridge(BridgeLayerError::UnexpectedPanic(_)) => {
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
        SignalJniError::Sgx(SgxError::AttestationError(_)) => {
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

        SignalJniError::UsernameError(UsernameError::NicknameCannotBeEmpty) => {
            jni_class_name!(org.signal.libsignal.usernames.CannotBeEmptyException)
        }

        SignalJniError::UsernameError(UsernameError::NicknameCannotStartWithDigit) => {
            jni_class_name!(org.signal.libsignal.usernames.CannotStartWithDigitException)
        }

        SignalJniError::UsernameError(UsernameError::MissingSeparator) => {
            jni_class_name!(org.signal.libsignal.usernames.MissingSeparatorException)
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

        SignalJniError::UsernameError(UsernameError::DiscriminatorCannotBeEmpty) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .usernames
                    .DiscriminatorCannotBeEmptyException
            )
        }

        SignalJniError::UsernameError(UsernameError::DiscriminatorCannotBeZero) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .usernames
                    .DiscriminatorCannotBeZeroException
            )
        }

        SignalJniError::UsernameError(UsernameError::DiscriminatorCannotBeSingleDigit) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .usernames
                    .DiscriminatorCannotBeSingleDigitException
            )
        }

        SignalJniError::UsernameError(UsernameError::DiscriminatorCannotHaveLeadingZeros) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .usernames
                    .DiscriminatorCannotHaveLeadingZerosException
            )
        }

        SignalJniError::UsernameError(UsernameError::BadDiscriminatorCharacter) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .usernames
                    .BadDiscriminatorCharacterException
            )
        }

        SignalJniError::UsernameError(UsernameError::DiscriminatorTooLarge) => {
            jni_class_name!(
                org.signal
                    .libsignal
                    .usernames
                    .DiscriminatorTooLargeException
            )
        }

        SignalJniError::UsernameProofError(usernames::ProofVerificationFailure) => {
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
        SignalJniError::Mp4SanitizeParse(_) | SignalJniError::WebpSanitizeParse(_) => {
            jni_class_name!(org.signal.libsignal.media.ParseException)
        }

        SignalJniError::Cdsi(_) => jni_class_name!(org.signal.libsignal.net.CdsiLookupException),
        SignalJniError::Net(_) => jni_class_name!(org.signal.libsignal.net.NetworkException),
        #[cfg(feature = "testing-fns")]
        SignalJniError::TestingError { exception_class } => exception_class,
    };

    let throwable = env
        .new_string(error.to_string())
        .and_then(|message| {
            let class = get_preloaded_class(env, exception_type)
                .transpose()
                .unwrap_or_else(|| env.find_class(exception_type))?;
            Ok(new_object(env, class, jni_args!((message => java.lang.String) -> void))?.into())
        })
        .map_err(Into::into);
    consume(env, throwable, &error)
}

/// Translates errors into Java exceptions.
///
/// Exceptions thrown in callbacks will be rethrown; all other errors will be mapped to an
/// appropriate Java exception class and thrown.
fn throw_error(env: &mut JNIEnv, error: SignalJniError) {
    convert_to_exception(env, error, |env, throwable, error| match throwable {
        Err(failure) => log::error!("failed to create exception for {}: {}", error, failure),
        Ok(throwable) => {
            let result = env.throw(throwable);
            if let Err(failure) = result {
                log::error!("failed to throw exception for {}: {}", error, failure);
            }
        }
    });
}

#[inline(always)]
pub fn run_ffi_safe<'local, F, R>(env: &mut JNIEnv<'local>, f: F) -> R
where
    F: for<'a> FnOnce(&'a mut JNIEnv<'local>) -> Result<R, SignalJniError> + std::panic::UnwindSafe,
    R: Default,
{
    // This AssertUnwindSafe is not technically safe.
    // If we get a panic downstream, it is entirely possible the Java environment won't be usable anymore.
    // But if that's the case, we've got bigger problems!
    // So if we want to catch panics, we have to allow this.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(env))) {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            throw_error(env, e);
            R::default()
        }
        Err(r) => {
            throw_error(env, BridgeLayerError::UnexpectedPanic(r).into());
            R::default()
        }
    }
}

pub unsafe fn native_handle_cast<T>(
    handle: ObjectHandle,
) -> Result<&'static mut T, BridgeLayerError> {
    /*
    Should we try testing the encoded pointer for sanity here, beyond
    being null? For example verifying that lowest bits are zero,
    highest bits are zero, greater than 64K, etc?
    */
    if handle == 0 {
        return Err(BridgeLayerError::NullPointer(None));
    }

    Ok(&mut *(handle as *mut T))
}

/// Calls a method and translates any thrown exceptions to
/// [`BridgeLayerError::CallbackException`].
///
/// Wraps [`JNIEnv::call_method`].
/// The result must have the correct type, or [`BridgeLayerError::UnexpectedJniResultType`] will be
/// returned instead.
pub fn call_method_checked<
    'input,
    'output,
    O: AsRef<JObject<'input>>,
    R: TryFrom<JValueOwned<'output>>,
    const LEN: usize,
>(
    env: &mut JNIEnv<'output>,
    obj: O,
    fn_name: &'static str,
    args: JniArgs<R, LEN>,
) -> Result<R, BridgeLayerError> {
    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    let result = env.call_method(obj, fn_name, args.sig, &args.args);
    check_exceptions_and_convert_result(env, fn_name, result)
}

/// Calls a method and translates any thrown exceptions to
/// [`BridgeLayerError::CallbackException`].
///
/// Wraps [`JNIEnv::call_static_method`].
/// The result must have the correct type, or [`BridgeLayerError::UnexpectedJniResultType`] will be
/// returned instead.
pub fn call_static_method_checked<
    'input,
    'output,
    C: jni::descriptors::Desc<'output, JClass<'input>>,
    R: TryFrom<JValueOwned<'output>>,
    const LEN: usize,
>(
    env: &mut JNIEnv<'output>,
    cls: C,
    fn_name: &'static str,
    args: JniArgs<R, LEN>,
) -> Result<R, BridgeLayerError> {
    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    let result = env.call_static_method(cls, fn_name, args.sig, &args.args);
    check_exceptions_and_convert_result(env, fn_name, result)
}

fn check_exceptions_and_convert_result<'output, R: TryFrom<JValueOwned<'output>>>(
    env: &mut JNIEnv<'output>,
    fn_name: &'static str,
    result: jni::errors::Result<JValueOwned<'output>>,
) -> Result<R, BridgeLayerError> {
    let throwable = env.exception_occurred()?;
    if **throwable == *JObject::null() {
        let result = result?;
        let type_name = result.type_name();
        result
            .try_into()
            .map_err(|_| BridgeLayerError::UnexpectedJniResultType(fn_name, type_name))
    } else {
        env.exception_clear()?;

        Err(BridgeLayerError::CallbackException(
            fn_name,
            ThrownException::new(env, throwable)?,
        ))
    }
}

static PRELOADED_CLASSES: OnceCell<HashMap<&'static str, GlobalRef>> = OnceCell::new();

const PRELOADED_CLASS_NAMES: &[&str] = &[
    jni_class_name!(org.signal.libsignal.net.CdsiLookupResponse::Entry),
    jni_class_name!(org.signal.libsignal.net.CdsiLookupResponse),
    jni_class_name!(org.signal.libsignal.internal.TestingException),
];

/// Preloads some classes from the provided [`JNIEnv`].
///
/// Uses [`JNIEnv::find_class`] to cache some classes in a static variable for
/// later. These cached class instances can later be retrieved with
/// [`get_preloaded_class`].
pub fn preload_classes(env: &mut JNIEnv<'_>) -> Result<(), BridgeLayerError> {
    let _saved = PRELOADED_CLASSES.get_or_try_init(|| {
        let no_class_found_exceptions = {
            let first = env.find_class(jni_class_name!(java.lang.NoClassDefFoundError))?;
            let second = env.find_class(jni_class_name!(java.lang.ClassNotFoundException))?;
            [first, second]
        };

        let is_not_found_exception =
            |throwable: &JThrowable<'_>, env: &JNIEnv<'_>| -> jni::errors::Result<bool> {
                for no_class_found in &no_class_found_exceptions {
                    if env.is_same_object(env.get_object_class(throwable)?, no_class_found)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            };

        PRELOADED_CLASS_NAMES
            .iter()
            .map(|name| {
                let find_class_result = env.find_class(name);
                let throwable = env.exception_occurred()?;
                let class = if **throwable == *JObject::null() {
                    find_class_result?
                } else {
                    env.exception_clear()?;

                    if !is_not_found_exception(&throwable, env)? {
                        return Err(BridgeLayerError::CallbackException(
                            "FindClass",
                            ThrownException::new(env, throwable)?,
                        ));
                    }

                    // Ignore failures caused by nonexistent classes. This
                    // allows the same native library to be used with JAR files
                    // that contain different subsets of classes.
                    JObject::null().into()
                };
                Ok((*name, env.new_global_ref(class)?))
            })
            .collect::<Result<HashMap<_, _>, BridgeLayerError>>()
    })?;

    Ok(())
}

/// Loads a previously cached class.
///
/// Looks up the given class name saved by [`preload_classes`], if there was
/// one. Returns `Ok(None)` otherwise.
///
/// This is useful on platforms like Android where JVM-spawned threads have
/// access to application-defined classes but native threads (including Tokio
/// runtime threads) do not. A class object cached from a JVM-spawned thread can
/// be used by natively-spawned threads to access application-defined types.
pub fn get_preloaded_class<'output>(
    env: &mut JNIEnv<'output>,
    name: &'static str,
) -> Result<Option<JClass<'output>>, jni::errors::Error> {
    let class = PRELOADED_CLASSES
        .get()
        .expect("Java classes were not preloaded")
        .get(&name);

    let local_ref = class.map(|class| env.new_local_ref(class)).transpose()?;

    Ok(local_ref.map(Into::into))
}

/// Constructs a new object using [`JniArgs`].
///
/// Wraps [`JNIEnv::new_object`]; all arguments are the same.
pub fn new_object<
    'output,
    C: jni::descriptors::Desc<'output, JClass<'output>>,
    const LEN: usize,
>(
    env: &mut JNIEnv<'output>,
    cls: C,
    args: JniArgs<(), LEN>,
) -> jni::errors::Result<JObject<'output>> {
    env.new_object(cls, args.sig, &args.args)
}

/// Constructs a Java object from the given boxed Rust value.
///
/// Assumes there's a corresponding constructor that takes a single `long` to represent the address.
pub fn jobject_from_native_handle<'a>(
    env: &mut JNIEnv<'a>,
    class_name: &str,
    boxed_handle: ObjectHandle,
) -> Result<JObject<'a>, BridgeLayerError> {
    Ok(new_object(
        env,
        class_name,
        jni_args!((boxed_handle => long) -> void),
    )?)
}

/// Constructs a Java SignalProtocolAddress from a ProtocolAddress value.
///
/// A convenience wrapper around `jobject_from_native_handle` for SignalProtocolAddress.
fn protocol_address_to_jobject<'a>(
    env: &mut JNIEnv<'a>,
    address: &ProtocolAddress,
) -> Result<JObject<'a>, BridgeLayerError> {
    let handle = address.clone().convert_into(env)?;
    jobject_from_native_handle(
        env,
        jni_class_name!(org.signal.libsignal.protocol.SignalProtocolAddress),
        handle,
    )
}

/// Verifies that a Java object is a non-`null` instance of the given class.
pub fn check_jobject_type(
    env: &mut JNIEnv,
    obj: &JObject,
    class_name: &'static str,
) -> Result<(), BridgeLayerError> {
    if obj.is_null() {
        return Err(BridgeLayerError::NullPointer(Some(class_name)));
    }

    let class = env.find_class(class_name)?;

    if !env.is_instance_of(obj, class)? {
        return Err(BridgeLayerError::BadJniParameter(class_name));
    }

    Ok(())
}

/// Calls a method, then clones the Rust value from the result.
///
/// The method is assumed to return a type with a `long nativeHandle()` method, which in turn must
/// produce a boxed Rust value.
pub fn get_object_with_native_handle<T: 'static + Clone, const LEN: usize>(
    env: &mut JNIEnv,
    store_obj: &JObject,
    callback_args: JniArgs<JObject<'_>, LEN>,
    callback_fn: &'static str,
) -> Result<Option<T>, SignalJniError> {
    env.with_local_frame(64, |env| -> SignalJniResult<Option<T>> {
        let obj = call_method_checked(
            env,
            store_obj,
            callback_fn,
            callback_args.for_nested_frame(),
        )?;
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
    env: &mut JNIEnv,
    store_obj: &JObject,
    callback_args: JniArgs<JObject<'_>, LEN>,
    callback_fn: &'static str,
) -> Result<Option<Vec<u8>>, SignalJniError> {
    env.with_local_frame(64, |env| -> SignalJniResult<Option<Vec<u8>>> {
        let obj = call_method_checked(
            env,
            store_obj,
            callback_fn,
            callback_args.for_nested_frame(),
        )?;

        if obj.is_null() {
            return Ok(None);
        }

        let bytes: JByteArray =
            call_method_checked(env, obj, "serialize", jni_args!(() -> [byte]))?.into();

        Ok(Some(env.convert_byte_array(bytes)?))
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
            #[export_name = concat!(
                env!("LIBSIGNAL_BRIDGE_FN_PREFIX_JNI"),
                stringify!($jni_name),
                "_1Destroy"
            )]
            #[allow(non_snake_case)]
            pub unsafe extern "C" fn [<__bridge_handle_jni_ $jni_name _destroy>](
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

/// A wrapper around a cloned [`JNIEnv`] that forces scoped use.
///
/// This sidesteps the safety issues with [`JNIEnv::unsafe_clone`] as long as an environment from an
/// outer frame is not used within an inner frame. (Really, this same condition makes `unsafe_clone`
/// safe as well, but using `EnvHandle` is a good reminder since it *only* allows scoped access.)
struct EnvHandle<'a> {
    env: JNIEnv<'a>,
}

impl<'a> EnvHandle<'a> {
    fn new(env: &JNIEnv<'a>) -> Self {
        Self {
            env: unsafe { env.unsafe_clone() },
        }
    }

    /// See [`JNIEnv::with_local_frame`].
    fn with_local_frame<F, T, E>(&mut self, capacity: i32, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut JNIEnv<'_>) -> Result<T, E>,
        E: From<jni::errors::Error>,
    {
        self.env.with_local_frame(capacity, f)
    }
}

/// A helper to convert a primitive value, like `int`, to its boxed types, like `Integer`.
///
/// A value that's already an object will be unchanged. A `void` "value" will be converted to
/// `null`.
fn box_primitive_if_needed<'a>(
    env: &mut JNIEnv<'a>,
    value: JValueOwned<'a>,
) -> jni::errors::Result<JObject<'a>> {
    match value {
        JValueOwned::Object(object) => Ok(object),
        JValueOwned::Byte(v) => new_object(
            env,
            jni_class_name!(java.lang.Byte),
            jni_args!((v => byte) -> void),
        ),
        JValueOwned::Char(v) => new_object(
            env,
            jni_class_name!(java.lang.Character),
            jni_args!((v => char) -> void),
        ),
        JValueOwned::Short(v) => new_object(
            env,
            jni_class_name!(java.lang.Short),
            jni_args!((v => short) -> void),
        ),
        JValueOwned::Int(v) => new_object(
            env,
            jni_class_name!(java.lang.Integer),
            jni_args!((v => int) -> void),
        ),
        JValueOwned::Long(v) => new_object(
            env,
            jni_class_name!(java.lang.Long),
            jni_args!((v => long) -> void),
        ),
        JValueOwned::Bool(v) => new_object(
            env,
            jni_class_name!(java.lang.Boolean),
            jni_args!((v != 0 => boolean) -> void),
        ),
        JValueOwned::Float(v) => new_object(
            env,
            jni_class_name!(java.lang.Float),
            jni_args!((v => float) -> void),
        ),
        JValueOwned::Double(v) => new_object(
            env,
            jni_class_name!(java.lang.Double),
            jni_args!((v => double) -> void),
        ),
        JValueOwned::Void => Ok(JObject::null()),
    }
}
