//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::error::Error;
use std::fmt::Display;
use std::marker::PhantomData;

use attest::enclave::Error as EnclaveError;
use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
pub use jni::objects::{
    AutoElements, JByteArray, JClass, JLongArray, JObject, JObjectArray, JString, ReleaseMode,
};
use jni::objects::{GlobalRef, JThrowable, JValue, JValueOwned};
pub use jni::sys::{jboolean, jint, jlong};
pub use jni::JNIEnv;
use jni::JavaVM;
use libsignal_account_keys::Error as PinError;
use libsignal_net::infra::ws::WebSocketServiceError;
use libsignal_net::keytrans::Error as KeyTransNetError;
use libsignal_net::svr3::Error as Svr3Error;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use usernames::{UsernameError, UsernameLinkError};

use crate::net::cdsi::CdsiError;

#[macro_use]
mod args;
pub use args::*;

mod chat;
pub use chat::*;

mod class_lookup;
pub use class_lookup::*;

#[macro_use]
mod convert;
pub use convert::*;

mod error;
pub use error::*;

mod futures;
pub use futures::*;

mod io;
pub use io::*;
use libsignal_net::chat::ChatServiceError;

mod storage;
pub use storage::*;

/// The type of boxed Rust values, as surfaced in JavaScript.
pub type ObjectHandle = jlong;

// Aliases with a certain spelling that gen_java_decl.py will pick out when generating Native.java.
pub type JavaArrayOfByteArray<'a> = JObjectArray<'a>;
pub type JavaByteBufferArray<'a> = JObjectArray<'a>;
pub type JavaObject<'a> = JObject<'a>;
pub type JavaUUID<'a> = JObject<'a>;
pub type JavaCiphertextMessage<'a> = JObject<'a>;
pub type JavaMap<'a> = JObject<'a>;

/// Return type marker for `bridge_fn`s that return Result, which gen_java_decl.py will pick out
/// when generating Native.java.
pub type Throwing<T> = T;

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

fn convert_to_exception<'a, 'env, F>(env: &'a mut JNIEnv<'env>, error: SignalJniError, consume: F)
where
    F: 'a
        + FnOnce(
            &'a mut JNIEnv<'env>,
            Result<JThrowable<'a>, BridgeLayerError>,
            ConsumableExceptionError,
        ),
{
    // This could be inlined, but then we'd have one copy per unique type for
    // `F`. That's expensive in terms of code size, so we break out the
    // invariant part into a separate function.
    let ConsumableException { throwable, error } = ConsumableException::new(env, error);
    consume(env, throwable, error)
}

struct ConsumableException<'a> {
    throwable: Result<JThrowable<'a>, BridgeLayerError>,
    error: ConsumableExceptionError,
}

#[derive(derive_more::From)]
enum ConsumableExceptionError {
    String(String),
    Static(&'static str),
    JniError(SignalJniError),
}

impl<'env> ConsumableException<'env> {
    fn new(env: &mut JNIEnv<'env>, error: SignalJniError) -> Self {
        fn to_java_string<'env>(
            env: &mut JNIEnv<'env>,
            s: impl Into<jni::strings::JNIString>,
        ) -> Result<JString<'env>, BridgeLayerError> {
            env.new_string(s)
                .check_exceptions(env, "ConsumableException::new")
        }

        let (exception_type, error) = match error {
            SignalJniError::Bridge(BridgeLayerError::CallbackException(callback, exception)) => {
                let throwable = env
                    .new_local_ref(exception.as_obj())
                    .expect_no_exceptions()
                    .map(JThrowable::from);
                return ConsumableException {
                    throwable,
                    error: format!("error in method call '{callback}'").into(),
                };
            }
            SignalJniError::Io(error) if error.kind() == std::io::ErrorKind::Other => {
                let thrown_exception = error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<ThrownException>())
                    .map(ThrownException::as_obj);

                if let Some(exception) = thrown_exception {
                    return ConsumableException {
                        throwable: env
                            .new_local_ref::<&JObject>(exception.as_ref())
                            .expect_no_exceptions()
                            .map(Into::into),
                        error: "error in callback".into(),
                    };
                }
                (ClassName("java.io.IOException"), SignalJniError::Io(error))
            }

            SignalJniError::Protocol(SignalProtocolError::ApplicationCallbackError(
                callback,
                exception,
            )) if <dyn Error>::is::<ThrownException>(&*exception) => {
                // The usual way to write this code would be to match on the result of Error::downcast.
                // However, the "failure" result, which is intended to return the original type back,
                // only supports Send and Sync as additional traits. For anything else, we have to test first.
                let exception =
                    <dyn Error>::downcast::<ThrownException>(exception).expect("just checked");
                return Self::new(
                    env,
                    SignalJniError::Bridge(BridgeLayerError::CallbackException(
                        callback, *exception,
                    )),
                );
            }

            SignalJniError::Protocol(SignalProtocolError::UntrustedIdentity(ref addr)) => {
                let throwable = to_java_string(env, addr.name()).and_then(|addr_name| {
                    new_instance(
                        env,
                        ClassName("org.signal.libsignal.protocol.UntrustedIdentityException"),
                        jni_args!((addr_name => java.lang.String) -> void),
                    )
                });

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            SignalJniError::Protocol(SignalProtocolError::SessionNotFound(ref addr)) => {
                let throwable = protocol_address_to_jobject(env, addr)
                    .and_then(|addr_object| {
                        Ok((addr_object, to_java_string(env, error.to_string())?))
                    })
                    .and_then(|(addr_object, message)| {
                        new_instance(
                            env,
                            ClassName("org.signal.libsignal.protocol.NoSessionException"),
                            jni_args!((
                            addr_object => org.signal.libsignal.protocol.SignalProtocolAddress,
                            message => java.lang.String,
                        ) -> void),
                        )
                    });

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            SignalJniError::Protocol(SignalProtocolError::InvalidRegistrationId(
                ref addr,
                _value,
            )) => {
                let throwable = protocol_address_to_jobject(env, addr)
                    .and_then(|addr_object| {
                        Ok((addr_object, to_java_string(env, error.to_string())?))
                    })
                    .and_then(|(addr_object, message)| {
                        new_instance(
                            env,
                            ClassName(
                                "org.signal.libsignal.protocol.InvalidRegistrationIdException",
                            ),
                            jni_args!((
                            addr_object => org.signal.libsignal.protocol.SignalProtocolAddress,
                            message => java.lang.String,
                        ) -> void),
                        )
                    });

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            SignalJniError::Protocol(SignalProtocolError::InvalidSenderKeySession {
                distribution_id,
            }) => {
                let throwable = distribution_id
                    .convert_into(env)
                    .and_then(|distribution_id_obj| {
                        Ok((distribution_id_obj, to_java_string(env, error.to_string())?))
                    })
                    .and_then(|(distribution_id_obj, message)| {
                        new_instance(
                        env,
                        ClassName(
                            "org.signal.libsignal.protocol.groups.InvalidSenderKeySessionException",
                        ),
                        jni_args!((
                            distribution_id_obj => java.util.UUID,
                            message => java.lang.String,
                        ) -> void),
                    )
                    });

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            SignalJniError::Protocol(SignalProtocolError::FingerprintVersionMismatch(
                theirs,
                ours,
            )) => {
                let throwable = new_instance(
                env,
                ClassName(
                    "org.signal.libsignal.protocol.fingerprint.FingerprintVersionMismatchException",
                ),
                jni_args!((theirs as jint => int, ours as jint => int) -> void),
            );

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            SignalJniError::Protocol(SignalProtocolError::SealedSenderSelfSend) => {
                let throwable = new_instance(
                    env,
                    ClassName("org.signal.libsignal.metadata.SelfSendException"),
                    jni_args!(() -> void),
                );

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            SignalJniError::Cdsi(CdsiError::RateLimited { retry_after }) => {
                let retry_after_seconds = retry_after
                    .as_secs()
                    .try_into()
                    .expect("duration < lifetime of the universe");
                let throwable = retry_later_exception(env, retry_after_seconds);

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            SignalJniError::Bridge(BridgeLayerError::UnexpectedPanic(_))
            | SignalJniError::Bridge(BridgeLayerError::BadJniParameter(_))
            | SignalJniError::Bridge(BridgeLayerError::UnexpectedJniResultType(_, _)) => {
                // java.lang.AssertionError has a slightly different signature.
                let throwable = to_java_string(env, error.to_string()).and_then(|message| {
                    new_instance(
                        env,
                        ClassName("java.lang.AssertionError"),
                        jni_args!((message => java.lang.Object) -> void),
                    )
                });

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            SignalJniError::BackupValidation(ref err) => {
                // TODO replace with try block once that is stabilized.
                let throwable = (|| {
                    let libsignal_message_backup::ReadError {
                        error,
                        found_unknown_fields,
                    } = err;

                    let message = error.to_string().convert_into(env)?;
                    let found_unknown_fields = found_unknown_fields
                        .iter()
                        .map(|field| field.to_string())
                        .collect::<Vec<_>>()
                        .into_boxed_slice()
                        .convert_into(env)?;
                    new_instance(
                        env,
                        ClassName("org.signal.libsignal.messagebackup.ValidationError"),
                        jni_args!((message => java.lang.String, found_unknown_fields => [java.lang.String]) -> void),
                    )
                })();
                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            SignalJniError::Bridge(BridgeLayerError::NullPointer(_)) => {
                (ClassName("java.lang.NullPointerException"), error)
            }

            SignalJniError::Protocol(SignalProtocolError::InvalidState(_, _)) => {
                (ClassName("java.lang.IllegalStateException"), error)
            }

            SignalJniError::Protocol(SignalProtocolError::InvalidArgument(_))
            | SignalJniError::SignalCrypto(SignalCryptoError::UnknownAlgorithm(_, _))
            | SignalJniError::SignalCrypto(SignalCryptoError::InvalidInputSize)
            | SignalJniError::SignalCrypto(SignalCryptoError::InvalidNonceSize)
            | SignalJniError::Bridge(BridgeLayerError::BadArgument(_))
            | SignalJniError::Bridge(BridgeLayerError::IntegerOverflow(_))
            | SignalJniError::Bridge(BridgeLayerError::IncorrectArrayLength { .. })
            | SignalJniError::KeyTransparency(KeyTransNetError::DecodingFailed(_)) => {
                (ClassName("java.lang.IllegalArgumentException"), error)
            }

            SignalJniError::Bridge(BridgeLayerError::Jni(_))
            | SignalJniError::Protocol(SignalProtocolError::ApplicationCallbackError(_, _))
            | SignalJniError::Protocol(SignalProtocolError::FfiBindingError(_))
            | SignalJniError::DeviceTransfer(DeviceTransferError::InternalError(_))
            | SignalJniError::DeviceTransfer(DeviceTransferError::KeyDecodingFailed) => {
                (ClassName("java.lang.RuntimeException"), error)
            }

            SignalJniError::Protocol(SignalProtocolError::DuplicatedMessage(_, _)) => (
                ClassName("org.signal.libsignal.protocol.DuplicateMessageException"),
                error,
            ),

            SignalJniError::Protocol(SignalProtocolError::InvalidPreKeyId)
            | SignalJniError::Protocol(SignalProtocolError::InvalidSignedPreKeyId)
            | SignalJniError::Protocol(SignalProtocolError::InvalidKyberPreKeyId) => (
                ClassName("org.signal.libsignal.protocol.InvalidKeyIdException"),
                error,
            ),

            SignalJniError::Protocol(SignalProtocolError::NoKeyTypeIdentifier)
            | SignalJniError::Protocol(SignalProtocolError::SignatureValidationFailed)
            | SignalJniError::Protocol(SignalProtocolError::BadKeyType(_))
            | SignalJniError::Protocol(SignalProtocolError::BadKeyLength(_, _))
            | SignalJniError::Protocol(SignalProtocolError::InvalidMacKeyLength(_))
            | SignalJniError::Protocol(SignalProtocolError::BadKEMKeyType(_))
            | SignalJniError::Protocol(SignalProtocolError::WrongKEMKeyType(_, _))
            | SignalJniError::Protocol(SignalProtocolError::BadKEMKeyLength(_, _))
            | SignalJniError::SignalCrypto(SignalCryptoError::InvalidKeySize) => (
                ClassName("org.signal.libsignal.protocol.InvalidKeyException"),
                error,
            ),

            SignalJniError::Protocol(SignalProtocolError::NoSenderKeyState { .. }) => (
                ClassName("org.signal.libsignal.protocol.NoSessionException"),
                error,
            ),

            SignalJniError::Protocol(SignalProtocolError::InvalidSessionStructure(_)) => (
                ClassName("org.signal.libsignal.protocol.InvalidSessionException"),
                error,
            ),

            SignalJniError::Protocol(SignalProtocolError::InvalidMessage(..))
            | SignalJniError::Protocol(SignalProtocolError::CiphertextMessageTooShort(_))
            | SignalJniError::Protocol(SignalProtocolError::InvalidProtobufEncoding)
            | SignalJniError::Protocol(SignalProtocolError::InvalidSealedSenderMessage(_))
            | SignalJniError::Protocol(SignalProtocolError::BadKEMCiphertextLength(_, _))
            | SignalJniError::SignalCrypto(SignalCryptoError::InvalidTag) => (
                ClassName("org.signal.libsignal.protocol.InvalidMessageException"),
                error,
            ),

            SignalJniError::Protocol(SignalProtocolError::UnrecognizedCiphertextVersion(_))
            | SignalJniError::Protocol(SignalProtocolError::UnrecognizedMessageVersion(_))
            | SignalJniError::Protocol(SignalProtocolError::UnknownSealedSenderVersion(_)) => (
                ClassName("org.signal.libsignal.protocol.InvalidVersionException"),
                error,
            ),

            SignalJniError::Protocol(SignalProtocolError::LegacyCiphertextVersion(_)) => (
                ClassName("org.signal.libsignal.protocol.LegacyMessageException"),
                error,
            ),

            SignalJniError::Protocol(SignalProtocolError::FingerprintParsingError) => (
                ClassName("org.signal.libsignal.protocol.fingerprint.FingerprintParsingException"),
                error,
            ),

            SignalJniError::HsmEnclave(HsmEnclaveError::HSMHandshakeError(_))
            | SignalJniError::HsmEnclave(HsmEnclaveError::HSMCommunicationError(_)) => (
                ClassName("org.signal.libsignal.hsmenclave.EnclaveCommunicationFailureException"),
                error,
            ),
            SignalJniError::HsmEnclave(HsmEnclaveError::TrustedCodeError) => (
                ClassName("org.signal.libsignal.hsmenclave.TrustedCodeMismatchException"),
                error,
            ),
            SignalJniError::HsmEnclave(HsmEnclaveError::InvalidPublicKeyError)
            | SignalJniError::HsmEnclave(HsmEnclaveError::InvalidCodeHashError) => {
                (ClassName("java.lang.IllegalArgumentException"), error)
            }
            SignalJniError::HsmEnclave(HsmEnclaveError::InvalidBridgeStateError) => {
                (ClassName("java.lang.IllegalStateException"), error)
            }

            SignalJniError::Enclave(EnclaveError::NoiseHandshakeError(_))
            | SignalJniError::Enclave(EnclaveError::NoiseError(_)) => (
                ClassName("org.signal.libsignal.sgxsession.SgxCommunicationFailureException"),
                error,
            ),
            SignalJniError::Enclave(EnclaveError::AttestationError(_)) => (
                ClassName("org.signal.libsignal.attest.AttestationFailedException"),
                error,
            ),
            SignalJniError::Enclave(EnclaveError::AttestationDataError { .. }) => (
                ClassName("org.signal.libsignal.attest.AttestationDataException"),
                error,
            ),
            SignalJniError::Enclave(EnclaveError::InvalidBridgeStateError) => {
                (ClassName("java.lang.IllegalStateException"), error)
            }

            SignalJniError::Pin(PinError::Argon2Error(_))
            | SignalJniError::Pin(PinError::DecodingError(_))
            | SignalJniError::Pin(PinError::MrenclaveLookupError) => {
                (ClassName("java.lang.IllegalArgumentException"), error)
            }

            SignalJniError::ZkGroupDeserializationFailure(_) => (
                ClassName("org.signal.libsignal.zkgroup.InvalidInputException"),
                error,
            ),

            SignalJniError::ZkGroupVerificationFailure(_) => (
                ClassName("org.signal.libsignal.zkgroup.VerificationFailedException"),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::NicknameCannotBeEmpty) => (
                ClassName("org.signal.libsignal.usernames.CannotBeEmptyException"),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::NicknameCannotStartWithDigit) => (
                ClassName("org.signal.libsignal.usernames.CannotStartWithDigitException"),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::MissingSeparator) => (
                ClassName("org.signal.libsignal.usernames.MissingSeparatorException"),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::BadNicknameCharacter) => (
                ClassName("org.signal.libsignal.usernames.BadNicknameCharacterException"),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::NicknameTooShort) => (
                ClassName("org.signal.libsignal.usernames.NicknameTooShortException"),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::NicknameTooLong) => (
                ClassName("org.signal.libsignal.usernames.NicknameTooLongException"),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::DiscriminatorCannotBeEmpty) => (
                ClassName("org.signal.libsignal.usernames.DiscriminatorCannotBeEmptyException"),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::DiscriminatorCannotBeZero) => (
                ClassName("org.signal.libsignal.usernames.DiscriminatorCannotBeZeroException"),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::DiscriminatorCannotBeSingleDigit) => (
                ClassName(
                    "org.signal.libsignal.usernames.DiscriminatorCannotBeSingleDigitException",
                ),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::DiscriminatorCannotHaveLeadingZeros) => (
                ClassName(
                    "org.signal.libsignal.usernames.DiscriminatorCannotHaveLeadingZerosException",
                ),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::BadDiscriminatorCharacter) => (
                ClassName("org.signal.libsignal.usernames.BadDiscriminatorCharacterException"),
                error,
            ),

            SignalJniError::UsernameError(UsernameError::DiscriminatorTooLarge) => (
                ClassName("org.signal.libsignal.usernames.DiscriminatorTooLargeException"),
                error,
            ),

            SignalJniError::UsernameProofError(usernames::ProofVerificationFailure) => (
                ClassName("org.signal.libsignal.usernames.ProofVerificationFailureException"),
                error,
            ),

            SignalJniError::UsernameLinkError(UsernameLinkError::InputDataTooLong) => (
                ClassName("org.signal.libsignal.usernames.UsernameLinkInputDataTooLong"),
                error,
            ),

            SignalJniError::UsernameLinkError(UsernameLinkError::InvalidEntropyDataLength) => (
                ClassName("org.signal.libsignal.usernames.UsernameLinkInvalidEntropyDataLength"),
                error,
            ),

            SignalJniError::UsernameLinkError(_) => (
                ClassName("org.signal.libsignal.usernames.UsernameLinkInvalidLinkData"),
                error,
            ),

            SignalJniError::Io(_) => (ClassName("java.io.IOException"), error),

            #[cfg(feature = "signal-media")]
            SignalJniError::Mp4SanitizeParse(_) | SignalJniError::WebpSanitizeParse(_) => (
                ClassName("org.signal.libsignal.media.ParseException"),
                error,
            ),

            SignalJniError::Cdsi(CdsiError::InvalidToken) => (
                ClassName("org.signal.libsignal.net.CdsiInvalidTokenException"),
                error,
            ),
            SignalJniError::Cdsi(
                CdsiError::InvalidResponse
                | CdsiError::ParseError
                | CdsiError::Protocol
                | CdsiError::NoTokenInResponse
                | CdsiError::Server { reason: _ },
            ) => (
                ClassName("org.signal.libsignal.net.CdsiProtocolException"),
                error,
            ),

            SignalJniError::WebSocket(WebSocketServiceError::Http(_)) => (
                // In practice, all WebSocket HTTP errors come from multi-route connections, so any
                // that make it to the point of bridging are considered to have resulted from a
                // successful *connection* that then gets an error status code, and so we use
                // NetworkProtocolException instead of NetworkException. We may want to revisit
                // assuming that *here*, though.
                ClassName("org.signal.libsignal.net.NetworkProtocolException"),
                error,
            ),

            SignalJniError::WebSocket(_) | SignalJniError::ConnectTimedOut => (
                ClassName("org.signal.libsignal.net.NetworkException"),
                error,
            ),

            SignalJniError::Svr3(Svr3Error::RestoreFailed(tries_remaining)) => {
                let throwable = to_java_string(env, error.to_string()).and_then(|message| {
                    new_instance(
                        env,
                        ClassName("org.signal.libsignal.svr.RestoreFailedException"),
                        // The number of tries will be hard-coded by the client app
                        // to some sensible value well within the int (i32) range.
                        // Malicious server can still send an invalid value. In
                        // this case panic is the best thing we can do.
                        jni_args!((message => java.lang.String, tries_remaining
                            .try_into()
                            .expect("tries_remaining overflows int") => int) -> void),
                    )
                });
                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }
            SignalJniError::Svr3(Svr3Error::DataMissing) => (
                ClassName("org.signal.libsignal.svr.DataMissingException"),
                error,
            ),
            SignalJniError::Svr3(_) => (ClassName("org.signal.libsignal.svr.SvrException"), error),

            SignalJniError::InvalidUri(_) => (ClassName("java.net.MalformedURLException"), error),

            SignalJniError::ChatService(ref chat) => {
                let class = match chat {
                    ChatServiceError::RetryLater {
                        retry_after_seconds,
                    } => {
                        return ConsumableException {
                            throwable: retry_later_exception(env, *retry_after_seconds),
                            error: error.into(),
                        }
                    }
                    ChatServiceError::Disconnected => {
                        ClassName("org.signal.libsignal.net.ChatServiceInactiveException")
                    }
                    ChatServiceError::AppExpired => {
                        ClassName("org.signal.libsignal.net.AppExpiredException")
                    }
                    ChatServiceError::DeviceDeregistered => {
                        ClassName("org.signal.libsignal.net.DeviceDeregisteredException")
                    }
                    ChatServiceError::WebSocket(_)
                    | ChatServiceError::UnexpectedFrameReceived
                    | ChatServiceError::ServerRequestMissingId
                    | ChatServiceError::IncomingDataInvalid
                    | ChatServiceError::RequestHasInvalidHeader
                    | ChatServiceError::RequestSendTimedOut
                    | ChatServiceError::TimeoutEstablishingConnection
                    | ChatServiceError::AllConnectionRoutesFailed
                    | ChatServiceError::InvalidConnectionConfiguration => {
                        ClassName("org.signal.libsignal.net.ChatServiceException")
                    }
                };
                (class, error)
            }

            SignalJniError::KeyTransparency(ref inner) => {
                let class = match inner {
                    KeyTransNetError::DecodingFailed(_) => {
                        unreachable!("should have been handled separately")
                    }
                    KeyTransNetError::ChatServiceError(_)
                    | KeyTransNetError::RequestFailed(_)
                    | KeyTransNetError::VerificationFailed(_)
                    | KeyTransNetError::InvalidResponse(_)
                    | KeyTransNetError::InvalidRequest(_) => {
                        ClassName("org.signal.libsignal.net.KeyTransparencyException")
                    }
                };
                (class, error)
            }

            SignalJniError::TestingError { exception_class } => (exception_class, error),
        };

        let throwable = to_java_string(env, error.to_string()).and_then(|message| {
            new_instance(
                env,
                exception_type,
                jni_args!((message => java.lang.String) -> void),
            )
        });
        ConsumableException {
            throwable: throwable.map(Into::into),
            error: error.into(),
        }
    }
}

fn retry_later_exception<'env>(
    env: &mut JNIEnv<'env>,
    retry_after_seconds: u32,
) -> Result<JThrowable<'env>, BridgeLayerError> {
    new_instance(
        env,
        ClassName("org.signal.libsignal.net.RetryLaterException"),
        jni_args!((retry_after_seconds.into() => long) -> void),
    )
    .map(Into::into)
}

impl Display for ConsumableExceptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsumableExceptionError::String(s) => Display::fmt(s, f),
            ConsumableExceptionError::Static(s) => Display::fmt(s, f),
            ConsumableExceptionError::JniError(j) => Display::fmt(j, f),
        }
    }
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
    let result = result.check_exceptions(env, fn_name)?;
    let type_name = result.type_name();
    result
        .try_into()
        .map_err(|_| BridgeLayerError::UnexpectedJniResultType(fn_name, type_name))
}

/// Constructs a new object using [`JniArgs`].
///
/// Wraps [`JNIEnv::new_object`]; all arguments are the same.
pub fn new_object<'output, 'a, const LEN: usize>(
    env: &mut JNIEnv<'output>,
    cls: impl AsRef<JClass<'a>>,
    args: JniArgs<(), LEN>,
) -> jni::errors::Result<JObject<'output>> {
    env.new_object(cls.as_ref(), args.sig, &args.args)
}

/// Looks up a class by name and constructs a new instance using [`new_object`].
pub fn new_instance<'output, const LEN: usize>(
    env: &mut JNIEnv<'output>,
    class_name: ClassName<'static>,
    args: JniArgs<(), LEN>,
) -> Result<JObject<'output>, BridgeLayerError> {
    let class = find_class(env, class_name)?;
    new_object(env, class, args).check_exceptions(env, class_name.0)
}

/// Constructs a Java object from the given boxed Rust value.
///
/// Assumes there's a corresponding constructor that takes a single `long` to represent the address.
pub fn jobject_from_native_handle<'a>(
    env: &mut JNIEnv<'a>,
    class_name: ClassName<'static>,
    boxed_handle: ObjectHandle,
) -> Result<JObject<'a>, BridgeLayerError> {
    new_instance(env, class_name, jni_args!((boxed_handle => long) -> void))
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
        ClassName("org.signal.libsignal.protocol.SignalProtocolAddress"),
        handle,
    )
}

/// Verifies that a Java object is a non-`null` instance of the given class.
pub fn check_jobject_type(
    env: &mut JNIEnv,
    obj: &JObject,
    class_name: ClassName<'static>,
) -> Result<(), BridgeLayerError> {
    if obj.is_null() {
        return Err(BridgeLayerError::NullPointer(Some(class_name.0)));
    }

    let class = find_class(env, class_name)?;

    if !env.is_instance_of(obj, class).expect_no_exceptions()? {
        return Err(BridgeLayerError::BadJniParameter(class_name.0));
    }

    Ok(())
}

/// Wraps [`JNIEnv::with_local_frame`] to check exceptions thrown by `with_local_frame` itself.
pub fn with_local_frame<T>(
    env: &mut JNIEnv<'_>,
    capacity: i32,
    context: &'static str,
    body: impl FnOnce(&mut JNIEnv<'_>) -> SignalJniResult<T>,
) -> SignalJniResult<T> {
    // JNIEnv::with_local_frame requires that the return error type be From<jni::errors::Error>.
    // We don't want to provide that, so we have to manually save *our* error (or success) into a
    // local instead.
    let mut result = None;
    let result_for_callback = &mut result;
    env.with_local_frame(capacity, move |env| {
        *result_for_callback = Some(body(env));
        Ok(())
    })
    .check_exceptions(env, context)?;
    result.expect("successful exit from with_local_frame")
}

/// Wraps [`JNIEnv::with_local_frame_returning_local`] to check exceptions thrown by
/// `with_local_frame_returning_local` itself.
pub fn with_local_frame_returning_local<'env>(
    env: &mut JNIEnv<'env>,
    capacity: i32,
    context: &'static str,
    body: impl for<'local> FnOnce(&mut JNIEnv<'local>) -> SignalJniResult<JObject<'local>>,
) -> SignalJniResult<JObject<'env>> {
    // JNIEnv::with_local_frame_returning_local requires that the return error type be
    // From<jni::errors::Error>. We don't want to provide that, so we have to manually save *our*
    // error into a local instead.
    let mut maybe_error = None;
    let error_for_callback = &mut maybe_error;
    let result = env
        .with_local_frame_returning_local(capacity, move |env| {
            body(env).or_else(|e| {
                *error_for_callback = Some(e);
                Ok(JObject::null())
            })
        })
        .check_exceptions(env, context)?;
    if let Some(error) = maybe_error {
        return Err(error);
    }
    Ok(result)
}

/// Calls a method, then clones the Rust value from the result.
///
/// The method is assumed to return a type with a `long unsafeHandle` field,
/// which in turn must hold a raw pointer produced from a boxed Rust value.
pub fn get_object_with_native_handle<T: 'static + Clone, const LEN: usize>(
    env: &mut JNIEnv,
    store_obj: &JObject,
    callback_args: JniArgs<JObject<'_>, LEN>,
    callback_fn: &'static str,
) -> Result<Option<T>, SignalJniError> {
    with_local_frame(env, 64, callback_fn, |env| -> SignalJniResult<Option<T>> {
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
            .get_field(obj, "unsafeHandle", jni_signature!(long))
            .check_exceptions(env, callback_fn)?
            .try_into()
            .expect_no_exceptions()?;
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
    with_local_frame(
        env,
        64,
        callback_fn,
        |env| -> SignalJniResult<Option<Vec<u8>>> {
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

            Ok(Some(
                env.convert_byte_array(bytes)
                    .check_exceptions(env, "serialize")?,
            ))
        },
    )
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

/// Used by [`bridge_handle_fns`](crate::support::bridge_handle_fns).
///
/// Not intended to be invoked directly.
#[macro_export]
macro_rules! jni_bridge_handle_destroy {
    ( $typ:ty as $jni_name:ident ) => {
        ::paste::paste! {
            #[export_name = concat!(
                env!("LIBSIGNAL_BRIDGE_FN_PREFIX_JNI"),
                stringify!($jni_name),
                "_1Destroy"
            )]
            #[allow(non_snake_case)]
            pub unsafe extern "C" fn [<__bridge_handle_jni_ $jni_name _destroy>](
                _env: ::jni::JNIEnv,
                _class: ::jni::objects::JClass,
                handle: $crate::jni::ObjectHandle,
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

    /// See [`with_local_frame`].
    fn with_local_frame<T>(
        &mut self,
        capacity: i32,
        context: &'static str,
        body: impl FnOnce(&mut JNIEnv<'_>) -> SignalJniResult<T>,
    ) -> SignalJniResult<T> {
        with_local_frame(&mut self.env, capacity, context, body)
    }
}

/// A helper to convert a primitive value, like `int`, to its boxed types, like `Integer`.
///
/// A value that's already an object will be unchanged. A `void` "value" will be converted to
/// `null`.
fn box_primitive_if_needed<'a>(
    env: &mut JNIEnv<'a>,
    value: JValueOwned<'a>,
) -> Result<JObject<'a>, BridgeLayerError> {
    match value {
        JValueOwned::Object(object) => Ok(object),
        JValueOwned::Byte(v) => new_instance(
            env,
            ClassName("java.lang.Byte"),
            jni_args!((v => byte) -> void),
        ),
        JValueOwned::Char(v) => new_instance(
            env,
            ClassName("java.lang.Character"),
            jni_args!((v => char) -> void),
        ),
        JValueOwned::Short(v) => new_instance(
            env,
            ClassName("java.lang.Short"),
            jni_args!((v => short) -> void),
        ),
        JValueOwned::Int(v) => new_instance(
            env,
            ClassName("java.lang.Integer"),
            jni_args!((v => int) -> void),
        ),
        JValueOwned::Long(v) => new_instance(
            env,
            ClassName("java.lang.Long"),
            jni_args!((v => long) -> void),
        ),
        JValueOwned::Bool(v) => new_instance(
            env,
            ClassName("java.lang.Boolean"),
            jni_args!((v != 0 => boolean) -> void),
        ),
        JValueOwned::Float(v) => new_instance(
            env,
            ClassName("java.lang.Float"),
            jni_args!((v => float) -> void),
        ),
        JValueOwned::Double(v) => new_instance(
            env,
            ClassName("java.lang.Double"),
            jni_args!((v => double) -> void),
        ),
        JValueOwned::Void => Ok(JObject::null()),
    }
}
