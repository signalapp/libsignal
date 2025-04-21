//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::error::Error;
use std::fmt::{Debug, Display};
use std::io::Error as IoError;
use std::marker::PhantomData;

use attest::enclave::Error as EnclaveError;
use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use http::uri::InvalidUri;
pub use jni::objects::{
    AutoElements, JByteArray, JClass, JLongArray, JObject, JObjectArray, JString, ReleaseMode,
};
use jni::objects::{GlobalRef, JThrowable, JValue, JValueOwned};
pub use jni::sys::{jboolean, jint, jlong};
pub use jni::JNIEnv;
use jni::JavaVM;
use libsignal_account_keys::Error as PinError;
use libsignal_net::chat::{ConnectError as ChatConnectError, SendError as ChatSendError};
use libsignal_net::infra::errors::RetryLater;
use libsignal_net::infra::ws::WebSocketServiceError;
use libsignal_net::keytrans::Error as KeyTransNetError;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

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
pub type JavaSignedPublicPreKey<'a> = JObject<'a>;
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
    F: 'a + FnOnce(&'a mut JNIEnv<'env>, Result<JThrowable<'a>, BridgeLayerError>, SignalJniError),
{
    // This could be inlined, but then we'd have one copy per unique type for
    // `F`. That's expensive in terms of code size, so we break out the
    // invariant part into a separate function.
    let throwable = error.to_throwable(env);
    consume(env, throwable, error)
}

impl JniError for BridgeLayerError {
    fn to_throwable<'a>(&self, env: &mut JNIEnv<'a>) -> Result<JThrowable<'a>, BridgeLayerError> {
        let class_name = match self {
            BridgeLayerError::CallbackException(_callback, exception) => {
                return env
                    .new_local_ref(exception.as_obj())
                    .expect_no_exceptions()
                    .map(JThrowable::from);
            }

            BridgeLayerError::UnexpectedPanic(_)
            | BridgeLayerError::BadJniParameter(_)
            | BridgeLayerError::UnexpectedJniResultType(_, _) => {
                // java.lang.AssertionError has a slightly different signature.
                let message = env
                    .new_string(self.to_string())
                    .check_exceptions(env, "JniError::into_throwable")?;
                return new_instance(
                    env,
                    ClassName("java.lang.AssertionError"),
                    jni_args!((message => java.lang.Object) -> void),
                )
                .map(Into::into);
            }

            BridgeLayerError::NullPointer(_) => ClassName("java.lang.NullPointerException"),
            BridgeLayerError::BadArgument(_)
            | BridgeLayerError::IntegerOverflow(_)
            | BridgeLayerError::IncorrectArrayLength { .. } => {
                ClassName("java.lang.IllegalArgumentException")
            }

            BridgeLayerError::Jni(_) => ClassName("java.lang.RuntimeException"),
        };
        make_single_message_throwable(env, &self.to_string(), class_name)
    }
}

impl JniError for SignalProtocolError {
    fn to_throwable<'a>(&self, env: &mut JNIEnv<'a>) -> Result<JThrowable<'a>, BridgeLayerError> {
        fn to_java_string<'env>(
            env: &mut JNIEnv<'env>,
            s: impl Into<jni::strings::JNIString>,
        ) -> Result<JString<'env>, BridgeLayerError> {
            env.new_string(s)
                .check_exceptions(env, "JniError::into_throwable")
        }

        let class_name = match self {
            SignalProtocolError::ApplicationCallbackError(_callback, exception) => {
                if let Some(exception) = <dyn Error>::downcast_ref::<ThrownException>(&**exception)
                {
                    return env
                        .new_local_ref(exception.as_obj())
                        .expect_no_exceptions()
                        .map(JThrowable::from);
                }

                ClassName("java.lang.RuntimeException")
            }

            SignalProtocolError::UntrustedIdentity(ref addr) => {
                let addr_name = to_java_string(env, addr.name())?;
                return new_instance(
                    env,
                    ClassName("org.signal.libsignal.protocol.UntrustedIdentityException"),
                    jni_args!((addr_name => java.lang.String) -> void),
                )
                .map(Into::into);
            }
            SignalProtocolError::SessionNotFound(ref addr) => {
                let addr_object = protocol_address_to_jobject(env, addr)?;
                let message = to_java_string(env, self.to_string())?;
                return new_instance(
                    env,
                    ClassName("org.signal.libsignal.protocol.NoSessionException"),
                    jni_args!((
                        addr_object => org.signal.libsignal.protocol.SignalProtocolAddress,
                        message => java.lang.String,
                    ) -> void),
                )
                .map(Into::into);
            }

            SignalProtocolError::InvalidRegistrationId(ref addr, _value) => {
                let addr_object = protocol_address_to_jobject(env, addr)?;
                let message = to_java_string(env, self.to_string())?;
                return new_instance(
                    env,
                    ClassName("org.signal.libsignal.protocol.InvalidRegistrationIdException"),
                    jni_args!((
                        addr_object => org.signal.libsignal.protocol.SignalProtocolAddress,
                        message => java.lang.String,
                    ) -> void),
                )
                .map(Into::into);
            }

            SignalProtocolError::InvalidSenderKeySession { distribution_id } => {
                let distribution_id = distribution_id.convert_into(env)?;
                let message = to_java_string(env, self.to_string())?;
                return new_instance(
                    env,
                    ClassName(
                        "org.signal.libsignal.protocol.groups.InvalidSenderKeySessionException",
                    ),
                    jni_args!((
                        distribution_id => java.util.UUID,
                        message => java.lang.String,
                    ) -> void),
                )
                .map(Into::into);
            }

            SignalProtocolError::FingerprintVersionMismatch(theirs, ours) => return new_instance(
                env,
                ClassName(
                    "org.signal.libsignal.protocol.fingerprint.FingerprintVersionMismatchException",
                ),
                jni_args!((*theirs as jint => int, *ours as jint => int) -> void),
            )
            .map(Into::into),
            SignalProtocolError::SealedSenderSelfSend => {
                return new_instance(
                    env,
                    ClassName("org.signal.libsignal.metadata.SelfSendException"),
                    jni_args!(() -> void),
                )
                .map(Into::into);
            }

            SignalProtocolError::InvalidState(_, _) => ClassName("java.lang.IllegalStateException"),

            SignalProtocolError::InvalidArgument(_) => {
                ClassName("java.lang.IllegalArgumentException")
            }
            SignalProtocolError::FfiBindingError(_) => ClassName("java.lang.RuntimeException"),

            SignalProtocolError::DuplicatedMessage(_, _) => {
                ClassName("org.signal.libsignal.protocol.DuplicateMessageException")
            }

            SignalProtocolError::InvalidPreKeyId
            | SignalProtocolError::InvalidSignedPreKeyId
            | SignalProtocolError::InvalidKyberPreKeyId => {
                ClassName("org.signal.libsignal.protocol.InvalidKeyIdException")
            }

            SignalProtocolError::NoKeyTypeIdentifier
            | SignalProtocolError::SignatureValidationFailed
            | SignalProtocolError::BadKeyType(_)
            | SignalProtocolError::BadKeyLength(_, _)
            | SignalProtocolError::InvalidMacKeyLength(_)
            | SignalProtocolError::BadKEMKeyType(_)
            | SignalProtocolError::WrongKEMKeyType(_, _)
            | SignalProtocolError::BadKEMKeyLength(_, _) => {
                ClassName("org.signal.libsignal.protocol.InvalidKeyException")
            }

            SignalProtocolError::NoSenderKeyState { .. } => {
                ClassName("org.signal.libsignal.protocol.NoSessionException")
            }

            SignalProtocolError::InvalidSessionStructure(_) => {
                ClassName("org.signal.libsignal.protocol.InvalidSessionException")
            }

            SignalProtocolError::InvalidMessage(..)
            | SignalProtocolError::CiphertextMessageTooShort(_)
            | SignalProtocolError::InvalidProtobufEncoding
            | SignalProtocolError::InvalidSealedSenderMessage(_)
            | SignalProtocolError::BadKEMCiphertextLength(_, _) => {
                ClassName("org.signal.libsignal.protocol.InvalidMessageException")
            }
            SignalProtocolError::UnrecognizedCiphertextVersion(_)
            | SignalProtocolError::UnrecognizedMessageVersion(_)
            | SignalProtocolError::UnknownSealedSenderVersion(_) => {
                ClassName("org.signal.libsignal.protocol.InvalidVersionException")
            }

            SignalProtocolError::LegacyCiphertextVersion(_) => {
                ClassName("org.signal.libsignal.protocol.LegacyMessageException")
            }

            SignalProtocolError::FingerprintParsingError => {
                ClassName("org.signal.libsignal.protocol.fingerprint.FingerprintParsingException")
            }
        };

        make_single_message_throwable(env, &self.to_string(), class_name)
    }
}

impl MessageOnlyExceptionJniError for ConnectTimedOut {
    fn exception_class(&self) -> ClassName<'static> {
        ClassName("org.signal.libsignal.net.NetworkException")
    }
}

fn make_single_message_throwable<'a>(
    env: &mut JNIEnv<'a>,
    message: &str,
    class: ClassName<'static>,
) -> Result<JThrowable<'a>, BridgeLayerError> {
    let message = env
        .new_string(message)
        .check_exceptions(env, "JniError::into_throwable")?;
    new_instance(env, class, jni_args!((message => java.lang.String) -> void)).map(Into::into)
}

impl JniError for IoError {
    fn to_throwable<'a>(&self, env: &mut JNIEnv<'a>) -> Result<JThrowable<'a>, BridgeLayerError> {
        if self.kind() == std::io::ErrorKind::Other {
            let thrown_exception = self
                .get_ref()
                .and_then(|e| e.downcast_ref::<ThrownException>())
                .map(ThrownException::as_obj);

            if let Some(exception) = thrown_exception {
                return env
                    .new_local_ref::<&JObject>(exception.as_ref())
                    .expect_no_exceptions()
                    .map(Into::into);
            }
        }

        make_single_message_throwable(env, &self.to_string(), ClassName("java.io.IOException"))
    }
}

impl JniError for libsignal_message_backup::ReadError {
    fn to_throwable<'a>(&self, env: &mut JNIEnv<'a>) -> Result<JThrowable<'a>, BridgeLayerError> {
        let Self {
            error,
            found_unknown_fields,
        } = self;

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
        ).map(Into::into)
    }
}

impl MessageOnlyExceptionJniError for SignalCryptoError {
    fn exception_class(&self) -> ClassName<'static> {
        match self {
            SignalCryptoError::UnknownAlgorithm(_, _)
            | SignalCryptoError::InvalidInputSize
            | SignalCryptoError::InvalidNonceSize => {
                ClassName("java.lang.IllegalArgumentException")
            }
            SignalCryptoError::InvalidKeySize => {
                ClassName("org.signal.libsignal.protocol.InvalidKeyException")
            }
            SignalCryptoError::InvalidTag => {
                ClassName("org.signal.libsignal.protocol.InvalidMessageException")
            }
        }
    }
}

impl MessageOnlyExceptionJniError for DeviceTransferError {
    fn exception_class(&self) -> ClassName<'static> {
        match self {
            DeviceTransferError::InternalError(_) | DeviceTransferError::KeyDecodingFailed => {
                ClassName("java.lang.RuntimeException")
            }
        }
    }
}

impl MessageOnlyExceptionJniError for HsmEnclaveError {
    fn exception_class(&self) -> ClassName<'static> {
        match self {
            HsmEnclaveError::HSMHandshakeError(_) | HsmEnclaveError::HSMCommunicationError(_) => {
                ClassName("org.signal.libsignal.hsmenclave.EnclaveCommunicationFailureException")
            }
            HsmEnclaveError::TrustedCodeError => {
                ClassName("org.signal.libsignal.hsmenclave.TrustedCodeMismatchException")
            }
            HsmEnclaveError::InvalidPublicKeyError | HsmEnclaveError::InvalidCodeHashError => {
                ClassName("java.lang.IllegalArgumentException")
            }
            HsmEnclaveError::InvalidBridgeStateError => {
                ClassName("java.lang.IllegalStateException")
            }
        }
    }
}

impl MessageOnlyExceptionJniError for EnclaveError {
    fn exception_class(&self) -> ClassName<'static> {
        match self {
            EnclaveError::NoiseHandshakeError(_) | EnclaveError::NoiseError(_) => {
                ClassName("org.signal.libsignal.sgxsession.SgxCommunicationFailureException")
            }
            EnclaveError::AttestationError(_) => {
                ClassName("org.signal.libsignal.attest.AttestationFailedException")
            }
            EnclaveError::AttestationDataError { .. } => {
                ClassName("org.signal.libsignal.attest.AttestationDataException")
            }
            EnclaveError::InvalidBridgeStateError => ClassName("java.lang.IllegalStateException"),
        }
    }
}

impl MessageOnlyExceptionJniError for PinError {
    fn exception_class(&self) -> ClassName<'static> {
        match self {
            PinError::Argon2Error(_)
            | PinError::DecodingError(_)
            | PinError::MrenclaveLookupError => ClassName("java.lang.IllegalArgumentException"),
        }
    }
}

impl MessageOnlyExceptionJniError for ZkGroupDeserializationFailure {
    fn exception_class(&self) -> ClassName<'static> {
        ClassName("org.signal.libsignal.zkgroup.InvalidInputException")
    }
}

impl MessageOnlyExceptionJniError for ZkGroupVerificationFailure {
    fn exception_class(&self) -> ClassName<'static> {
        ClassName("org.signal.libsignal.zkgroup.VerificationFailedException")
    }
}

impl MessageOnlyExceptionJniError for UsernameError {
    fn exception_class(&self) -> ClassName<'static> {
        match self {
            UsernameError::NicknameCannotBeEmpty => {
                ClassName("org.signal.libsignal.usernames.CannotBeEmptyException")
            }
            UsernameError::NicknameCannotStartWithDigit => {
                ClassName("org.signal.libsignal.usernames.CannotStartWithDigitException")
            }
            UsernameError::MissingSeparator => {
                ClassName("org.signal.libsignal.usernames.MissingSeparatorException")
            }
            UsernameError::BadNicknameCharacter => {
                ClassName("org.signal.libsignal.usernames.BadNicknameCharacterException")
            }
            UsernameError::NicknameTooShort => {
                ClassName("org.signal.libsignal.usernames.NicknameTooShortException")
            }
            UsernameError::NicknameTooLong => {
                ClassName("org.signal.libsignal.usernames.NicknameTooLongException")
            }
            UsernameError::DiscriminatorCannotBeEmpty => {
                ClassName("org.signal.libsignal.usernames.DiscriminatorCannotBeEmptyException")
            }
            UsernameError::DiscriminatorCannotBeZero => {
                ClassName("org.signal.libsignal.usernames.DiscriminatorCannotBeZeroException")
            }
            UsernameError::DiscriminatorCannotBeSingleDigit => ClassName(
                "org.signal.libsignal.usernames.DiscriminatorCannotBeSingleDigitException",
            ),
            UsernameError::DiscriminatorCannotHaveLeadingZeros => ClassName(
                "org.signal.libsignal.usernames.DiscriminatorCannotHaveLeadingZerosException",
            ),
            UsernameError::BadDiscriminatorCharacter => {
                ClassName("org.signal.libsignal.usernames.BadDiscriminatorCharacterException")
            }
            UsernameError::DiscriminatorTooLarge => {
                ClassName("org.signal.libsignal.usernames.DiscriminatorTooLargeException")
            }
        }
    }
}

impl MessageOnlyExceptionJniError for usernames::ProofVerificationFailure {
    fn exception_class(&self) -> ClassName<'static> {
        ClassName("org.signal.libsignal.usernames.ProofVerificationFailureException")
    }
}

impl MessageOnlyExceptionJniError for UsernameLinkError {
    fn exception_class(&self) -> ClassName<'static> {
        match self {
            UsernameLinkError::InputDataTooLong => {
                ClassName("org.signal.libsignal.usernames.UsernameLinkInputDataTooLong")
            }
            UsernameLinkError::InvalidEntropyDataLength => {
                ClassName("org.signal.libsignal.usernames.UsernameLinkInvalidEntropyDataLength")
            }
            _ => ClassName("org.signal.libsignal.usernames.UsernameLinkInvalidLinkData"),
        }
    }
}

#[cfg(feature = "signal-media")]
impl MessageOnlyExceptionJniError for signal_media::sanitize::mp4::ParseErrorReport {
    fn exception_class(&self) -> ClassName<'static> {
        ClassName("org.signal.libsignal.media.ParseException")
    }
}

#[cfg(feature = "signal-media")]
impl MessageOnlyExceptionJniError for signal_media::sanitize::webp::ParseErrorReport {
    fn exception_class(&self) -> ClassName<'static> {
        ClassName("org.signal.libsignal.media.ParseException")
    }
}

mod registration {
    use libsignal_core::try_scoped;
    use libsignal_net::registration::{
        CreateSessionError, InvalidSessionId, RequestError, RequestVerificationCodeError,
        ResumeSessionError, SubmitVerificationError, UpdateSessionError,
        VerificationCodeNotDeliverable,
    };

    use super::*;

    impl<E: JniError> JniError for RequestError<E> {
        fn to_throwable<'a>(
            &self,
            env: &mut JNIEnv<'a>,
        ) -> Result<JThrowable<'a>, BridgeLayerError> {
            let message = match self {
                RequestError::RequestWasNotValid => "the request did not pass server validation",

                RequestError::Other(inner) => return inner.to_throwable(env),
                RequestError::Timeout => {
                    return libsignal_net::chat::SendError::RequestTimedOut.to_throwable(env)
                }
                RequestError::Unknown(message) => message,
            };
            make_single_message_throwable(
                env,
                message,
                ClassName("org.signal.libsignal.net.RegistrationException"),
            )
        }
    }

    impl MessageOnlyExceptionJniError for InvalidSessionId {
        fn exception_class(&self) -> ClassName<'static> {
            ClassName("org.signal.libsignal.net.RegistrationSessionIdInvalidException")
        }
    }

    fn session_not_found<'a>(
        env: &mut JNIEnv<'a>,
        message: &str,
    ) -> Result<JThrowable<'a>, BridgeLayerError> {
        make_single_message_throwable(
            env,
            message,
            ClassName("org.signal.libsignal.net.RegistrationSessionNotFoundException"),
        )
    }
    fn not_ready_for_verification<'a>(
        env: &mut JNIEnv<'a>,
        message: &str,
    ) -> Result<JThrowable<'a>, BridgeLayerError> {
        make_single_message_throwable(
            env,
            message,
            ClassName("org.signal.libsignal.net.RegistrationSessionNotReadyException"),
        )
    }

    impl JniError for CreateSessionError {
        fn to_throwable<'a>(
            &self,
            env: &mut JNIEnv<'a>,
        ) -> Result<JThrowable<'a>, BridgeLayerError> {
            match self {
                CreateSessionError::InvalidSessionId => InvalidSessionId.to_throwable(env),
                CreateSessionError::RetryLater(retry_later) => retry_later.to_throwable(env),
            }
        }
    }

    impl JniError for ResumeSessionError {
        fn to_throwable<'a>(
            &self,
            env: &mut JNIEnv<'a>,
        ) -> Result<JThrowable<'a>, BridgeLayerError> {
            match self {
                ResumeSessionError::InvalidSessionId => InvalidSessionId.to_throwable(env),
                ResumeSessionError::SessionNotFound => session_not_found(env, &self.to_string()),
            }
        }
    }

    impl JniError for UpdateSessionError {
        fn to_throwable<'a>(
            &self,
            env: &mut JNIEnv<'a>,
        ) -> Result<JThrowable<'a>, BridgeLayerError> {
            match self {
                UpdateSessionError::RetryLater(retry_later) => retry_later.to_throwable(env),
                UpdateSessionError::Rejected => make_single_message_throwable(
                    env,
                    &self.to_string(),
                    ClassName("org.signal.libsignal.net.RegistrationException"),
                ),
            }
        }
    }

    impl JniError for RequestVerificationCodeError {
        fn to_throwable<'a>(
            &self,
            env: &mut JNIEnv<'a>,
        ) -> Result<JThrowable<'a>, BridgeLayerError> {
            match self {
                RequestVerificationCodeError::InvalidSessionId => {
                    InvalidSessionId.to_throwable(env)
                }
                RequestVerificationCodeError::SessionNotFound => {
                    session_not_found(env, &self.to_string())
                }
                RequestVerificationCodeError::NotReadyForVerification => {
                    not_ready_for_verification(env, &self.to_string())
                }
                RequestVerificationCodeError::SendFailed => make_single_message_throwable(
                    env,
                    &self.to_string(),
                    ClassName("org.signal.libsignal.net.RegistrationSessionSendCodeException"),
                ),
                RequestVerificationCodeError::CodeNotDeliverable(
                    VerificationCodeNotDeliverable {
                        reason,
                        permanent_failure,
                    },
                ) => {
                    let (message, reason) = try_scoped(|| {
                        Ok((env.new_string(self.to_string())?, env.new_string(reason)?))
                    })
                    .check_exceptions(env, "RequestVerificationCodeError::to_throwable")?;
                    let args = jni_args!((message => java.lang.String, reason => java.lang.String, *permanent_failure => boolean) -> void);
                    new_instance(
                        env,
                        ClassName(
                            "org.signal.libsignal.net.RegistrationCodeNotDeliverableException",
                        ),
                        args,
                    )
                    .map(Into::into)
                }
                RequestVerificationCodeError::RetryLater(retry_later) => {
                    retry_later.to_throwable(env)
                }
            }
        }
    }

    impl JniError for SubmitVerificationError {
        fn to_throwable<'a>(
            &self,
            env: &mut JNIEnv<'a>,
        ) -> Result<JThrowable<'a>, BridgeLayerError> {
            match self {
                SubmitVerificationError::InvalidSessionId => InvalidSessionId.to_throwable(env),
                SubmitVerificationError::SessionNotFound => {
                    session_not_found(env, &self.to_string())
                }
                SubmitVerificationError::NotReadyForVerification => {
                    not_ready_for_verification(env, &self.to_string())
                }
                SubmitVerificationError::RetryLater(retry_later) => retry_later.to_throwable(env),
            }
        }
    }
}

impl JniError for CdsiError {
    fn to_throwable<'a>(&self, env: &mut JNIEnv<'a>) -> Result<JThrowable<'a>, BridgeLayerError> {
        let class = match *self {
            CdsiError::RateLimited(retry_later) => {
                return retry_later.to_throwable(env);
            }
            CdsiError::InvalidToken => {
                ClassName("org.signal.libsignal.net.CdsiInvalidTokenException")
            }
            CdsiError::InvalidResponse
            | CdsiError::ParseError
            | CdsiError::Protocol
            | CdsiError::NoTokenInResponse
            | CdsiError::Server { reason: _ } => {
                ClassName("org.signal.libsignal.net.CdsiProtocolException")
            }
        };
        make_single_message_throwable(env, &self.to_string(), class)
    }
}

impl MessageOnlyExceptionJniError for WebSocketServiceError {
    fn exception_class(&self) -> ClassName<'static> {
        match self {
            WebSocketServiceError::Http(_) => {
                // In practice, all WebSocket HTTP errors come from multi-route connections, so any
                // that make it to the point of bridging are considered to have resulted from a
                // successful *connection* that then gets an error status code, and so we use
                // NetworkProtocolException instead of NetworkException. We may want to revisit
                // assuming that *here*, though.
                ClassName("org.signal.libsignal.net.NetworkProtocolException")
            }

            _ => ClassName("org.signal.libsignal.net.NetworkException"),
        }
    }
}

impl MessageOnlyExceptionJniError for InvalidUri {
    fn exception_class(&self) -> ClassName<'static> {
        ClassName("java.net.MalformedURLException")
    }
}

impl JniError for ChatConnectError {
    fn to_throwable<'a>(&self, env: &mut JNIEnv<'a>) -> Result<JThrowable<'a>, BridgeLayerError> {
        let class = match *self {
            ChatConnectError::RetryLater(retry_later) => return retry_later.to_throwable(env),
            ChatConnectError::AppExpired => {
                ClassName("org.signal.libsignal.net.AppExpiredException")
            }
            ChatConnectError::DeviceDeregistered => {
                ClassName("org.signal.libsignal.net.DeviceDeregisteredException")
            }
            ChatConnectError::WebSocket(_)
            | ChatConnectError::Timeout
            | ChatConnectError::AllAttemptsFailed
            | ChatConnectError::InvalidConnectionConfiguration => {
                ClassName("org.signal.libsignal.net.ChatServiceException")
            }
        };
        make_single_message_throwable(env, &self.to_string(), class)
    }
}

impl MessageOnlyExceptionJniError for ChatSendError {
    fn exception_class(&self) -> ClassName<'static> {
        match self {
            ChatSendError::Disconnected => {
                ClassName("org.signal.libsignal.net.ChatServiceInactiveException")
            }
            ChatSendError::ConnectionInvalidated => {
                ClassName("org.signal.libsignal.net.ConnectionInvalidatedException")
            }
            ChatSendError::ConnectedElsewhere => {
                ClassName("org.signal.libsignal.net.ConnectedElsewhereException")
            }
            ChatSendError::WebSocket(_)
            | ChatSendError::IncomingDataInvalid
            | ChatSendError::RequestHasInvalidHeader
            | ChatSendError::RequestTimedOut => {
                ClassName("org.signal.libsignal.net.ChatServiceException")
            }
        }
    }
}

impl MessageOnlyExceptionJniError for KeyTransNetError {
    fn exception_class(&self) -> ClassName<'static> {
        match &self {
            KeyTransNetError::ChatSendError(send_error) => send_error.exception_class(),
            KeyTransNetError::RequestFailed(_)
            | KeyTransNetError::VerificationFailed(_)
            | KeyTransNetError::InvalidResponse(_)
            | KeyTransNetError::InvalidRequest(_)
            | KeyTransNetError::DecodingFailed(_) => {
                ClassName("org.signal.libsignal.net.KeyTransparencyException")
            }
        }
    }
}

impl MessageOnlyExceptionJniError for TestingError {
    fn exception_class(&self) -> ClassName<'static> {
        self.exception_class
    }
}

impl JniError for RetryLater {
    fn to_throwable<'a>(&self, env: &mut JNIEnv<'a>) -> Result<JThrowable<'a>, BridgeLayerError> {
        let Self {
            retry_after_seconds,
        } = self;
        new_instance(
            env,
            ClassName("org.signal.libsignal.net.RetryLaterException"),
            jni_args!(((*retry_after_seconds).into() => long) -> void),
        )
        .map(Into::into)
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

/// Casts the given handle as a `&T`.
///
/// # Safety
///
/// The caller must ensure that the provided handle is in fact the Java
/// representation of a pointer to a value of type `T`, and that the pointer
/// remains valid as long as the returned reference is around.
pub unsafe fn native_handle_cast<'l, T>(
    handle: ObjectHandle,
) -> Result<&'l mut T, BridgeLayerError> {
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
pub fn with_local_frame<T, E: From<BridgeLayerError>>(
    env: &mut JNIEnv<'_>,
    capacity: i32,
    context: &'static str,
    body: impl FnOnce(&mut JNIEnv<'_>) -> Result<T, E>,
) -> Result<T, E> {
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

/// Calls a Java method, then clones the Rust value from the result.
///
/// The Java method is assumed to return a type that implements the
/// `NativeHandleGuard.Owner` interface.
pub fn get_object_with_native_handle<T: 'static + Clone, const LEN: usize>(
    env: &mut JNIEnv,
    store_obj: &JObject,
    callback_args: JniArgs<JObject<'_>, LEN>,
    callback_fn: &'static str,
) -> Result<Option<T>, BridgeLayerError> {
    with_local_frame(env, 64, callback_fn, |env| {
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
            .call_method(
                obj,
                "unsafeNativeHandleWithoutGuard",
                jni_signature!(() -> long),
                &[],
            )
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
) -> Result<Option<Vec<u8>>, BridgeLayerError> {
    with_local_frame(env, 64, callback_fn, |env| {
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
    fn with_local_frame<T, E: From<BridgeLayerError>>(
        &mut self,
        capacity: i32,
        context: &'static str,
        body: impl FnOnce(&mut JNIEnv<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
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
