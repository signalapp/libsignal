//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::fmt;

use neon::thread::LocalKey;
#[cfg(feature = "signal-media")]
use signal_media::sanitize::mp4::{Error as Mp4Error, ParseError as Mp4ParseError};
#[cfg(feature = "signal-media")]
use signal_media::sanitize::webp::{Error as WebpError, ParseError as WebpParseError};

use super::*;
use crate::support::IllegalArgumentError;

static ERRORS_MODULE: LocalKey<Root<JsObject>> = LocalKey::new();
const ERROR_CLASS_NAME: &str = "LibSignalErrorBase";

#[expect(non_snake_case)]
fn node_registerErrors(mut cx: FunctionContext) -> JsResult<JsValue> {
    let errors_module = cx.argument::<JsObject>(0)?;
    _ = ERRORS_MODULE.get_or_try_init(&mut cx, |cx| {
        Ok::<_, std::convert::Infallible>(errors_module.root(cx))
    });
    Ok(cx.undefined().upcast())
}
node_register!(registerErrors);

fn no_extra_properties<'a>(cx: &mut impl Context<'a>) -> JsResult<'a, JsValue> {
    Ok(cx.undefined().upcast())
}

fn new_js_error<'a, C: Context<'a>>(
    cx: &mut C,
    name: Option<&str>,
    message: &str,
    operation: &str,
    make_extra_props: impl FnOnce(&mut C) -> JsResult<'a, JsValue>,
) -> Handle<'a, JsError> {
    let result = cx.try_catch(|cx| {
        let errors_module: Handle<JsObject> = match ERRORS_MODULE.get(cx) {
            Some(root) => root.to_inner(cx),
            None => cx.throw_error("registerErrors not called")?,
        };
        let error_class: Handle<JsFunction> = errors_module.get(cx, ERROR_CLASS_NAME)?;
        let name_arg = match name {
            Some(name) => cx.string(name).upcast::<JsValue>(),
            None => cx.undefined().upcast(),
        };
        let extra_props_arg = make_extra_props(cx)?;

        let args = (
            cx.string(message),
            name_arg,
            cx.string(operation),
            extra_props_arg,
        );
        error_class.construct_with(cx).args(args).apply(cx)
    });
    result.unwrap_or_else(|failure| {
        let failure_str = failure.to_string(cx).map(|s| s.value(cx)).ok();
        let failure_msg = failure_str.as_deref().unwrap_or("(could not print error)");

        let name = name.unwrap_or("LibSignalError");
        log::warn!("could not construct {name}: {failure_msg}");

        // Make sure we still throw something.
        JsError::error(cx, message).expect("JsError::error only returns Ok")
    })
}

/// [`std::error::Error`] implementer that wraps a thrown value.
#[derive(Debug)]
pub(crate) enum ThrownException {
    Error(Root<JsError>),
    String(String),
}

impl ThrownException {
    pub(crate) fn from_value<'a>(cx: &mut FunctionContext<'a>, error: Handle<'a, JsValue>) -> Self {
        if let Ok(e) = error.downcast::<JsError, _>(cx) {
            ThrownException::Error(e.root(cx))
        } else if let Ok(e) = error.downcast::<JsString, _>(cx) {
            ThrownException::String(e.value(cx))
        } else {
            ThrownException::String(
                error
                    .to_string(cx)
                    .expect("can convert to string")
                    .value(cx),
            )
        }
    }
}

impl Default for ThrownException {
    fn default() -> Self {
        Self::String(String::default())
    }
}

impl From<&str> for ThrownException {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl std::fmt::Display for ThrownException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(r) => write!(f, "{r:?}"),
            Self::String(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for ThrownException {}

pub trait SignalNodeError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError>;
}

/// Provides a simple [`SignalNodeError`] implementation.
///
/// Implementing types get a straightforward blanket implementation of
/// [`SignalNodeError`] that converts to a generic error with
/// [`self.to_string()`](ToString::to_string) as the error message.
pub trait DefaultSignalNodeError: ToString {}

impl<S: DefaultSignalNodeError> SignalNodeError for S {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let message = self.to_string();
        new_js_error(cx, None, &message, operation_name, no_extra_properties)
    }
}

const INVALID_MEDIA_INPUT: &str = "InvalidMediaInput";
const IO_ERROR: &str = "IoError";
const UNSUPPORTED_MEDIA_INPUT: &str = "UnsupportedMediaInput";

impl DefaultSignalNodeError for IllegalArgumentError {}

impl SignalNodeError for SignalProtocolError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let message = self.to_string();
        match self {
            SignalProtocolError::DuplicatedMessage(..) => new_js_error(
                cx,
                Some("DuplicatedMessage"),
                &message,
                operation_name,
                no_extra_properties,
            ),
            SignalProtocolError::SealedSenderSelfSend => new_js_error(
                cx,
                Some("SealedSenderSelfSend"),
                &message,
                operation_name,
                no_extra_properties,
            ),
            SignalProtocolError::UntrustedIdentity(addr) => {
                let make_extra_props = |cx: &mut C| {
                    let props = cx.empty_object();
                    let addr_string = cx.string(addr.name());
                    props.set(cx, "_addr", addr_string)?;
                    Ok(props.upcast())
                };
                new_js_error(
                    cx,
                    Some("UntrustedIdentity"),
                    &message,
                    operation_name,
                    make_extra_props,
                )
            }
            SignalProtocolError::InvalidRegistrationId(addr, _value) => {
                let make_extra_props = |cx: &mut C| {
                    let props = cx.empty_object();
                    let addr = addr.clone().convert_into(cx)?;
                    props.set(cx, "_addr", addr)?;
                    Ok(props.upcast())
                };
                new_js_error(
                    cx,
                    Some("InvalidRegistrationId"),
                    &message,
                    operation_name,
                    make_extra_props,
                )
            }
            SignalProtocolError::InvalidProtocolAddress { name, device_id } => {
                let make_extra_props = |cx: &mut C| {
                    let props = cx.empty_object();
                    let name = cx.string(name);
                    props.set(cx, "name", name)?;
                    let device_id = cx.number(device_id);
                    props.set(cx, "deviceId", device_id)?;
                    Ok(props.upcast())
                };
                new_js_error(
                    cx,
                    Some("InvalidProtocolAddress"),
                    &message,
                    operation_name,
                    make_extra_props,
                )
            }
            SignalProtocolError::InvalidSessionStructure(..) => new_js_error(
                cx,
                Some("InvalidSession"),
                &message,
                operation_name,
                no_extra_properties,
            ),
            SignalProtocolError::InvalidSenderKeySession { distribution_id } => {
                let make_extra_props = |cx: &mut C| {
                    let props = cx.empty_object();
                    let distribution_id_str =
                        cx.string(format!("{:x}", distribution_id.as_hyphenated()));
                    props.set(cx, "distribution_id", distribution_id_str)?;
                    Ok(props.upcast())
                };
                new_js_error(
                    cx,
                    Some("InvalidSenderKeySession"),
                    &message,
                    operation_name,
                    make_extra_props,
                )
            }
            _ => new_js_error(cx, None, &message, operation_name, no_extra_properties),
        }
    }
}

impl DefaultSignalNodeError for libsignal_protocol::FingerprintError {}

impl DefaultSignalNodeError for device_transfer::Error {}

impl DefaultSignalNodeError for attest::hsm_enclave::Error {}

impl DefaultSignalNodeError for attest::enclave::Error {}

impl DefaultSignalNodeError for signal_crypto::Error {}

impl SignalNodeError for libsignal_net::svrb::Error {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let (name, make_props) = match &self {
            Self::Service(_) | Self::AllConnectionAttemptsFailed | Self::Connect(_) => {
                (Some(IO_ERROR), None)
            }
            Self::RateLimited(inner) => return inner.into_throwable(cx, operation_name),
            Self::AttestationError(_) => (Some("SvrAttestationError"), None),
            Self::RestoreFailed(tries_remaining) => (
                Some("SvrRestoreFailed"),
                Some(move |cx: &mut C| {
                    let props = cx.empty_object();
                    let tries_remaining = tries_remaining.convert_into(cx)?;
                    props.set(cx, "triesRemaining", tries_remaining)?;
                    Ok(props.upcast())
                }),
            ),
            Self::DataMissing => (Some("SvrDataMissing"), None),
            Self::Protocol(_) => (Some("IoError"), None),
            Self::PreviousBackupDataInvalid => (Some("SvrInvalidData"), None),
            Self::MetadataInvalid => (Some("SvrInvalidData"), None),
            Self::DecryptionError(_) => (Some("SvrInvalidData"), None),
        };

        let message = self.to_string();
        match make_props {
            Some(f) => new_js_error(cx, name, &message, operation_name, f),
            None => new_js_error(cx, name, &message, operation_name, no_extra_properties),
        }
    }
}

impl DefaultSignalNodeError for zkgroup::ZkGroupVerificationFailure {}

impl DefaultSignalNodeError for zkgroup::ZkGroupDeserializationFailure {}

impl SignalNodeError for usernames::UsernameError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = match &self {
            Self::BadNicknameCharacter => "BadNicknameCharacter",
            Self::NicknameTooShort => "NicknameTooShort",
            Self::NicknameTooLong => "NicknameTooLong",
            Self::NicknameCannotBeEmpty => "NicknameCannotBeEmpty",
            Self::NicknameCannotStartWithDigit => "CannotStartWithDigit",
            Self::MissingSeparator => "MissingSeparator",
            Self::DiscriminatorCannotBeEmpty => "DiscriminatorCannotBeEmpty",
            Self::DiscriminatorCannotBeZero => "DiscriminatorCannotBeZero",
            Self::DiscriminatorCannotBeSingleDigit => "DiscriminatorCannotBeSingleDigit",
            Self::DiscriminatorCannotHaveLeadingZeros => "DiscriminatorCannotHaveLeadingZeros",
            Self::BadDiscriminatorCharacter => "BadDiscriminatorCharacter",
            Self::DiscriminatorTooLarge => "DiscriminatorTooLarge",
        };
        let message = self.to_string();
        new_js_error(
            cx,
            Some(name),
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

impl DefaultSignalNodeError for usernames::ProofVerificationFailure {}

impl SignalNodeError for usernames::UsernameLinkError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = match &self {
            Self::InputDataTooLong => Some("InputDataTooLong"),
            Self::InvalidEntropyDataLength => Some("InvalidEntropyDataLength"),
            Self::UsernameLinkDataTooShort
            | Self::HmacMismatch
            | Self::BadCiphertext
            | Self::InvalidDecryptedDataStructure => Some("InvalidUsernameLinkEncryptedData"),
        };
        let message = self.to_string();
        new_js_error(cx, name, &message, operation_name, no_extra_properties)
    }
}

#[cfg(feature = "signal-media")]
impl SignalNodeError for Mp4Error {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = match &self {
            Mp4Error::Io(_) => IO_ERROR,
            Mp4Error::Parse(err) => match err.kind {
                Mp4ParseError::InvalidBoxLayout
                | Mp4ParseError::InvalidInput
                | Mp4ParseError::MissingRequiredBox(_)
                | Mp4ParseError::TruncatedBox => INVALID_MEDIA_INPUT,
                Mp4ParseError::UnsupportedBox(_)
                | Mp4ParseError::UnsupportedBoxLayout
                | Mp4ParseError::UnsupportedFormat(_) => UNSUPPORTED_MEDIA_INPUT,
            },
        };
        let message = self.to_string();
        new_js_error(
            cx,
            Some(name),
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

#[cfg(feature = "signal-media")]
impl SignalNodeError for WebpError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = match &self {
            WebpError::Io(_) => IO_ERROR,
            WebpError::Parse(err) => match err.kind {
                WebpParseError::InvalidChunkLayout
                | WebpParseError::InvalidInput
                | WebpParseError::InvalidVp8lPrefixCode
                | WebpParseError::MissingRequiredChunk(_)
                | WebpParseError::TruncatedChunk => INVALID_MEDIA_INPUT,
                WebpParseError::UnsupportedChunk(_) | WebpParseError::UnsupportedVp8lVersion(_) => {
                    UNSUPPORTED_MEDIA_INPUT
                }
            },
        };
        let message = self.to_string();
        new_js_error(
            cx,
            Some(name),
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

impl SignalNodeError for std::io::Error {
    fn into_throwable<'a, C: Context<'a>>(
        mut self,
        cx: &mut C,
        _operation_name: &str,
    ) -> Handle<'a, JsError> {
        let exception = (self.kind() == std::io::ErrorKind::Other)
            .then(|| {
                self.get_mut()
                    .and_then(|e| e.downcast_mut::<ThrownException>())
            })
            .flatten()
            .map(std::mem::take);

        let error_string = match exception {
            Some(ThrownException::Error(e)) => return e.into_inner(cx),
            Some(ThrownException::String(s)) => s,
            None => self.to_string(),
        };
        JsError::error(cx, error_string).expect("JsError::error always returns Ok")
    }
}

impl SignalNodeError for libsignal_net::chat::ConnectError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = match self {
            Self::AppExpired => "AppExpired",
            Self::DeviceDeregistered => "DeviceDelinked",
            Self::RetryLater(retry_later) => {
                return retry_later.into_throwable(cx, operation_name);
            }
            Self::WebSocket(_)
            | Self::Timeout
            | Self::AllAttemptsFailed
            | Self::InvalidConnectionConfiguration =>
            // TODO: Distinguish retryable errors from proper failures?
            {
                IO_ERROR
            }
        };
        let message = self.to_string();
        new_js_error(
            cx,
            Some(name),
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

impl SignalNodeError for libsignal_net::chat::SendError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = match self {
            Self::Disconnected => Some("ChatServiceInactive"),
            Self::ConnectionInvalidated => Some("ConnectionInvalidated"),
            Self::ConnectedElsewhere => Some("ConnectedElsewhere"),
            Self::WebSocket(_)
            | Self::IncomingDataInvalid
            | Self::RequestHasInvalidHeader
            | Self::RequestTimedOut =>
            // TODO: Distinguish retryable errors from proper failures?
            {
                Some(IO_ERROR)
            }
        };
        let message = self.to_string();
        new_js_error(cx, name, &message, operation_name, no_extra_properties)
    }
}

impl SignalNodeError for libsignal_net::infra::errors::RetryLater {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let properties = move |cx: &mut C| {
            let props = cx.empty_object();
            let retry_after = self.retry_after_seconds.convert_into(cx)?;
            props.set(cx, "retryAfterSecs", retry_after)?;
            Ok(props.upcast())
        };
        let message = self.to_string();
        new_js_error(
            cx,
            Some("RateLimitedError"),
            &message,
            operation_name,
            properties,
        )
    }
}

impl SignalNodeError for libsignal_net_chat::api::RateLimitChallenge {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let message = self.to_string();
        let Self { token, options } = self;
        let properties = move |cx: &mut C| {
            let token = cx.string(token);
            let options = options.into_boxed_slice().convert_into(cx)?.upcast();
            let set_constructor: Handle<'_, JsFunction> = cx.global("Set")?;
            let options = set_constructor.construct(cx, [options])?;
            let props = cx.empty_object();
            props.set(cx, "token", token)?;
            props.set(cx, "options", options)?;
            Ok(props.upcast())
        };
        new_js_error(
            cx,
            Some("RateLimitChallengeError"),
            &message,
            operation_name,
            properties,
        )
    }
}

impl SignalNodeError for http::uri::InvalidUri {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = Some("InvalidUri");
        let message = self.to_string();
        new_js_error(cx, name, &message, operation_name, no_extra_properties)
    }
}

impl SignalNodeError for libsignal_net::cdsi::LookupError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = match self {
            Self::RateLimited(retry_later) => {
                return retry_later.into_throwable(cx, operation_name);
            }
            Self::AttestationError(e) => return e.into_throwable(cx, operation_name),
            Self::InvalidArgument { server_reason: _ } => None,
            Self::InvalidToken => Some("CdsiInvalidToken"),
            Self::AllConnectionAttemptsFailed
            | Self::ConnectTransport(_)
            | Self::WebSocket(_)
            | Self::CdsiProtocol(_)
            | Self::EnclaveProtocol(_)
            | Self::Server { reason: _ } => Some(IO_ERROR),
        };
        let message = self.to_string();
        new_js_error(cx, name, &message, operation_name, no_extra_properties)
    }
}

impl<E: SignalNodeError> SignalNodeError for libsignal_net_chat::api::RequestError<E> {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let io_error_message: Cow<'static, str> = match self {
            Self::Other(inner) => return inner.into_throwable(cx, operation_name),
            Self::Challenge(challenge) => {
                return challenge.into_throwable(cx, operation_name);
            }
            Self::RetryLater(retry_later) => {
                return retry_later.into_throwable(cx, operation_name);
            }
            Self::Disconnected(disconnected) => {
                return disconnected.into_throwable(cx, operation_name);
            }
            Self::Timeout => {
                return libsignal_net::chat::SendError::RequestTimedOut
                    .into_throwable(cx, operation_name);
            }
            Self::Unexpected { log_safe } => log_safe.into(),
            Self::ServerSideError => "server-side error".into(),
        };
        new_js_error(
            cx,
            Some(IO_ERROR),
            &io_error_message,
            operation_name,
            no_extra_properties,
        )
    }
}

impl SignalNodeError for std::convert::Infallible {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        _cx: &mut C,
        _operation_name: &str,
    ) -> Handle<'a, JsError> {
        match self {}
    }
}

impl SignalNodeError for libsignal_net_chat::api::messages::MultiRecipientSendFailure {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let msg = self.to_string();
        match self {
            Self::Unauthorized => new_js_error(
                cx,
                Some("RequestUnauthorized"),
                &msg,
                operation_name,
                no_extra_properties,
            ),
            Self::MismatchedDevices(mismatched_device_errors) => {
                new_js_error(cx, Some("MismatchedDevices"), &msg, operation_name, |cx| {
                    let errors_module: Handle<JsObject> = match ERRORS_MODULE.get(cx) {
                        Some(root) => root.to_inner(cx),
                        None => cx.throw_error("registerErrors not called")?,
                    };
                    // We want to use the actual class so it can have a real ServiceId object as a
                    // field, which isn't currently accessible to the Rust side of the bridge.
                    let mismatched_device_entry_cls: Handle<JsFunction> =
                        errors_module.get(cx, "MismatchedDevicesEntry")?;
                    let mismatched_device_entry_array = cx.empty_array();
                    for (error, i) in mismatched_device_errors.into_iter().zip(0..) {
                        let js_entry = error.convert_into(cx)?;
                        let js_entry_with_strong_type =
                            mismatched_device_entry_cls.construct(cx, [js_entry.upcast()])?;
                        mismatched_device_entry_array.set(cx, i, js_entry_with_strong_type)?;
                    }

                    let props = JsObject::new(cx);
                    props.set(cx, "entries", mismatched_device_entry_array)?;
                    Ok(props.upcast())
                })
            }
        }
    }
}

mod registration {
    use libsignal_net_chat::api::registration::{
        CheckSvr2CredentialsError, CreateSessionError, RegisterAccountError, RegistrationLock,
        RequestVerificationCodeError, ResumeSessionError, SubmitVerificationError,
        UpdateSessionError, VerificationCodeNotDeliverable,
    };
    use libsignal_net_chat::registration::RequestError;

    use super::*;

    impl<E: Into<BridgedErrorVariant> + std::fmt::Display> SignalNodeError for RequestError<E> {
        fn into_throwable<'a, C: Context<'a>>(
            self,
            cx: &mut C,
            operation_name: &str,
        ) -> Handle<'a, JsError> {
            let inner = match self {
                RequestError::Other(inner) => inner.into(),
                RequestError::Timeout => {
                    return libsignal_net::chat::SendError::RequestTimedOut
                        .into_throwable(cx, operation_name);
                }
                e @ (RequestError::Unexpected { log_safe: _ } | RequestError::ServerSideError) => {
                    return new_js_error(
                        cx,
                        None,
                        &e.to_string(),
                        operation_name,
                        no_extra_properties,
                    );
                }
                RequestError::RetryLater(retry_later) => {
                    return retry_later.into_throwable(cx, operation_name);
                }
                RequestError::Challenge(challenge) => {
                    return challenge.into_throwable(cx, operation_name);
                }
                RequestError::Disconnected(d) => match d {},
            };
            SignalNodeError::into_throwable(inner, cx, operation_name)
        }
    }

    enum BridgedErrorVariant {
        SessionNotFound,
        InvalidSessionId,
        RequestInvalid,
        RequestRejected,
        NotReadyForVerification,
        VerificationSendFailed,
        VerificationNotDeliverable(VerificationCodeNotDeliverable),
        RegistrationLock(RegistrationLock),
        RecoveryVerificationFailed,
        DeviceTransferPossibleNotSkipped,
    }

    impl SignalNodeError for BridgedErrorVariant {
        fn into_throwable<'a, C: Context<'a>>(
            self,
            cx: &mut C,
            operation_name: &str,
        ) -> Handle<'a, JsError> {
            let message = match self {
                BridgedErrorVariant::SessionNotFound => {
                    "no verification session found for the session ID"
                }
                BridgedErrorVariant::InvalidSessionId => "the session ID was invalid",
                BridgedErrorVariant::RequestInvalid => "the request did not pass server validation",
                BridgedErrorVariant::RequestRejected => "the information provided was rejected",
                BridgedErrorVariant::NotReadyForVerification => {
                    "the session is not ready for verification"
                }
                BridgedErrorVariant::VerificationSendFailed => {
                    "sending the verification code failed"
                }
                BridgedErrorVariant::VerificationNotDeliverable(_not_deliverable) => {
                    "the verification code could not be delivered"
                }
                BridgedErrorVariant::RecoveryVerificationFailed => {
                    "the recovery password was not accepted"
                }
                BridgedErrorVariant::DeviceTransferPossibleNotSkipped => {
                    "device transfer is possible but wasn't explicitly skipped"
                }
                BridgedErrorVariant::RegistrationLock(_registration_lock) => {
                    "registration is locked"
                }
            };
            new_js_error(cx, None, message, operation_name, no_extra_properties)
        }
    }

    impl From<CreateSessionError> for BridgedErrorVariant {
        fn from(value: CreateSessionError) -> Self {
            match value {
                CreateSessionError::InvalidSessionId => Self::InvalidSessionId,
            }
        }
    }

    impl From<ResumeSessionError> for BridgedErrorVariant {
        fn from(value: ResumeSessionError) -> Self {
            match value {
                ResumeSessionError::InvalidSessionId => Self::InvalidSessionId,
                ResumeSessionError::SessionNotFound => Self::SessionNotFound,
            }
        }
    }

    impl From<UpdateSessionError> for BridgedErrorVariant {
        fn from(value: UpdateSessionError) -> Self {
            match value {
                UpdateSessionError::Rejected => Self::RequestRejected,
            }
        }
    }

    impl From<RequestVerificationCodeError> for BridgedErrorVariant {
        fn from(value: RequestVerificationCodeError) -> Self {
            match value {
                RequestVerificationCodeError::InvalidSessionId => Self::InvalidSessionId,
                RequestVerificationCodeError::SessionNotFound => Self::SessionNotFound,
                RequestVerificationCodeError::NotReadyForVerification => {
                    Self::NotReadyForVerification
                }
                RequestVerificationCodeError::SendFailed => Self::VerificationSendFailed,
                RequestVerificationCodeError::CodeNotDeliverable(not_deliverable) => {
                    Self::VerificationNotDeliverable(not_deliverable)
                }
            }
        }
    }

    impl From<SubmitVerificationError> for BridgedErrorVariant {
        fn from(value: SubmitVerificationError) -> Self {
            match value {
                SubmitVerificationError::InvalidSessionId => Self::InvalidSessionId,
                SubmitVerificationError::SessionNotFound => Self::SessionNotFound,
                SubmitVerificationError::NotReadyForVerification => Self::NotReadyForVerification,
            }
        }
    }

    impl From<CheckSvr2CredentialsError> for BridgedErrorVariant {
        fn from(value: CheckSvr2CredentialsError) -> Self {
            match value {
                CheckSvr2CredentialsError::CredentialsCouldNotBeParsed => Self::RequestInvalid,
            }
        }
    }

    impl From<RegisterAccountError> for BridgedErrorVariant {
        fn from(value: RegisterAccountError) -> Self {
            match value {
                RegisterAccountError::DeviceTransferIsPossibleButNotSkipped => {
                    Self::DeviceTransferPossibleNotSkipped
                }
                RegisterAccountError::RegistrationRecoveryVerificationFailed => {
                    Self::RecoveryVerificationFailed
                }
                RegisterAccountError::RegistrationLock(registration_lock) => {
                    Self::RegistrationLock(registration_lock)
                }
            }
        }
    }
}

impl SignalNodeError for CancellationError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let message = self.to_string();
        new_js_error(
            cx,
            Some("Cancelled"),
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

impl SignalNodeError for libsignal_message_backup::ReadError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let libsignal_message_backup::ReadError {
            error,
            found_unknown_fields,
        } = self;
        let message = error.to_string();
        let make_props = |cx: &mut C| {
            let props = cx.empty_object();
            let unknown_field_messages = found_unknown_fields.convert_into(cx)?;
            props.set(cx, "unknownFields", unknown_field_messages)?;
            Ok(props.upcast())
        };
        new_js_error(
            cx,
            Some("BackupValidation"),
            &message,
            operation_name,
            make_props,
        )
    }
}

impl SignalNodeError for libsignal_net_chat::api::DisconnectedError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let message = self.to_string();
        let name = match &self {
            Self::ConnectedElsewhere => "ConnectedElsewhere",
            Self::ConnectionInvalidated => "ConnectionInvalidated",
            Self::Transport { .. } => IO_ERROR,
            Self::Closed => "ChatServiceInactive",
        };
        new_js_error(
            cx,
            Some(name),
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

impl SignalNodeError for libsignal_net_chat::api::keytrans::Error {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        use libsignal_keytrans::Error as KtError;

        let message = self.to_string();
        let name = match self {
            libsignal_net_chat::api::keytrans::Error::VerificationFailed(
                KtError::VerificationFailed(_),
            ) => "KeyTransparencyVerificationFailed",
            libsignal_net_chat::api::keytrans::Error::VerificationFailed(_)
            | libsignal_net_chat::api::keytrans::Error::InvalidResponse(_)
            | libsignal_net_chat::api::keytrans::Error::InvalidRequest(_) => "KeyTransparencyError",
        };
        new_js_error(
            cx,
            Some(name),
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

/// Represents an error returned by a callback.
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

/// Converts a JavaScript error message to a [`SignalProtocolError::ApplicationCallbackError`].
pub fn js_error_to_rust(func: &'static str, err: String) -> SignalProtocolError {
    SignalProtocolError::ApplicationCallbackError(func, Box::new(CallbackError::new(err)))
}
