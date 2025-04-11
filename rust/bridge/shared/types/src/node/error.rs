//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

#[cfg(feature = "signal-media")]
use signal_media::sanitize::mp4::{Error as Mp4Error, ParseError as Mp4ParseError};
#[cfg(feature = "signal-media")]
use signal_media::sanitize::webp::{Error as WebpError, ParseError as WebpParseError};

use super::*;

const ERRORS_PROPERTY_NAME: &str = "Errors";
const ERROR_CLASS_NAME: &str = "LibSignalErrorBase";

#[allow(non_snake_case)]
fn node_registerErrors(mut cx: FunctionContext) -> JsResult<JsValue> {
    let errors_module = cx.argument::<JsObject>(0)?;
    cx.this::<JsObject>()?
        .set(&mut cx, ERRORS_PROPERTY_NAME, errors_module)?;
    Ok(cx.undefined().upcast())
}
node_register!(registerErrors);

fn no_extra_properties<'a>(cx: &mut impl Context<'a>) -> JsResult<'a, JsValue> {
    Ok(cx.undefined().upcast())
}

fn new_js_error<'a, C: Context<'a>>(
    cx: &mut C,
    module: Handle<'a, JsObject>,
    name: Option<&str>,
    message: &str,
    operation: &str,
    make_extra_props: impl FnOnce(&mut C) -> JsResult<'a, JsValue>,
) -> Handle<'a, JsError> {
    let result = cx.try_catch(|cx| {
        let errors_module: Handle<JsObject> = module.get(cx, ERRORS_PROPERTY_NAME)?;
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
            Self::Error(r) => write!(f, "{:?}", r),
            Self::String(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for ThrownException {}

pub trait SignalNodeError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        module: Handle<'a, JsObject>,
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
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let message = self.to_string();
        new_js_error(
            cx,
            module,
            None,
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

const INVALID_MEDIA_INPUT: &str = "InvalidMediaInput";
const IO_ERROR: &str = "IoError";
const UNSUPPORTED_MEDIA_INPUT: &str = "UnsupportedMediaInput";

impl SignalNodeError for SignalProtocolError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let message = self.to_string();
        match self {
            SignalProtocolError::DuplicatedMessage(..) => new_js_error(
                cx,
                module,
                Some("DuplicatedMessage"),
                &message,
                operation_name,
                no_extra_properties,
            ),
            SignalProtocolError::SealedSenderSelfSend => new_js_error(
                cx,
                module,
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
                    module,
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
                    module,
                    Some("InvalidRegistrationId"),
                    &message,
                    operation_name,
                    make_extra_props,
                )
            }
            SignalProtocolError::InvalidSessionStructure(..) => new_js_error(
                cx,
                module,
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
                    module,
                    Some("InvalidSenderKeySession"),
                    &message,
                    operation_name,
                    make_extra_props,
                )
            }
            _ => new_js_error(
                cx,
                module,
                None,
                &message,
                operation_name,
                no_extra_properties,
            ),
        }
    }
}

impl DefaultSignalNodeError for device_transfer::Error {}

impl DefaultSignalNodeError for attest::hsm_enclave::Error {}

impl DefaultSignalNodeError for attest::enclave::Error {}

impl DefaultSignalNodeError for signal_crypto::Error {}

impl DefaultSignalNodeError for zkgroup::ZkGroupVerificationFailure {}

impl DefaultSignalNodeError for zkgroup::ZkGroupDeserializationFailure {}

impl SignalNodeError for usernames::UsernameError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        module: Handle<'a, JsObject>,
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
            module,
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
        module: Handle<'a, JsObject>,
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
        new_js_error(
            cx,
            module,
            name,
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

#[cfg(feature = "signal-media")]
impl SignalNodeError for Mp4Error {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        module: Handle<'a, JsObject>,
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
            module,
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
        module: Handle<'a, JsObject>,
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
            module,
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
        _module: Handle<'a, JsObject>,
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
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = match self {
            Self::AppExpired => "AppExpired",
            Self::DeviceDeregistered => "DeviceDelinked",
            Self::RetryLater(retry_later) => {
                return retry_later.into_throwable(cx, module, operation_name)
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
            module,
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
        module: Handle<'a, JsObject>,
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
        new_js_error(
            cx,
            module,
            name,
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

impl SignalNodeError for libsignal_net::infra::errors::RetryLater {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        module: Handle<'a, JsObject>,
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
            module,
            Some("RateLimitedError"),
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
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = Some("InvalidUri");
        let message = self.to_string();
        new_js_error(
            cx,
            module,
            name,
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

impl SignalNodeError for libsignal_net::cdsi::LookupError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let name = match self {
            Self::RateLimited(retry_later) => {
                return retry_later.into_throwable(cx, module, operation_name)
            }
            Self::AttestationError(e) => return e.into_throwable(cx, module, operation_name),
            Self::InvalidArgument { server_reason: _ } => None,
            Self::InvalidToken => Some("CdsiInvalidToken"),
            Self::ConnectionTimedOut
            | Self::ConnectTransport(_)
            | Self::WebSocket(_)
            | Self::CdsiProtocol(_)
            | Self::EnclaveProtocol(_)
            | Self::InvalidResponse
            | Self::ParseError
            | Self::Server { reason: _ } => Some(IO_ERROR),
        };
        let message = self.to_string();
        new_js_error(
            cx,
            module,
            name,
            &message,
            operation_name,
            no_extra_properties,
        )
    }
}

mod registration {
    use libsignal_net::infra::errors::RetryLater;
    use libsignal_net::registration::{
        CreateSessionError, RegisterAccountError, RegistrationLock, RequestError,
        RequestVerificationCodeError, ResumeSessionError, SubmitVerificationError,
        UpdateSessionError, VerificationCodeNotDeliverable,
    };

    use super::*;

    impl<E: Into<BridgedErrorVariant> + std::fmt::Display> SignalNodeError for RequestError<E> {
        fn into_throwable<'a, C: Context<'a>>(
            self,
            cx: &mut C,
            module: Handle<'a, JsObject>,
            operation_name: &str,
        ) -> Handle<'a, JsError> {
            let inner = match self {
                RequestError::RequestWasNotValid => BridgedErrorVariant::RequestInvalid,
                RequestError::Other(inner) => inner.into(),
                RequestError::Timeout => {
                    return libsignal_net::chat::SendError::RequestTimedOut.into_throwable(
                        cx,
                        module,
                        operation_name,
                    )
                }
                RequestError::Unknown(message) => {
                    return new_js_error(
                        cx,
                        module,
                        None,
                        &message,
                        operation_name,
                        no_extra_properties,
                    )
                }
            };
            SignalNodeError::into_throwable(inner, cx, module, operation_name)
        }
    }

    enum BridgedErrorVariant {
        SessionNotFound,
        InvalidSessionId,
        RequestInvalid,
        RetryLater(RetryLater),
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
            module: Handle<'a, JsObject>,
            operation_name: &str,
        ) -> Handle<'a, JsError> {
            let message = match self {
                BridgedErrorVariant::RetryLater(retry_later) => {
                    return retry_later.into_throwable(cx, module, operation_name)
                }
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
            new_js_error(
                cx,
                module,
                None,
                message,
                operation_name,
                no_extra_properties,
            )
        }
    }

    impl From<CreateSessionError> for BridgedErrorVariant {
        fn from(value: CreateSessionError) -> Self {
            match value {
                CreateSessionError::InvalidSessionId => Self::InvalidSessionId,
                CreateSessionError::RetryLater(retry_later) => Self::RetryLater(retry_later),
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
                UpdateSessionError::RetryLater(retry_later) => Self::RetryLater(retry_later),
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
                RequestVerificationCodeError::RetryLater(retry_later) => {
                    Self::RetryLater(retry_later)
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
                SubmitVerificationError::RetryLater(retry_later) => Self::RetryLater(retry_later),
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
                RegisterAccountError::RetryLater(retry_later) => Self::RetryLater(retry_later),
            }
        }
    }
}

impl SignalNodeError for CancellationError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let message = self.to_string();
        new_js_error(
            cx,
            module,
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
        module: Handle<'a, JsObject>,
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
            module,
            Some("BackupValidation"),
            &message,
            operation_name,
            make_props,
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
