//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

use libsignal_net::chat::ChatServiceError;
use libsignal_net::svr3::Error as Svr3Error;
use signal_media::sanitize::mp4::{Error as Mp4Error, ParseError as Mp4ParseError};
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

fn optional_extra_properties<'a, C: Context<'a>, F: FnOnce(&mut C) -> JsResult<'a, JsValue>>(
    f: Option<F>,
) -> impl FnOnce(&mut C) -> JsResult<'a, JsValue> {
    |cx| match f {
        None => no_extra_properties(cx),
        Some(f) => f(cx),
    }
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

pub trait SignalNodeError: Sized + fmt::Display {
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
const RATE_LIMITED_ERROR: &str = "RateLimitedError";
const SVR3_DATA_MISSING: &str = "SvrDataMissing";
const SVR3_ROTATION_MACHINE_STEPS: &str = "SvrRotationMachineTooManySteps";
const SVR3_REQUEST_FAILED: &str = "SvrRequestFailed";
const SVR3_RESTORE_FAILED: &str = "SvrRestoreFailed";
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

impl SignalNodeError for device_transfer::Error {}

impl SignalNodeError for attest::hsm_enclave::Error {}

impl SignalNodeError for attest::enclave::Error {}

impl SignalNodeError for signal_crypto::Error {}

impl SignalNodeError for zkgroup::ZkGroupVerificationFailure {}

impl SignalNodeError for zkgroup::ZkGroupDeserializationFailure {}

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

impl SignalNodeError for usernames::ProofVerificationFailure {}

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

impl SignalNodeError for libsignal_net::chat::ChatServiceError {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let (name, properties) = match self {
            ChatServiceError::Disconnected => (Some("ChatServiceInactive"), None),
            ChatServiceError::AppExpired => (Some("AppExpired"), None),
            ChatServiceError::DeviceDeregistered => (Some("DeviceDelinked"), None),
            ChatServiceError::RetryLater {
                retry_after_seconds,
            } => rate_limited_error(retry_after_seconds),
            ChatServiceError::WebSocket(_)
            | ChatServiceError::UnexpectedFrameReceived
            | ChatServiceError::ServerRequestMissingId
            | ChatServiceError::IncomingDataInvalid
            | ChatServiceError::RequestHasInvalidHeader
            | ChatServiceError::RequestSendTimedOut
            | ChatServiceError::TimeoutEstablishingConnection
            | ChatServiceError::AllConnectionRoutesFailed
            | ChatServiceError::InvalidConnectionConfiguration =>
            // TODO: Distinguish retryable errors from proper failures?
            {
                (Some(IO_ERROR), None)
            }
        };
        let message = self.to_string();
        new_js_error(
            cx,
            module,
            name,
            &message,
            operation_name,
            optional_extra_properties(properties),
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
        let (name, make_extra_props) = match self {
            Self::RateLimited {
                retry_after_seconds,
            } => rate_limited_error(retry_after_seconds),
            Self::AttestationError(e) => return e.into_throwable(cx, module, operation_name),
            Self::InvalidArgument { server_reason: _ } => (None, None),
            Self::InvalidToken => (Some("CdsiInvalidToken"), None),
            Self::ConnectionTimedOut
            | Self::ConnectTransport(_)
            | Self::WebSocket(_)
            | Self::CdsiProtocol(_)
            | Self::EnclaveProtocol(_)
            | Self::InvalidResponse
            | Self::ParseError
            | Self::Server { reason: _ } => (Some(IO_ERROR), None),
        };
        let message = self.to_string();
        new_js_error(
            cx,
            module,
            name,
            &message,
            operation_name,
            optional_extra_properties(make_extra_props),
        )
    }
}

fn rate_limited_error<'a, C: Context<'a>>(
    retry_after_seconds: u32,
) -> (
    Option<&'a str>,
    Option<impl Fn(&mut C) -> JsResult<'a, JsValue>>,
) {
    (
        Some(RATE_LIMITED_ERROR),
        Some(move |cx: &mut C| {
            let props = cx.empty_object();
            let retry_after = retry_after_seconds.convert_into(cx)?;
            props.set(cx, "retryAfterSecs", retry_after)?;
            Ok(props.upcast())
        }),
    )
}

impl SignalNodeError for libsignal_net::svr3::Error {
    fn into_throwable<'a, C: Context<'a>>(
        self,
        cx: &mut C,
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> Handle<'a, JsError> {
        let (name, make_props) = match self {
            Svr3Error::Service(_) | Svr3Error::ConnectionTimedOut | Svr3Error::Connect(_) => {
                (Some(IO_ERROR), None)
            }
            Svr3Error::AttestationError(inner) => {
                return inner.into_throwable(cx, module, operation_name);
            }
            Svr3Error::RequestFailed(_) => (Some(SVR3_REQUEST_FAILED), None),
            Svr3Error::RestoreFailed(tries_remaining) => (
                Some(SVR3_RESTORE_FAILED),
                Some(move |cx: &mut C| {
                    let props = cx.empty_object();
                    let tries_remaining = tries_remaining.convert_into(cx)?;
                    props.set(cx, "triesRemaining", tries_remaining)?;
                    Ok(props.upcast())
                }),
            ),
            Svr3Error::DataMissing => (Some(SVR3_DATA_MISSING), None),
            Svr3Error::Protocol(_) => (None, None),
            Svr3Error::RotationMachineTooManySteps => (Some(SVR3_ROTATION_MACHINE_STEPS), None),
        };

        let message = self.to_string();
        new_js_error(
            cx,
            module,
            name,
            &message,
            operation_name,
            optional_extra_properties(make_props),
        )
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
