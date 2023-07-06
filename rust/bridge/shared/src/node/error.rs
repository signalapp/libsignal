//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;

use paste::paste;
use signal_media::sanitize;
use std::fmt;

const ERRORS_PROPERTY_NAME: &str = "Errors";
const ERROR_CLASS_NAME: &str = "LibSignalErrorBase";

#[allow(non_snake_case)]
fn node_registerErrors(mut cx: FunctionContext) -> JsResult<JsValue> {
    let errors_module = cx.argument::<JsObject>(0)?;
    cx.this()
        .set(&mut cx, ERRORS_PROPERTY_NAME, errors_module)?;
    Ok(cx.undefined().upcast())
}
node_register!(registerErrors);

fn new_js_error<'a>(
    cx: &mut impl Context<'a>,
    module: Handle<'a, JsObject>,
    name: Option<&str>,
    message: &str,
    operation: &str,
    extra_props: Option<Handle<'a, JsObject>>,
) -> Option<Handle<'a, JsObject>> {
    let result = cx.try_catch(|cx| {
        let errors_module: Handle<JsObject> = module.get(cx, ERRORS_PROPERTY_NAME)?;
        let error_class: Handle<JsFunction> = errors_module.get(cx, ERROR_CLASS_NAME)?;
        let name_arg = match name {
            Some(name) => cx.string(name).upcast(),
            None => cx.undefined().upcast(),
        };
        let extra_props_arg = match extra_props {
            Some(props) => props.upcast(),
            None => cx.undefined().upcast(),
        };

        let args: &[Handle<JsValue>] = &[
            cx.string(message).upcast(),
            name_arg,
            cx.string(operation).upcast(),
            extra_props_arg,
        ];
        error_class.construct(cx, args)
    });
    match result {
        Ok(error_instance) => Some(error_instance),
        Err(failure) => {
            log::warn!(
                "could not construct {}: {}",
                name.unwrap_or("LibSignalError"),
                failure
                    .to_string(cx)
                    .map(|s| s.value(cx))
                    .unwrap_or_else(|_| "(could not print error)".to_owned())
            );
            None
        }
    }
}

pub trait SignalNodeError: Sized + fmt::Display {
    fn throw<'a>(
        self,
        cx: &mut impl Context<'a>,
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> JsResult<'a, JsValue> {
        let message = self.to_string();
        match new_js_error(cx, module, None, &message, operation_name, None) {
            Some(error) => cx.throw(error),
            None => {
                // Make sure we still throw something.
                cx.throw_error(&message)
            }
        }
    }
}

const IO_ERROR: &str = "IoError";
const INVALID_MEDIA_INPUT: &str = "InvalidMediaInput";
const UNSUPPORTED_MEDIA_INPUT: &str = "UnsupportedMediaInput";

impl SignalNodeError for neon::result::Throw {
    fn throw<'a>(
        self,
        _cx: &mut impl Context<'a>,
        _module: Handle<'a, JsObject>,
        _operation_name: &str,
    ) -> JsResult<'a, JsValue> {
        Err(self)
    }
}

impl SignalNodeError for SignalProtocolError {
    fn throw<'a>(
        self,
        cx: &mut impl Context<'a>,
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> JsResult<'a, JsValue> {
        // Check for some dedicated error types first.
        let custom_error = match &self {
            SignalProtocolError::DuplicatedMessage(..) => new_js_error(
                cx,
                module,
                Some("DuplicatedMessage"),
                &self.to_string(),
                operation_name,
                None,
            ),
            SignalProtocolError::SealedSenderSelfSend => new_js_error(
                cx,
                module,
                Some("SealedSenderSelfSend"),
                &self.to_string(),
                operation_name,
                None,
            ),
            SignalProtocolError::UntrustedIdentity(addr) => {
                let props = cx.empty_object();
                let addr_string = cx.string(addr.name());
                props.set(cx, "_addr", addr_string)?;
                new_js_error(
                    cx,
                    module,
                    Some("UntrustedIdentity"),
                    &self.to_string(),
                    operation_name,
                    Some(props),
                )
            }
            SignalProtocolError::InvalidRegistrationId(addr, _value) => {
                let props = cx.empty_object();
                let addr = addr.clone().convert_into(cx)?;
                props.set(cx, "_addr", addr)?;
                new_js_error(
                    cx,
                    module,
                    Some("InvalidRegistrationId"),
                    &self.to_string(),
                    operation_name,
                    Some(props),
                )
            }
            SignalProtocolError::InvalidSessionStructure(..) => new_js_error(
                cx,
                module,
                Some("InvalidSession"),
                &self.to_string(),
                operation_name,
                None,
            ),
            SignalProtocolError::InvalidSenderKeySession { distribution_id } => {
                let props = cx.empty_object();
                let distribution_id_str =
                    cx.string(format!("{:x}", distribution_id.as_hyphenated()));
                props.set(cx, "distribution_id", distribution_id_str)?;
                new_js_error(
                    cx,
                    module,
                    Some("InvalidSenderKeySession"),
                    &self.to_string(),
                    operation_name,
                    Some(props),
                )
            }
            _ => new_js_error(cx, module, None, &self.to_string(), operation_name, None),
        };

        match custom_error {
            Some(error) => cx.throw(error),
            None => {
                // Make sure we still throw something.
                cx.throw_error(&self.to_string())
            }
        }
    }
}

impl SignalNodeError for device_transfer::Error {}

impl SignalNodeError for attest::hsm_enclave::Error {}

impl SignalNodeError for attest::sgx_session::Error {}

impl SignalNodeError for signal_crypto::Error {}

impl SignalNodeError for zkgroup::ZkGroupVerificationFailure {}

impl SignalNodeError for zkgroup::ZkGroupDeserializationFailure {}

impl SignalNodeError for usernames::UsernameError {
    fn throw<'a>(
        self,
        cx: &mut impl Context<'a>,
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> JsResult<'a, JsValue> {
        let name = match &self {
            Self::BadNicknameCharacter => Some("BadNicknameCharacter"),
            Self::NicknameTooShort => Some("NicknameTooShort"),
            Self::NicknameTooLong => Some("NicknameTooLong"),
            Self::CannotBeEmpty => Some("CannotBeEmpty"),
            Self::CannotStartWithDigit => Some("CannotStartWithDigit"),
            Self::MissingSeparator => Some("MissingSeparator"),
            // These don't get a dedicated error code
            // because clients won't need to distinguish them from other errors.
            Self::BadDiscriminator => None,
            Self::ProofVerificationFailure => None,
        };
        let message = self.to_string();
        match new_js_error(cx, module, name, &message, operation_name, None) {
            Some(error) => cx.throw(error),
            None => {
                // Make sure we still throw something.
                cx.throw_error(message)
            }
        }
    }
}

impl SignalNodeError for usernames::UsernameLinkError {
    fn throw<'a>(
        self,
        cx: &mut impl Context<'a>,
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> JsResult<'a, JsValue> {
        let name = match &self {
            Self::InputDataTooLong => Some("InputDataTooLong"),
            Self::InvalidEntropyDataLength => Some("InvalidEntropyDataLength"),
            Self::UsernameLinkDataTooShort
            | Self::HmacMismatch
            | Self::BadCiphertext
            | Self::InvalidDecryptedDataStructure => Some("InvalidUsernameLinkEncryptedData"),
        };
        let message = self.to_string();
        match new_js_error(cx, module, name, &message, operation_name, None) {
            Some(error) => cx.throw(error),
            None => {
                // Make sure we still throw something.
                cx.throw_error(message)
            }
        }
    }
}

impl SignalNodeError for sanitize::Error {
    fn throw<'a>(
        self,
        cx: &mut impl Context<'a>,
        module: Handle<'a, JsObject>,
        operation_name: &str,
    ) -> JsResult<'a, JsValue> {
        let name = match &self {
            sanitize::Error::Io(_) => Some(IO_ERROR),
            sanitize::Error::Parse(err) => match err.kind {
                sanitize::ParseError::InvalidBoxLayout => Some(INVALID_MEDIA_INPUT),
                sanitize::ParseError::InvalidInput => Some(INVALID_MEDIA_INPUT),
                sanitize::ParseError::MissingRequiredBox(_) => Some(INVALID_MEDIA_INPUT),
                sanitize::ParseError::TruncatedBox => Some(INVALID_MEDIA_INPUT),
                sanitize::ParseError::UnsupportedBox(_) => Some(UNSUPPORTED_MEDIA_INPUT),
                sanitize::ParseError::UnsupportedBoxLayout => Some(UNSUPPORTED_MEDIA_INPUT),
                sanitize::ParseError::UnsupportedFormat(_) => Some(UNSUPPORTED_MEDIA_INPUT),
            },
        };
        let message = self.to_string();
        match new_js_error(cx, module, name, &message, operation_name, None) {
            Some(error) => cx.throw(error),
            None => {
                // Make sure we still throw something.
                cx.throw_error(&message)
            }
        }
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
