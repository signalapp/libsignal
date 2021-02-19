//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;

use std::fmt;

#[derive(Debug)]
pub struct CallbackError {
    message: String,
}

impl CallbackError {
    pub(crate) fn new(message: String) -> CallbackError {
        Self { message }
    }
}

impl fmt::Display for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "callback error {}", self.message)
    }
}

impl std::error::Error for CallbackError {}

pub fn js_error_to_rust(func: &'static str, err: String) -> SignalProtocolError {
    SignalProtocolError::ApplicationCallbackError(func, Box::new(CallbackError::new(err)))
}
