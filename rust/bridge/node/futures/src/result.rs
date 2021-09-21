//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;

/// The result of a JavaScript promise: a success value or a failure value.
pub type JsPromiseResult<'a> = Result<Handle<'a, JsValue>, Handle<'a, JsValue>>;

/// A trait to lift the cases of Result into types, to be used as generic arguments.
pub(crate) trait JsPromiseResultConstructor: 'static {
    fn make(value: Handle<JsValue>) -> JsPromiseResult;
}

/// A constructor for [Result::Ok].
pub(crate) struct JsFulfilledResult;

impl JsPromiseResultConstructor for JsFulfilledResult {
    fn make(value: Handle<JsValue>) -> JsPromiseResult {
        Ok(value)
    }
}

/// A constructor for [Result::Err].
pub(crate) struct JsRejectedResult;

impl JsPromiseResultConstructor for JsRejectedResult {
    fn make(value: Handle<JsValue>) -> JsPromiseResult {
        Err(value)
    }
}
