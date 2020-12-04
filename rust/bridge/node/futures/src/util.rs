//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::any::Any;

// See https://github.com/rust-lang/rfcs/issues/1389
pub(crate) fn describe_any(any: &Box<dyn Any + Send>) -> String {
    if let Some(msg) = any.downcast_ref::<&str>() {
        msg.to_string()
    } else if let Some(msg) = any.downcast_ref::<String>() {
        msg.to_string()
    } else {
        "(break on rust_panic to debug)".to_string()
    }
}
