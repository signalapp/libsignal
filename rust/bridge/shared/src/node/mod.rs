//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol::*;
use std::convert::TryFrom;
use std::ops::Deref;

pub(crate) use neon::context::Context;
pub(crate) use neon::prelude::*;
pub(crate) use neon::types::buffer::TypedArray;

/// Used to keep track of all generated entry points.
///
/// Takes the *JavaScript* name `fooBar` of a function; the corresponding Rust function must be
/// declared `node_fooBar`.
// Declared early so it can be used in submodules.
macro_rules! node_register {
    ( $name:ident ) => {
        paste! {
            #[no_mangle] // necessary because we are linking as a cdylib
            #[allow(non_upper_case_globals)]
            #[linkme::distributed_slice(crate::node::LIBSIGNAL_FNS)]
            static [<signal_register_node_ $name>]: (&str, crate::node::JsFn) =
                (stringify!($name), [<node_ $name>]);
        }
    };
}

#[macro_use]
mod convert;
pub use convert::*;

mod error;
pub use error::*;

mod io;
pub use io::*;

mod storage;
pub use storage::*;

/// A function pointer referring to a Neon-based Node entry point.
#[doc(hidden)]
pub(crate) type JsFn = for<'a> fn(FunctionContext<'a>) -> JsResult<'a, JsValue>;

#[doc(hidden)]
#[linkme::distributed_slice]
pub(crate) static LIBSIGNAL_FNS: [(&'static str, JsFn)] = [..];

/// Exports all `bridge_fn`-generated entry points.
pub fn register(cx: &mut ModuleContext) -> NeonResult<()> {
    for (name, f) in LIBSIGNAL_FNS {
        cx.export_function(name, *f)?;
    }
    Ok(())
}

/// A wrapper around a type that implements Neon's [`Finalize`] by simply dropping the type.
pub struct DefaultFinalize<T>(pub T);

impl<T> Finalize for DefaultFinalize<T> {}

impl<T> Deref for DefaultFinalize<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<T> for DefaultFinalize<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

pub type DefaultJsBox<T> = JsBox<DefaultFinalize<T>>;
