//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Allows `async` blocks to be used to wait on JavaScript futures using [Neon][].
//!
//! Neon provides a way to expose *synchronous* JavaScript functions from Rust.
//! This means that if Rust wants to wait for the result of a JavaScript promise,
//! it can at best return a callback to continue its work when the promise settles.
//! This does not naturally compose with Rust's `async`, which works in terms of [Futures](trait@std::future::Future).
//!
//! This crate provides functionality for (1) wrapping JavaScript futures so they can be awaited on in Rust,
//! and (2) producing a JavaScript promise that wraps a Rust future. It does so by resuming execution
//! of the Rust future on the JavaScript microtask queue whenever an awaited JavaScript promise is settled.
//!
//! To get started, look at the [promise()] function and the [JsFuture::from_promise] method.
//!
//! [Neon]: https://neon-bindings.com/

#![warn(missing_docs)]
#![warn(clippy::unwrap_used)]

mod executor;
pub use executor::ChannelEx;

mod exception;
pub use exception::PersistentException;

mod future;
pub use future::{JsFuture, JsFutureBuilder};

mod promise;
pub use promise::{promise, settle_promise};

mod result;
pub use result::JsPromiseResult;

mod util;
pub use util::call_method;
