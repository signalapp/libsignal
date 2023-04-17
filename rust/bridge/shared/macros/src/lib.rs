//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Generates C, Java, and Node entry points for Rust functions.
//!
//! The goal of the `bridge_fn` family of macros is to define a cross-language glue layer using
//! strongly-typed Rust code. You can write a normal top-level Rust function exposing a particular
//! operation, and additional functions will be generated for FFI, JNI, and Node bindings, mapping
//! types automatically.
//!
//! It is explicitly *not* a goal for this layer to generate perfect C, Java, or TypeScript APIs.
//! Rather, it should generate safe interfaces to *Rust* APIs, on top of which idiomatic Swift,
//! Java, and TypeScript APIs can be built.
//!
//! # Example
//!
//! ```ignore
//! # #[cfg(ignore_even_when_running_all_tests)]
//! #[bridge_fn]
//! fn SenderKeyMessage_New(
//!     key_id: u32,
//!     iteration: u32,
//!     ciphertext: &[u8],
//!     pk: &PrivateKey,
//! ) -> Result<SenderKeyMessage> {
//!     let mut csprng = rand::rngs::OsRng;
//!     SenderKeyMessage::new(key_id, iteration, ciphertext, &mut csprng, pk)
//! }
//! ```
//!
//! ```c
//! SignalFfiError *signal_sender_key_message_new(
//!     SignalSenderKeyMessage **out,
//!     uint32_t key_id,
//!     uint32_t iteration,
//!     const unsigned char *ciphertext,
//!     size_t ciphertext_len,
//!     const SignalPrivateKey *pk);
//! ```
//!
//! ```java
//! public static native long SenderKeyMessage_New(
//!     int keyId,
//!     int iteration,
//!     byte[] ciphertext,
//!     long pk);
//! ```
//!
//! ```typescript
//! export function SenderKeyMessage_New(
//!     keyId: number,
//!     iteration: number,
//!     ciphertext: Buffer,
//!     pk: Wrapper<PrivateKey>
//! ): SenderKeyMessage;
//! ```
//!
//! # Async support for Node
//!
//! For the Node bridge, if a `bridge_fn` is declared as `async`, it will return a JavaScript
//! Promise and run the function on the JavaScript event loop using the `signal-neon-futures`
//! crate. Interaction with JavaScript can be done through async callbacks, including trait objects
//! defined using the [`async-trait`][] crate. Like the synchronous implementations of all three
//! bridges, **panics will be caught** and translated to JavaScript exceptions.
//!
//! The FFI and JNI bridges do not support asynchronous execution; an `async` function is invoked
//! and `expect`ed to complete immediately without blocking.
//!
//! [`async-trait`]: https://crates.io/crates/async-trait
//!
//! # Naming conventions
//!
//! By default, `bridge_fn` tries to pick a good name for each exposed entry point:
//!
//! - FFI: Convert the function's name to `lower_snake_case` and prepend `signal_`.
//! - JNI: Escape any underscores in the function's name per the [JNI spec][], then prepend
//!  `Java_org_signal_libsignal_internal_Native_` to expose the function as a static method of the
//!  class `org.signal.libsignal.internal.Native`.
//! - Node: Use the original function's name.
//!
//! As such, the recommended naming scheme for `bridge_fn` functions is `ObjectOrGroup_Operation`.
//!
//! Any of these names can be replaced by specifying an argument to the `bridge_fn` attribute:
//!
//! ```ignore
//! # #[cfg(ignore_even_when_running_all_tests)]
//! #[bridge_fn(ffi = "magic_alakazam", jni = "Magic_1Alakazam")]
//! fn Abracadabra() {
//!   // ...
//! }
//! ```
//!
//! A replaced name does not undergo any transformation, but is still prefixed with the required
//! "namespace" for FFI and JNI.
//!
//! [JNI spec]: https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/design.html#resolving_native_method_names
//!
//! # Limiting to certain bridges
//!
//! Do not use `cfg(feature = "abc")` to restrict a `bridge_fn` to certain bridges (e.g. "just
//! FFI"). This interacts poorly with commands like `cargo clippy --workspace`, which try to
//! validate all packages by enabling all three bridges at once. Instead, you can write e.g.
//! `bridge_fn(jni = false)` to keep from exposing a particular function to Java.
//!
//! # Adding new argument and result types
//!
//! If your argument or result type is a Rust value being wrapped in an opaque box, declare it
//! using the `bridge_handle` macro alongside other such types. Otherwise, there are two steps:
//!
//! 1. Argument and result types for FFI and JNI are determined by macros `ffi_arg_type`,
//!    `ffi_result_type`, `jni_arg_type`, and `jni_result_type`. You may need to add your new type
//!    there. JNI and Node types also undergo some additional transformation in the scripts
//!    `gen_java_decl.py` and `gen_ts_decl.py`, which you may need to tweak as well.
//!
//! 2. Argument types conform to one or more of the following bridge-specific traits:
//!
//!     - `ffi::ArgTypeInfo` or `ffi::SizedArgTypeInfo`
//!     - `jni::ArgTypeInfo`
//!     - `node::ArgTypeInfo` and/or `node::AsyncArgTypeInfo`
//!
//!     Similarly, result types conform to one or more of the following:
//!
//!     - `ffi::ResultTypeInfo`
//!     - `jni::ResultTypeInfo`
//!     - `node::ResultTypeInfo`
//!
//!    These traits define how to convert between the bridge type and the Rust type used in the
//!    function as written. See each individual trait for more info on how to add a new type.
//!
//! # Limitations
//!
//! - Input buffers require special treatment for FFI so that their size can be passed in.
//!   This needs special handling in the implementation of the macros to generate multiple
//!   parameters in the FFI entry point that map to a single parameter in the corresponding Rust
//!   function. Supporting more types that would require multiple parameters is non-trivial,
//!   particularly when trying to do so on the syntactic representation of the AST that macros are
//!   restricted to.
//!
//! - There is no support for multiple return values, even though some of the FFI entry points
//!   use multiple output parameters. These functions must be implemented manually.

use proc_macro::TokenStream;
use quote::*;
use syn::punctuated::Punctuated;
use syn::*;
use syn_mid::ItemFn;

mod ffi;
mod jni;
mod node;

fn value_for_meta_key<'a>(
    meta_values: &'a Punctuated<MetaNameValue, Token![,]>,
    key: &str,
) -> Option<&'a Lit> {
    meta_values
        .iter()
        .find(|meta| meta.path.get_ident().map_or(false, |ident| ident == key))
        .map(|meta| &meta.lit)
}

fn name_for_meta_key(
    meta_values: &Punctuated<MetaNameValue, Token![,]>,
    key: &str,
    enabled: bool,
    default: impl FnOnce() -> String,
) -> Result<Option<String>> {
    if !enabled {
        return Ok(None);
    }
    match value_for_meta_key(meta_values, key) {
        Some(Lit::Str(name_str)) => Ok(Some(name_str.value())),
        Some(Lit::Bool(LitBool { value: false, .. })) => Ok(None),
        Some(value) => Err(Error::new(value.span(), "name must be a string literal")),
        None => Ok(Some(default())),
    }
}

#[derive(Clone, Copy)]
enum ResultKind {
    Regular,
    Void,
}

fn bridge_fn_impl(attr: TokenStream, item: TokenStream, result_kind: ResultKind) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);

    let item_names =
        parse_macro_input!(attr with Punctuated<MetaNameValue, Token![,]>::parse_terminated);
    let ffi_name = match name_for_meta_key(&item_names, "ffi", cfg!(feature = "ffi"), || {
        ffi::name_from_ident(&function.sig.ident)
    }) {
        Ok(name) => name,
        Err(error) => return error.to_compile_error().into(),
    };
    let jni_name = match name_for_meta_key(&item_names, "jni", cfg!(feature = "jni"), || {
        jni::name_from_ident(&function.sig.ident)
    }) {
        Ok(name) => name,
        Err(error) => return error.to_compile_error().into(),
    };
    let node_name = match name_for_meta_key(&item_names, "node", cfg!(feature = "node"), || {
        node::name_from_ident(&function.sig.ident)
    }) {
        Ok(name) => name,
        Err(error) => return error.to_compile_error().into(),
    };

    let ffi_feature = ffi_name.as_ref().map(|_| quote!(feature = "ffi"));
    let jni_feature = jni_name.as_ref().map(|_| quote!(feature = "jni"));
    let node_feature = node_name.as_ref().map(|_| quote!(feature = "node"));
    let maybe_features = [ffi_feature, jni_feature, node_feature];
    let feature_list = maybe_features.iter().flatten();

    let ffi_fn = ffi_name.map(|name| ffi::bridge_fn(name, &function.sig, result_kind));
    let jni_fn = jni_name.map(|name| jni::bridge_fn(name, &function.sig, result_kind));
    let node_fn = node_name.map(|name| node::bridge_fn(name, &function.sig, result_kind));

    quote!(
        #[allow(non_snake_case)]
        #[cfg(any(#(#feature_list,)*))]
        #[inline(always)]
        #function

        #ffi_fn

        #jni_fn

        #node_fn
    )
    .into()
}

/// Generates C, Java, and Node entry points for a Rust function that returns a value.
///
/// See the [crate-level documentation](crate) for more information.
///
/// # Example
///
/// ```ignore
/// // Produces a C function named "signal_checksum_buffer"
/// // and a TypeScript function manually named "Buffer_Checksum",
/// // with the Java entry point disabled.
/// # #[cfg(ignore_even_when_running_all_tests)]
/// #[bridge_fn(jni = false, node = "Buffer_Checksum")]
/// fn ChecksumBuffer(buffer: &[u8]) -> u64 {
///   // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn bridge_fn(attr: TokenStream, item: TokenStream) -> TokenStream {
    bridge_fn_impl(attr, item, ResultKind::Regular)
}

/// Generates C, Java, and Node entry points for a Rust function that returns `Result<(), _>`.
///
/// Because the C bindings conventions use out-parameters for successful return values,
/// a case of "no result on success" must be annotated specially.
///
/// See the [crate-level documentation](crate) for more information.
///
/// # Example
///
/// ```ignore
/// // Produces a C function manually named "signal_process_postkey"
/// // and a JNI function named "PostKey_1Process" (with JNI "_1" mangling for an underscore),
/// // with the Node entry point disabled.
/// # #[cfg(ignore_even_when_running_all_tests)]
/// #[bridge_fn_void(ffi = "process_postkey", node = false)]
/// fn PostKey_Process(post_key: &PostKey) -> Result<()> {
///   // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn bridge_fn_void(attr: TokenStream, item: TokenStream) -> TokenStream {
    bridge_fn_impl(attr, item, ResultKind::Void)
}
