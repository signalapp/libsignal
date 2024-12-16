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
//! - FFI: Convert the function's name to `lower_snake_case` and prepend the value of environment
//!   variable `LIBSIGNAL_BRIDGE_FN_PREFIX_FFI`, which the client crate should set in its build.rs.
//! - JNI: Escape any underscores in the function's name per the [JNI spec][], then prepend the
//!   value of environment variable `LIBSIGNAL_BRIDGE_FN_PREFIX_JNI`, which the client should set in
//!   its build.rs. The value should be something like `Java_org_signal_libsignal_internal_Native_`
//!   to expose the function as a static method of the class `org.signal.libsignal.internal.Native`.
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
//! using the `bridge_as_handle` macro alongside other such types. Otherwise, there are two steps:
//!
//! 1. Argument and result types for FFI and JNI are determined by macros `ffi_arg_type`,
//!    `ffi_result_type`, `jni_arg_type`, and `jni_result_type`. You may need to add your new type
//!    there. JNI and Node types also undergo some additional transformation in the scripts
//!    `gen_java_decl.py` and `gen_ts_decl.py`, which you may need to tweak as well.
//!
//! 2. Argument types conform to one or more of the following bridge-specific traits:
//!
//!     - `ffi::ArgTypeInfo`
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
//! - There is no support for multiple return values, even though some of the FFI entry points
//!   use multiple output parameters. These functions must be implemented manually.

use proc_macro::TokenStream;
use quote::*;
use syn::parse::Parse;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::*;
use syn_mid::ItemFn;

mod ffi;
mod jni;
mod node;
mod util;

fn value_for_meta_key<'a>(
    meta_values: &'a Punctuated<MetaNameValue, Token![,]>,
    key: &str,
) -> Option<&'a Expr> {
    meta_values
        .iter()
        .find(|meta| meta.path.get_ident().is_some_and(|ident| ident == key))
        .map(|meta| &meta.value)
}

fn name_for_meta_key(
    meta_values: &Punctuated<MetaNameValue, Token![,]>,
    key: &str,
    default: impl FnOnce() -> String,
) -> Result<Option<String>> {
    match value_for_meta_key(meta_values, key) {
        Some(Expr::Lit(ExprLit {
            lit: Lit::Str(name_str),
            ..
        })) => Ok(Some(name_str.value())),
        Some(Expr::Lit(ExprLit {
            lit: Lit::Bool(LitBool { value: false, .. }),
            ..
        })) => Ok(None),
        Some(value) => Err(Error::new(value.span(), "name must be a string literal")),
        None => Ok(Some(default())),
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
enum ResultKind {
    Regular,
    Void,
}

impl From<&syn_mid::Signature> for ResultKind {
    fn from(value: &syn_mid::Signature) -> Self {
        let type_ = match &value.output {
            ReturnType::Default => return Self::Void,
            ReturnType::Type(_, type_) => type_.as_ref(),
        };

        let output_type = match &type_ {
            syn::Type::Path(path) if path.qself.is_none() => &path.path,
            syn::Type::Tuple(t) if t.elems.is_empty() => return ResultKind::Void,
            _ => return ResultKind::Regular,
        };

        let is_void_result = |segment: &syn::PathSegment| {
            if segment.ident != "Result" {
                return false;
            }

            let PathArguments::AngleBracketed(args) = &segment.arguments else {
                return false;
            };

            args.args.first().is_some_and(|arg| match arg {
                GenericArgument::Type(syn::Type::Tuple(t)) => t.elems.is_empty(),
                _ => false,
            })
        };

        let last_segment = output_type.segments.last();
        if last_segment.is_some_and(is_void_result) {
            return ResultKind::Void;
        }

        ResultKind::Regular
    }
}

enum BridgingKind<T = Type> {
    Regular,
    Io { runtime: T },
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
struct BridgeIoParams {
    runtime: Type,
    item_names: Punctuated<MetaNameValue, Token![,]>,
}

impl Parse for BridgeIoParams {
    fn parse(input: parse::ParseStream) -> Result<Self> {
        let runtime: Type = input.parse()?;
        if input.is_empty() {
            // bridge_io(MyRuntime)
            return Ok(Self {
                runtime,
                item_names: Default::default(),
            });
        }
        if input.peek(Token![=]) {
            // bridge_io(jni = "blah")
            return Err(Error::new(
                runtime.span(),
                "missing async runtime type in #[bridge_io]",
            ));
        }
        input.parse::<Token![,]>()?;
        // bridge_io(MyRuntime, jni = "blah")
        let item_names = Punctuated::<MetaNameValue, Token![,]>::parse_terminated(input)?;
        Ok(Self {
            runtime,
            item_names,
        })
    }
}

fn bridge_fn_impl(
    attr: TokenStream,
    item: TokenStream,
    bridging_kind: BridgingKind<()>,
) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);

    let (bridging_kind, item_names) = match bridging_kind {
        BridgingKind::Regular => (
            BridgingKind::Regular,
            parse_macro_input!(attr with Punctuated<MetaNameValue, Token![,]>::parse_terminated),
        ),
        BridgingKind::Io { runtime: () } => {
            let params = parse_macro_input!(attr as BridgeIoParams);
            (
                BridgingKind::Io {
                    runtime: params.runtime,
                },
                params.item_names,
            )
        }
    };
    let result_kind = ResultKind::from(&function.sig);

    let ffi_name = match name_for_meta_key(&item_names, "ffi", || {
        ffi::name_from_ident(&function.sig.ident)
    }) {
        Ok(name) => name,
        Err(error) => return error.to_compile_error().into(),
    };
    let jni_name = match name_for_meta_key(&item_names, "jni", || {
        jni::name_from_ident(&function.sig.ident)
    }) {
        Ok(name) => name,
        Err(error) => return error.to_compile_error().into(),
    };
    let node_name = match name_for_meta_key(&item_names, "node", || {
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

    // We could early-exit on the Errors returned from generating each wrapper,
    // but since they could be for unrelated issues, it's better to show all of them to the user.
    let ffi_fn = ffi_name.map(|name| {
        ffi::bridge_fn(&name, &function.sig, result_kind, &bridging_kind)
            .unwrap_or_else(Error::into_compile_error)
    });
    let jni_fn = jni_name.map(|name| {
        jni::bridge_fn(&name, &function.sig, &bridging_kind)
            .unwrap_or_else(Error::into_compile_error)
    });
    let node_fn = node_name.map(|name| {
        node::bridge_fn(&name, &function.sig, &bridging_kind)
            .unwrap_or_else(Error::into_compile_error)
    });

    quote!(
        #[allow(non_snake_case, clippy::needless_pass_by_ref_mut)]
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
    bridge_fn_impl(attr, item, BridgingKind::Regular)
}

#[proc_macro_attribute]
pub fn bridge_io(attr: TokenStream, item: TokenStream) -> TokenStream {
    bridge_fn_impl(attr, item, BridgingKind::Io { runtime: () })
}

#[cfg(test)]
mod bridge_io_params_tests {
    use super::*;

    #[test]
    fn invalid() {
        assert!(parse2::<BridgeIoParams>(quote!()).is_err());
        assert!(parse2::<BridgeIoParams>(quote!(-notAType)).is_err());
        assert!(parse2::<BridgeIoParams>(quote!(ffi = false)).is_err());
    }

    #[test]
    fn just_runtime() {
        let params: BridgeIoParams = parse2(quote!(some::Runtime)).expect("valid");
        assert_eq!(
            params,
            BridgeIoParams {
                runtime: parse_quote!(some::Runtime),
                item_names: Default::default()
            }
        );

        // Check that a trailing comma produces the same result.
        assert_eq!(params, parse2(quote!(some::Runtime,)).expect("valid"))
    }

    #[test]
    fn runtime_plus_renaming() {
        let params: BridgeIoParams =
            parse2(quote!(some::Runtime, a = "1", b = "2")).expect("valid");
        assert_eq!(params.runtime, parse_quote!(some::Runtime));
        assert_eq!(params.item_names, parse_quote!(a = "1", b = "2"));

        let params_with_trailing_comma: BridgeIoParams =
            parse2(quote!(some::Runtime, a = "1", b = "2")).expect("valid");
        assert_eq!(params.runtime, params_with_trailing_comma.runtime);
        // The trailing comma makes `item_names` unequal, but the items within are still equal.
        assert_eq!(
            params.item_names.into_iter().collect::<Vec<_>>(),
            params_with_trailing_comma
                .item_names
                .into_iter()
                .collect::<Vec<_>>(),
        );
    }
}

#[cfg(test)]
mod return_type_test {
    use super::*;

    #[test]
    fn implicit() {
        let parsed: ItemFn = parse_quote! {
            fn no_return() {}
        };
        assert_eq!(ResultKind::from(&parsed.sig), ResultKind::Void)
    }

    #[test]
    fn explicit_empty_tuple() {
        let parsed: ItemFn = parse_quote! {
            fn returns_empty_tuple() -> () {}
        };
        assert_eq!(ResultKind::from(&parsed.sig), ResultKind::Void)
    }

    #[test]
    fn result_returns() {
        let parsed: &[ItemFn] = &[
            parse_quote! { fn result_empty_tuple() -> Result<(), Err> { unimplemented!() } },
            parse_quote! { fn result_empty_tuple_alias() -> Result<()> { unimplemented!() } },
            parse_quote! { fn result_fq_empty_tuple() -> std::result::Result<(), Err> { unimplemented!() } },
            parse_quote! { fn result_fq_empty_tuple_alias() -> my::package::custom::Result<()> { unimplemented!() } },
        ];

        for item in parsed {
            assert_eq!(
                ResultKind::from(&item.sig),
                ResultKind::Void,
                "{}",
                item.to_token_stream()
            );
        }
    }

    #[test]
    fn regular_types() {
        let parsed: &[ItemFn] = &[
            parse_quote! { fn returns_bool() -> bool { unimplemented!() } },
            parse_quote! { fn returns_u32() -> u32 { unimplemented!() } },
            parse_quote! { fn returns_result_u32_alias() -> Result<u32> { unimplemented!() } },
            parse_quote! { fn returns_result_u32() -> Result<u32, Err> { unimplemented!() } },
            parse_quote! { fn returns_fq_result_u32() -> std::result::Result<u32, Err> { unimplemented!() } },
        ];

        for item in parsed {
            assert_eq!(
                ResultKind::from(&item.sig),
                ResultKind::Regular,
                "{}",
                item.to_token_stream()
            );
        }
    }
}
