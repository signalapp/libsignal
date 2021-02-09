//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![feature(box_patterns)]

use heck::SnakeCase;
use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro2::TokenStream as TokenStream2;
use quote::*;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::*;
use syn_mid::{FnArg, ItemFn, Pat, PatType, Signature};
use unzip_n::unzip_n;

unzip_n!(3);
unzip_n!(4);

fn value_for_meta_key<'a>(
    meta_values: &'a Punctuated<MetaNameValue, Token![,]>,
    key: &str,
) -> Option<&'a Lit> {
    meta_values
        .iter()
        .find(|meta| meta.path.get_ident().map_or(false, |ident| ident == key))
        .map(|meta| &meta.lit)
}

#[derive(Clone, Copy)]
enum ResultKind {
    Regular,
    Buffer,
    Void,
}

impl ResultKind {
    fn has_env(self) -> bool {
        match self {
            Self::Regular | Self::Void => false,
            Self::Buffer => true,
        }
    }
}

fn ffi_bridge_fn(name: String, sig: &Signature, result_kind: ResultKind) -> TokenStream2 {
    let name = format_ident!("signal_{}", name);

    let (output_args, env_arg, output_processing) = match (result_kind, &sig.output) {
        (ResultKind::Regular, ReturnType::Default) => (quote!(), quote!(), quote!()),
        (ResultKind::Regular, ReturnType::Type(_, ref ty)) => (
            quote!(out: *mut ffi_result_type!(#ty),), // note the trailing comma
            quote!(),
            quote!(<#ty as ffi::ResultTypeInfo>::write_to(out, __result)?),
        ),
        (ResultKind::Void, ReturnType::Default) => (quote!(), quote!(), quote!()),
        (ResultKind::Void, ReturnType::Type(_, _)) => (quote!(), quote!(), quote!(__result?;)),
        (ResultKind::Buffer, ReturnType::Type(_, _)) => (
            quote!(
                out: *mut *const libc::c_uchar,
                out_len: *mut libc::size_t, // note the trailing comma
            ),
            quote!(ffi::Env,), // note the trailing comma
            quote!(ffi::write_bytearray_to(out, out_len, __result?)?),
        ),
        (ResultKind::Buffer, ReturnType::Default) => {
            return Error::new(
                sig.paren_token.span,
                "missing result type for bridge_fn_buffer",
            )
            .to_compile_error()
        }
    };

    let await_if_needed = sig.asyncness.map(|_| {
        quote! {
            let __result = expect_ready(__result);
        }
    });

    let (input_names, input_args, input_processing) = sig
        .inputs
        .iter()
        .skip(if result_kind.has_env() { 1 } else { 0 })
        .map(|arg| match arg {
            FnArg::Receiver(tokens) => (
                Ident::new("self", tokens.self_token.span),
                Error::new(tokens.self_token.span, "cannot have 'self' parameter")
                    .to_compile_error(),
                quote!(),
            ),
            FnArg::Typed(PatType {
                attrs,
                pat: box Pat::Ident(name),
                colon_token,
                ty:
                    ty
                    @
                    box Type::Reference(TypeReference {
                        elem: box Type::Slice(_),
                        ..
                    }),
            }) => {
                let size_arg = format_ident!("{}_len", name.ident);
                (
                    name.ident.clone(),
                    quote!(
                        #(#attrs)* #name #colon_token ffi_arg_type!(#ty),
                        #size_arg: libc::size_t
                    ),
                    quote!(
                        let #name = <#ty as ffi::SizedArgTypeInfo>::convert_from(#name, #size_arg)?
                    ),
                )
            }
            FnArg::Typed(PatType {
                attrs,
                pat: box Pat::Ident(name),
                colon_token,
                ty,
            }) => (
                name.ident.clone(),
                quote!(#(#attrs)* #name #colon_token ffi_arg_type!(#ty)),
                quote!(let #name = <#ty as ffi::ArgTypeInfo>::convert_from(#name)?),
            ),
            FnArg::Typed(PatType { pat, .. }) => (
                Ident::new("unexpected", pat.span()),
                Error::new(pat.span(), "cannot use patterns in paramater").to_compile_error(),
                quote!(),
            ),
        })
        .unzip_n_vec();

    let orig_name = sig.ident.clone();

    quote! {
        #[cfg(feature = "ffi")]
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            #output_args
            #(#input_args),*
        ) -> *mut ffi::SignalFfiError {
            ffi::run_ffi_safe(|| {
                #(#input_processing);*;
                let __result = #orig_name(#env_arg #(#input_names),*);
                #await_if_needed;
                #output_processing;
                Ok(())
            })
        }
    }
}

fn ffi_name_from_ident(ident: &Ident) -> String {
    ident.to_string().to_snake_case()
}

fn jni_bridge_fn(name: String, sig: &Signature, result_kind: ResultKind) -> TokenStream2 {
    let name = format_ident!("Java_org_signal_client_internal_Native_{}", name);

    let (env_arg, output) = match (result_kind, &sig.output) {
        (ResultKind::Regular, ReturnType::Default) => (quote!(), quote!()),
        (ResultKind::Regular, ReturnType::Type(_, ref ty)) => {
            (quote!(), quote!(-> jni_result_type!(#ty)))
        }
        (ResultKind::Void, _) => (quote!(), quote!()),
        (ResultKind::Buffer, ReturnType::Type(_, _)) => (quote!(&env,), quote!(-> jni::jbyteArray)),
        (ResultKind::Buffer, ReturnType::Default) => {
            return Error::new(
                sig.paren_token.span,
                "missing result type for bridge_fn_buffer",
            )
            .to_compile_error()
        }
    };

    let await_if_needed = sig.asyncness.map(|_| {
        quote! {
            let __result = expect_ready(__result);
        }
    });

    let (input_names, input_args, input_processing) = sig
        .inputs
        .iter()
        .skip(if result_kind.has_env() { 1 } else { 0 })
        .map(|arg| match arg {
            FnArg::Receiver(tokens) => (
                Ident::new("self", tokens.self_token.span),
                Error::new(tokens.self_token.span, "cannot have 'self' parameter")
                    .to_compile_error(),
                quote!(),
            ),
            FnArg::Typed(PatType {
                attrs,
                pat: box Pat::Ident(name),
                colon_token,
                ty,
            }) => (
                name.ident.clone(),
                quote!(#(#attrs)* #name #colon_token jni_arg_type!(#ty)),
                quote! {
                    let mut #name = <#ty as jni::ArgTypeInfo>::borrow(&env, #name)?;
                    let #name = <#ty as jni::ArgTypeInfo>::load_from(&env, &mut #name)?
                },
            ),
            FnArg::Typed(PatType { pat, .. }) => (
                Ident::new("unexpected", pat.span()),
                Error::new(pat.span(), "cannot use patterns in paramater").to_compile_error(),
                quote!(),
            ),
        })
        .unzip_n_vec();

    let orig_name = sig.ident.clone();

    quote! {
        #[cfg(feature = "jni")]
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            env: jni::JNIEnv,
            _class: jni::JClass,
            #(#input_args),*
        ) #output {
            jni::run_ffi_safe(&env, || {
                #(#input_processing);*;
                let __result = #orig_name(#env_arg #(#input_names),*);
                #await_if_needed;
                jni::ResultTypeInfo::convert_into(__result, &env)
            })
        }
    }
}

fn jni_name_from_ident(ident: &Ident) -> String {
    ident.to_string().replace("_", "_1")
}

fn node_bridge_fn(name: String, sig: &Signature, result_kind: ResultKind) -> TokenStream2 {
    let name_with_prefix = format_ident!("node_{}", name);
    let name_without_prefix = Ident::new(&name, Span::call_site());

    let (env_arg, result_type_str) = match (result_kind, &sig.output) {
        (ResultKind::Regular, ReturnType::Default) => (quote!(), "()".to_string()),
        (ResultKind::Regular, ReturnType::Type(_, ty)) => (quote!(), quote!(#ty).to_string()),
        (ResultKind::Void, _) => (quote!(), "()".to_string()),
        (ResultKind::Buffer, ReturnType::Type(_, _)) => (quote!(&mut cx,), "Buffer".to_string()),
        (ResultKind::Buffer, ReturnType::Default) => {
            return Error::new(
                sig.paren_token.span,
                "missing result type for bridge_fn_buffer",
            )
            .to_compile_error()
        }
    };

    let (input_names, input_borrowing, input_loading, input_finalization) = sig
        .inputs
        .iter()
        .skip(if result_kind.has_env() { 1 } else { 0 })
        .zip(0..)
        .map(|(arg, i)| match arg {
            FnArg::Receiver(tokens) => (
                Ident::new("self", tokens.self_token.span),
                Error::new(tokens.self_token.span, "cannot have 'self' parameter")
                    .to_compile_error(),
                quote!(),
                quote!(),
            ),
            FnArg::Typed(PatType {
                attrs: _,
                pat: box Pat::Ident(name),
                colon_token: _,
                ty,
            }) => {
                let (type_info_trait, borrow_or_save) = match sig.asyncness {
                    Some(_) => (quote!(AsyncArgTypeInfo), quote!(save)),
                    None => (quote!(ArgTypeInfo), quote!(borrow)),
                };
                let name_arg = format_ident!("{}_arg", name.ident);
                let name_borrow = format_ident!("{}_borrow", name.ident);
                (
                    name.ident.clone(),
                    quote! {
                        let #name_arg = cx.argument::<<#ty as node::#type_info_trait>::ArgType>(#i)?;
                        let mut #name_borrow = <#ty as node::#type_info_trait>::#borrow_or_save(&mut cx, #name_arg)?;
                    },
                    quote! {
                        let #name = <#ty as node::#type_info_trait>::load_from(&mut #name_borrow);
                    },
                    quote! {
                        neon::prelude::Finalize::finalize(#name_borrow, cx);
                    },
                )
            }
            FnArg::Typed(PatType { pat, .. }) => (
                Ident::new("unexpected", pat.span()),
                Error::new(pat.span(), "cannot use patterns in parameter").to_compile_error(),
                quote!(),
                quote!(),
            ),
        })
        .unzip_n_vec();

    let orig_name = sig.ident.clone();
    let node_annotation = format!(
        "ts: export function {}({}): {}",
        name_without_prefix,
        sig.inputs
            .iter()
            .skip(if result_kind.has_env() { 1 } else { 0 })
            .map(|arg| quote!(#arg).to_string())
            .collect::<Vec<_>>()
            .join(", "),
        result_type_str
    );

    let body = match sig.asyncness {
        Some(_) => quote! {
            #(#input_borrowing)*
            Ok(signal_neon_futures::promise(&mut cx, async move {
                #(#input_loading)*
                let __result = #orig_name(#env_arg #(#input_names),*).await;
                signal_neon_futures::settle_promise(move |cx| {
                    let mut cx = scopeguard::guard(cx, |cx| {
                        #(#input_finalization)*
                    });
                    node::ResultTypeInfo::convert_into(__result, *cx)
                })
            })?.upcast())
        },
        None => quote! {
            #(#input_borrowing)*
            #(#input_loading)*
            let __result = #orig_name(#env_arg #(#input_names),*);
            Ok(node::ResultTypeInfo::convert_into(__result, &mut cx)?.upcast())
        },
    };

    quote! {
        #[cfg(feature = "node")]
        #[allow(non_snake_case)]
        #[doc = #node_annotation]
        pub fn #name_with_prefix(
            mut cx: node::FunctionContext,
        ) -> node::JsResult<node::JsValue> {
            #body
        }

        #[cfg(feature = "node")]
        node_register!(#name_without_prefix);
    }
}

fn node_name_from_ident(ident: &Ident) -> String {
    ident.to_string()
}

fn bridge_fn_impl(attr: TokenStream, item: TokenStream, result_kind: ResultKind) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);

    let item_names =
        parse_macro_input!(attr with Punctuated<MetaNameValue, Token![,]>::parse_terminated);
    let ffi_name = match value_for_meta_key(&item_names, "ffi") {
        Some(Lit::Str(name_str)) => Some(name_str.value()),
        Some(Lit::Bool(LitBool { value: false, .. })) => None,
        Some(value) => {
            return Error::new(value.span(), "ffi name must be a string literal")
                .to_compile_error()
                .into()
        }
        None => Some(ffi_name_from_ident(&function.sig.ident)),
    };
    let jni_name = match value_for_meta_key(&item_names, "jni") {
        Some(Lit::Str(name_str)) => Some(name_str.value()),
        Some(Lit::Bool(LitBool { value: false, .. })) => None,
        Some(value) => {
            return Error::new(value.span(), "jni name must be a string literal")
                .to_compile_error()
                .into()
        }
        None => Some(jni_name_from_ident(&function.sig.ident)),
    };
    let node_name = match value_for_meta_key(&item_names, "node") {
        Some(Lit::Str(name_str)) => Some(name_str.value()),
        Some(Lit::Bool(LitBool { value: false, .. })) => None,
        Some(value) => {
            return Error::new(value.span(), "node name must be a string literal")
                .to_compile_error()
                .into()
        }
        None => Some(node_name_from_ident(&function.sig.ident)),
    };

    let ffi_feature = ffi_name.as_ref().map(|_| quote!(feature = "ffi"));
    let jni_feature = jni_name.as_ref().map(|_| quote!(feature = "jni"));
    let node_feature = node_name.as_ref().map(|_| quote!(feature = "node"));
    let maybe_features = [ffi_feature, jni_feature, node_feature];
    let feature_list = maybe_features.iter().flatten();

    let ffi_fn = ffi_name.map(|name| ffi_bridge_fn(name, &function.sig, result_kind));
    let jni_fn = jni_name.map(|name| jni_bridge_fn(name, &function.sig, result_kind));
    let node_fn = node_name.map(|name| node_bridge_fn(name, &function.sig, result_kind));

    quote!(
        #[allow(non_snake_case)]
        #[cfg(any(#(#feature_list,)*))]
        #function

        #ffi_fn

        #jni_fn

        #node_fn
    )
    .into()
}

#[proc_macro_attribute]
pub fn bridge_fn(attr: TokenStream, item: TokenStream) -> TokenStream {
    bridge_fn_impl(attr, item, ResultKind::Regular)
}

#[proc_macro_attribute]
pub fn bridge_fn_buffer(attr: TokenStream, item: TokenStream) -> TokenStream {
    bridge_fn_impl(attr, item, ResultKind::Buffer)
}

#[proc_macro_attribute]
pub fn bridge_fn_void(attr: TokenStream, item: TokenStream) -> TokenStream {
    bridge_fn_impl(attr, item, ResultKind::Void)
}
