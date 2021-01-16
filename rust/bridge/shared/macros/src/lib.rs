//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![feature(box_patterns)]

use heck::SnakeCase;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::*;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::*;
use syn_mid::{FnArg, ItemFn, Pat, PatType, Signature};
use unzip3::Unzip3;

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
}

impl ResultKind {
    fn has_env(self) -> bool {
        match self {
            Self::Regular => false,
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

    let (input_names, input_args, input_processing): (
        Vec<Ident>,
        Vec<TokenStream2>,
        Vec<TokenStream2>,
    ) = sig
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
        .unzip3();

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
        (ResultKind::Buffer, ReturnType::Type(_, _)) => (quote!(&env,), quote!(-> jni::jbyteArray)),
        (ResultKind::Buffer, ReturnType::Default) => {
            return Error::new(
                sig.paren_token.span,
                "missing result type for bridge_fn_buffer",
            )
            .to_compile_error()
        }
    };

    let (input_names, input_args, input_processing): (
        Vec<Ident>,
        Vec<TokenStream2>,
        Vec<TokenStream2>,
    ) = sig
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
                ty: ty @ box Type::Reference(_),
            }) => (
                name.ident.clone(),
                quote!(#(#attrs)* #name #colon_token jni_arg_type!(#ty)),
                quote!(
                    let #name = <#ty as jni::RefArgTypeInfo>::convert_from(&env, #name)?;
                    let #name = std::borrow::Borrow::borrow(&#name)
                ),
            ),
            FnArg::Typed(PatType {
                attrs,
                pat: box Pat::Ident(name),
                colon_token,
                ty,
            }) => (
                name.ident.clone(),
                quote!(#(#attrs)* #name #colon_token jni_arg_type!(#ty)),
                quote!(let #name = <#ty as jni::ArgTypeInfo>::convert_from(&env, #name)?),
            ),
            FnArg::Typed(PatType { pat, .. }) => (
                Ident::new("unexpected", pat.span()),
                Error::new(pat.span(), "cannot use patterns in paramater").to_compile_error(),
                quote!(),
            ),
        })
        .unzip3();

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
                jni::ResultTypeInfo::convert_into(#orig_name(#env_arg #(#input_names),*), &env)
            })
        }
    }
}

fn jni_name_from_ident(ident: &Ident) -> String {
    ident.to_string().replace("_", "_1")
}

fn bridge_fn_impl(attr: TokenStream, item: TokenStream, result_kind: ResultKind) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);

    let item_names =
        parse_macro_input!(attr with Punctuated<MetaNameValue, Token![,]>::parse_terminated);
    let ffi_name = match value_for_meta_key(&item_names, "ffi") {
        Some(Lit::Str(name_str)) => name_str.value(),
        Some(value) => {
            return Error::new(value.span(), "ffi name must be a string literal")
                .to_compile_error()
                .into()
        }
        None => ffi_name_from_ident(&function.sig.ident),
    };
    let jni_name = match value_for_meta_key(&item_names, "jni") {
        Some(Lit::Str(name_str)) => name_str.value(),
        Some(value) => {
            return Error::new(value.span(), "jni name must be a string literal")
                .to_compile_error()
                .into()
        }
        None => jni_name_from_ident(&function.sig.ident),
    };

    let ffi_fn = ffi_bridge_fn(ffi_name, &function.sig, result_kind);
    let jni_fn = jni_bridge_fn(jni_name, &function.sig, result_kind);

    quote!(
        #[allow(non_snake_case)]
        #function

        #ffi_fn

        #jni_fn
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
