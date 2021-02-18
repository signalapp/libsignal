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
use std::fmt::Display;
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
                quote! {
                    let mut #name = <#ty as ffi::ArgTypeInfo>::borrow(#name)?;
                    let #name = <#ty as ffi::ArgTypeInfo>::load_from(&mut #name)?
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

fn node_bridge_fn_body(
    orig_name: &Ident,
    input_args: &[(&Ident, &Type)],
    result_kind: ResultKind,
) -> TokenStream2 {
    let input_borrowing = input_args.iter().zip(0..).map(|((name, ty), i)| {
        let name_arg = format_ident!("{}_arg", name);
        let name_stored = format_ident!("{}_stored", name);
        quote! {
            // First, load each argument and "borrow" its contents from the JavaScript handle.
            let #name_arg = cx.argument::<<#ty as node::ArgTypeInfo>::ArgType>(#i)?;
            let mut #name_stored = <#ty as node::ArgTypeInfo>::borrow(&mut cx, #name_arg)?;
        }
    });

    let input_loading = input_args.iter().map(|(name, ty)| {
        let name_stored = format_ident!("{}_stored", name);
        quote! {
            // Then load the expected types from the stored values.
            let #name = <#ty as node::ArgTypeInfo>::load_from(&mut #name_stored);
        }
    });

    let env_arg = if result_kind.has_env() {
        quote!(&mut cx,)
    } else {
        quote!()
    };
    let input_names = input_args.iter().map(|(name, _ty)| name);

    quote! {
        #(#input_borrowing)*
        #(#input_loading)*
        let __result = #orig_name(#env_arg #(#input_names),*);
        Ok(node::ResultTypeInfo::convert_into(__result, &mut cx)?.upcast())
    }
}

fn node_bridge_fn_async_body(
    orig_name: &Ident,
    input_args: &[(&Ident, &Type)],
    result_kind: ResultKind,
) -> TokenStream2 {
    let input_saving = input_args.iter().zip(0..).map(|((name, ty), i)| {
        let name_arg = format_ident!("{}_arg", name);
        let name_stored = format_ident!("{}_stored", name);
        let name_guard = format_ident!("{}_guard", name);
        quote! {
            // First, load each argument and save it in a context-independent form.
            let #name_arg = cx.borrow_mut().argument::<<#ty as node::AsyncArgTypeInfo>::ArgType>(#i)?;
            let #name_stored = <#ty as node::AsyncArgTypeInfo>::save(&mut cx.borrow_mut(), #name_arg)?;
            // Make sure we Finalize any arguments we've loaded if there's an error.
            let mut #name_guard = scopeguard::guard(#name_stored, |#name_stored| {
                neon::prelude::Finalize::finalize(#name_stored, &mut *cx.borrow_mut())
            });
        }
    });

    let input_unwrapping = input_args.iter().map(|(name, _ty)| {
        let name_stored = format_ident!("{}_stored", name);
        let name_guard = format_ident!("{}_guard", name);
        quote! {
            // Okay, we've loaded all the arguments; we can't fail from here on out.
            let mut #name_stored = scopeguard::ScopeGuard::into_inner(#name_guard);
        }
    });

    let input_loading = input_args.iter().map(|(name, ty)| {
        let name_stored = format_ident!("{}_stored", name);
        quote! {
            // Inside the future, we load the expected types from the stored values.
            let #name = <#ty as node::AsyncArgTypeInfo>::load_from(&mut #name_stored);
        }
    });

    let env_arg = if result_kind.has_env() {
        quote!(node::AsyncEnv,)
    } else {
        quote!()
    };
    let input_names = input_args.iter().map(|(name, _ty)| name);

    let input_finalization = input_args.iter().map(|(name, _ty)| {
        let name_stored = format_ident!("{}_stored", name);
        quote! {
            // Clean up all the stored values at the end.
            neon::prelude::Finalize::finalize(#name_stored, cx);
        }
    });

    quote! {
        // Use a RefCell so that the early-exit cleanup functions can reference the context
        // without taking ownership.
        let cx = std::cell::RefCell::new(cx);
        #(#input_saving)*
        #(#input_unwrapping)*
        Ok(signal_neon_futures::promise(
            &mut cx.into_inner(),
            std::panic::AssertUnwindSafe(async move {
                #(#input_loading)*
                let __result = #orig_name(#env_arg #(#input_names),*).await;
                signal_neon_futures::settle_promise(move |cx| {
                    let mut cx = scopeguard::guard(cx, |cx| {
                        #(#input_finalization)*
                    });
                    node::ResultTypeInfo::convert_into(__result, *cx)
                })
            })
        )?.upcast())
    }
}

fn node_bridge_fn(name: String, sig: &Signature, result_kind: ResultKind) -> TokenStream2 {
    let name_with_prefix = format_ident!("node_{}", name);
    let name_without_prefix = Ident::new(&name, Span::call_site());

    let result_type_format = if sig.asyncness.is_some() {
        |ty: &dyn Display| format!("Promise<{}>", ty)
    } else {
        |ty: &dyn Display| format!("{}", ty)
    };
    let result_type_str = match (result_kind, &sig.output) {
        (ResultKind::Regular, ReturnType::Default) => result_type_format(&"()"),
        (ResultKind::Regular, ReturnType::Type(_, ty)) => result_type_format(&quote!(#ty)),
        (ResultKind::Void, _) => result_type_format(&"()"),
        (ResultKind::Buffer, ReturnType::Type(_, _)) => result_type_format(&"Buffer"),
        (ResultKind::Buffer, ReturnType::Default) => {
            return Error::new(
                sig.paren_token.span,
                "missing result type for bridge_fn_buffer",
            )
            .to_compile_error()
        }
    };

    let input_args: Result<Vec<_>> = sig
        .inputs
        .iter()
        .skip(if result_kind.has_env() { 1 } else { 0 })
        .map(|arg| match arg {
            FnArg::Receiver(tokens) => Err(Error::new(
                tokens.self_token.span,
                "cannot have 'self' parameter",
            )),
            FnArg::Typed(PatType {
                attrs: _,
                pat: box Pat::Ident(name),
                colon_token: _,
                ty,
            }) => Ok((&name.ident, &**ty)),
            FnArg::Typed(PatType { pat, .. }) => {
                Err(Error::new(pat.span(), "cannot use patterns in parameter"))
            }
        })
        .collect();

    let input_args = match input_args {
        Ok(args) => args,
        Err(error) => return error.to_compile_error(),
    };

    let body = match sig.asyncness {
        Some(_) => node_bridge_fn_async_body(&sig.ident, &input_args, result_kind),
        None => node_bridge_fn_body(&sig.ident, &input_args, result_kind),
    };

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
