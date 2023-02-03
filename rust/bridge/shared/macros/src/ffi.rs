//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use heck::SnakeCase;
use proc_macro2::TokenStream as TokenStream2;
use quote::*;
use syn::spanned::Spanned;
use syn::*;
use syn_mid::{FnArg, Pat, PatType, Signature};
use unzip3::Unzip3;

use crate::ResultKind;

pub(crate) fn bridge_fn(name: String, sig: &Signature, result_kind: ResultKind) -> TokenStream2 {
    let name = format_ident!("signal_{}", name);

    let (output_args, output_processing) = match (result_kind, &sig.output) {
        (_, ReturnType::Default) => (quote!(), quote!()),
        (ResultKind::Regular, ReturnType::Type(_, ty)) => (
            quote!(out: *mut ffi_result_type!(#ty),), // note the trailing comma
            quote!(ffi::write_result_to(out, __result)?),
        ),
        (ResultKind::Void, ReturnType::Type(_, _)) => (quote!(), quote!(__result?;)),
    };

    let await_if_needed = sig.asyncness.map(|_| {
        quote! {
            let __result = __result.now_or_never().unwrap();
        }
    });

    let (input_names, input_args, input_processing): (Vec<_>, Vec<_>, Vec<_>) = sig
        .inputs
        .iter()
        .map(|arg| match arg {
            FnArg::Receiver(tokens) => (
                Ident::new("self", tokens.self_token.span),
                Error::new(tokens.self_token.span, "cannot have 'self' parameter")
                    .to_compile_error(),
                quote!(),
            ),
            FnArg::Typed(PatType {
                attrs,
                pat,
                colon_token,
                ty,
            }) => {
                if let Pat::Ident(name) = pat.as_ref() {
                    (
                        name.ident.clone(),
                        quote!(#(#attrs)* #name #colon_token ffi_arg_type!(#ty)),
                        quote! {
                            let mut #name = <#ty as ffi::ArgTypeInfo>::borrow(#name)?;
                            let #name = <#ty as ffi::ArgTypeInfo>::load_from(&mut #name)?
                        },
                    )
                } else {
                    (
                        Ident::new("unexpected", arg.span()),
                        Error::new(arg.span(), "cannot use patterns in parameter")
                            .to_compile_error(),
                        quote!(),
                    )
                }
            }
        })
        .unzip3();

    let orig_name = sig.ident.clone();

    quote! {
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            #output_args
            #(#input_args),*
        ) -> *mut ffi::SignalFfiError {
            ffi::run_ffi_safe(|| {
                #(#input_processing);*;
                let __result = #orig_name(#(#input_names),*);
                #await_if_needed;
                #output_processing;
                Ok(())
            })
        }
    }
}

pub(crate) fn name_from_ident(ident: &Ident) -> String {
    ident.to_string().to_snake_case()
}
