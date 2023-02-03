//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use proc_macro2::TokenStream as TokenStream2;
use quote::*;
use syn::spanned::Spanned;
use syn::*;
use syn_mid::{FnArg, Pat, PatType, Signature};
use unzip3::Unzip3;

use crate::ResultKind;

pub(crate) fn bridge_fn(name: String, sig: &Signature, result_kind: ResultKind) -> TokenStream2 {
    let name = format_ident!("Java_org_signal_libsignal_internal_Native_{}", name);

    let output = match (result_kind, &sig.output) {
        (ResultKind::Regular, ReturnType::Default) => quote!(),
        (ResultKind::Regular, ReturnType::Type(_, ty)) => quote!(-> jni_result_type!(#ty)),
        (ResultKind::Void, _) => quote!(),
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
                        quote!(#(#attrs)* #name #colon_token jni_arg_type!(#ty)),
                        quote! {
                            let mut #name = <#ty as jni::ArgTypeInfo>::borrow(&env, #name)?;
                            let #name = <#ty as jni::ArgTypeInfo>::load_from(&env, &mut #name)?
                        },
                    )
                } else {
                    (
                        Ident::new("unexpected", pat.span()),
                        Error::new(pat.span(), "cannot use patterns in parameter")
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
            env: jni::JNIEnv,
            _class: jni::JClass,
            #(#input_args),*
        ) #output {
            jni::run_ffi_safe(&env, || {
                #(#input_processing);*;
                let __result = #orig_name(#(#input_names),*);
                #await_if_needed;
                jni::ResultTypeInfo::convert_into(__result, &env)
            })
        }
    }
}

pub(crate) fn name_from_ident(ident: &Ident) -> String {
    ident.to_string().replace('_', "_1")
}
