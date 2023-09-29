//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use heck::SnakeCase;
use proc_macro2::TokenStream as TokenStream2;
use quote::*;
use syn::*;
use syn_mid::Signature;

use crate::util::extract_arg_names_and_types;
use crate::ResultKind;

pub(crate) fn bridge_fn(
    name: &str,
    sig: &Signature,
    result_kind: ResultKind,
) -> Result<TokenStream2> {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let name = format_ident!("signal_{}", name);
    let orig_name = &sig.ident;

    let input_names_and_types = extract_arg_names_and_types(sig)?;

    let input_names = input_names_and_types.iter().map(|(name, _ty)| name);
    let input_args = input_names_and_types
        .iter()
        .map(|(name, ty)| quote!(#name: ffi_arg_type!(#ty)));
    let input_processing = input_names_and_types.iter().map(|(name, ty)| {
        quote! {
            // See ffi::ArgTypeInfo for information on this two-step process.
            let mut #name = <#ty as ffi::ArgTypeInfo>::borrow(#name)?;
            let #name = <#ty as ffi::ArgTypeInfo>::load_from(&mut #name)?
        }
    });

    // "Support" async operations by requiring them to complete synchronously.
    let await_if_needed = sig.asyncness.map(|_| {
        quote! {
            let __result = __result.now_or_never().unwrap();
        }
    });

    let (output_arg_if_needed, output_processing) = match (result_kind, &sig.output) {
        (_, ReturnType::Default) => (quote!(), quote!()),
        (ResultKind::Regular, ReturnType::Type(_, ty)) => (
            quote!(out: *mut ffi_result_type!(#ty),), // note the trailing comma
            quote!(ffi::write_result_to(out, __result)?),
        ),
        (ResultKind::Void, ReturnType::Type(_, _)) => (quote!(), quote!(__result?)),
    };

    Ok(quote! {
        #[cfg(feature = "ffi")]
        #[no_mangle]
        pub unsafe extern "C" fn #name(
            #output_arg_if_needed
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
    })
}

pub(crate) fn name_from_ident(ident: &Ident) -> String {
    ident.to_string().to_snake_case()
}
