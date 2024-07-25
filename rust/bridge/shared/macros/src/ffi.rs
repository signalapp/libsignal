//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use heck::ToSnakeCase;
use proc_macro2::TokenStream as TokenStream2;
use quote::*;
use syn::*;
use syn_mid::Signature;

use crate::util::{extract_arg_names_and_types, result_type};
use crate::{BridgingKind, ResultKind};

pub(crate) fn bridge_fn(
    name: &str,
    sig: &Signature,
    result_kind: ResultKind,
    bridging_kind: &BridgingKind,
) -> Result<TokenStream2> {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let wrapper_name = format_ident!("__bridge_fn_ffi_{}", name);

    let input_names_and_types = extract_arg_names_and_types(sig)?;

    let input_args = input_names_and_types
        .iter()
        .map(|(name, ty)| quote!(#name: ffi_arg_type!(#ty)));

    let implicit_args = match bridging_kind {
        BridgingKind::Regular => match (result_kind, &sig.output) {
            (ResultKind::Regular, ReturnType::Type(_, ty)) => {
                quote!(out: *mut ffi_result_type!(#ty),) // note the trailing comma
            }
            (ResultKind::Void, _) | (_, ReturnType::Default) => quote!(),
        },
        BridgingKind::Io { runtime } => {
            if sig.asyncness.is_none() {
                return Err(Error::new(
                    sig.ident.span(),
                    format_args!("non-async function '{}' cannot use #[bridge_io]", sig.ident),
                ));
            }
            let output = result_type(&sig.output);
            quote!(
                promise: *mut ffi::CPromise<ffi_result_type!(#output)>,
                async_runtime: ffi_arg_type!(&#runtime), // note the trailing comma
            )
        }
    };

    let body = match bridging_kind {
        BridgingKind::Regular => bridge_fn_body(sig, &input_names_and_types, result_kind),
        BridgingKind::Io { runtime } => bridge_io_body(&sig.ident, &input_names_and_types, runtime),
    };

    Ok(quote! {
        #[cfg(feature = "ffi")]
        #[export_name = concat!(env!("LIBSIGNAL_BRIDGE_FN_PREFIX_FFI"), #name)]
        pub unsafe extern "C" fn #wrapper_name(
            #implicit_args
            #(#input_args),*
        ) -> *mut ffi::SignalFfiError {
            #body
        }
    })
}

fn bridge_fn_body(
    sig: &Signature,
    input_names_and_types: &[(&Ident, &Type)],
    result_kind: ResultKind,
) -> TokenStream2 {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let orig_name = &sig.ident;

    let input_names = input_names_and_types.iter().map(|(name, _ty)| name);
    let input_processing = input_names_and_types.iter().map(|(name, ty)| {
        quote! {
            // See ffi::ArgTypeInfo for information on this two-step process.
            let mut #name = <#ty as ffi::ArgTypeInfo>::borrow(#name)?;
            let #name = <#ty as ffi::ArgTypeInfo>::load_from(&mut #name);
        }
    });

    // "Support" async operations by requiring them to complete synchronously.
    let await_if_needed = sig.asyncness.map(|_| {
        quote! {
            use ::futures_util::future::FutureExt as _;
            let __result = __result.now_or_never().unwrap();
        }
    });

    let output_processing = match (result_kind, &sig.output) {
        (_, ReturnType::Default) => quote!(),
        (ResultKind::Regular, ReturnType::Type(..)) => {
            quote!(ffi::write_result_to(out, __result)?)
        }
        (ResultKind::Void, ReturnType::Type(..)) => quote!(__result?),
    };

    quote! {
        ffi::run_ffi_safe(|| {
            #(#input_processing)*
            let __result = #orig_name(#(#input_names),*);
            #await_if_needed;
            #output_processing;
            Ok(())
        })
    }
}

fn generate_code_to_load_input(name: impl IdentFragment, ty: impl ToTokens) -> TokenStream2 {
    let name = format_ident!("{}", name);
    quote! {
        // See ffi::ArgTypeInfo for information on this two-step process.
        let mut #name = <#ty as ffi::ArgTypeInfo>::borrow(#name)?;
        let #name = <#ty as ffi::ArgTypeInfo>::load_from(&mut #name);
    }
}

fn bridge_io_body(
    orig_name: &Ident,
    input_args: &[(&Ident, &Type)],
    runtime: &Type,
) -> TokenStream2 {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let load_async_runtime = generate_code_to_load_input("async_runtime", quote!(&#runtime));
    let load_promise = quote! {
        let promise = promise.as_mut().ok_or(ffi::NullPointerError)?;
    };

    let input_saving = input_args.iter().map(|(name, ty)| {
        let name_stored = format_ident!("{}_stored", name);
        quote! {
            // "Borrow" from each argument before starting the async work
            // (it's not exactly a borrow since it has to outlive the synchronous call from C).
            // NOTE: If we want this to have different behavior from synchronous bridge_fns,
            // we can introduce an AsyncArgTypeInfo trait like Node has.
            let mut #name_stored = <#ty as ffi::ArgTypeInfo>::borrow(#name)?;
        }
    });

    let input_loading = input_args.iter().map(|(name, ty)| {
        let name_stored = format_ident!("{}_stored", name);
        quote! {
            // Inside the future, we load the expected types from the stored values.
            let #name = <#ty as ffi::ArgTypeInfo>::load_from(&mut #name_stored);
        }
    });

    let input_names = input_args.iter().map(|(name, _ty)| name);

    quote! {
        ffi::run_ffi_safe(|| {
            #load_async_runtime
            #load_promise
            #(#input_saving)*
            ffi::run_future_on_runtime(
                async_runtime,
                promise,
                |__cancel| async move {
                    let __future = ffi::catch_unwind(std::panic::AssertUnwindSafe(async move {
                        #(#input_loading)*
                        ::tokio::select! {
                            __result = #orig_name(#(#input_names),*) => {
                                // If the original function can't fail, wrap the result in Ok for uniformity.
                                // See TransformHelper::ok_if_needed.
                                Ok(TransformHelper(__result).ok_if_needed()?.0)
                            }
                            _ = __cancel => {
                                Err(ffi::FutureCancelled.into())
                            }
                        }
                    }));
                    ffi::FutureResultReporter::new(__future.await)
                }
            );
            Ok(())
        })
    }
}

pub(crate) fn name_from_ident(ident: &Ident) -> String {
    ident.to_string().to_snake_case()
}
