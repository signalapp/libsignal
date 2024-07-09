//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use proc_macro2::TokenStream as TokenStream2;
use quote::*;
use syn::*;
use syn_mid::Signature;

use crate::util::{extract_arg_names_and_types, result_type};
use crate::BridgingKind;

pub(crate) fn bridge_fn(
    name: &str,
    sig: &Signature,
    bridging_kind: &BridgingKind,
) -> Result<TokenStream2> {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let wrapper_name = format_ident!("__bridge_fn_jni_{}", name);
    let orig_name = &sig.ident;

    let input_names_and_types = extract_arg_names_and_types(sig)?;

    let input_args = input_names_and_types
        .iter()
        .map(|(name, ty)| quote!(#name: jni_arg_type!(#ty)));

    // "Support" async operations by requiring them to complete synchronously.
    let async_runtime_if_needed = match bridging_kind {
        BridgingKind::Regular => quote!(),
        BridgingKind::Io { runtime } => {
            if sig.asyncness.is_none() {
                return Err(Error::new(
                    sig.ident.span(),
                    format_args!("non-async function '{}' cannot use #[bridge_io]", sig.ident),
                ));
            }
            quote!(async_runtime: jni_arg_type!(&#runtime),) // Note the trailing comma!
        }
    };

    let output = result_type(&sig.output);
    let result_ty = match bridging_kind {
        BridgingKind::Regular => quote!(jni_result_type!(#output)),
        BridgingKind::Io { .. } => {
            quote!(jni::JavaCompletableFuture<'local, jni_result_type!(#output)>)
        }
    };

    let body = match bridging_kind {
        BridgingKind::Regular => {
            bridge_fn_body(orig_name, &input_names_and_types, sig.asyncness.is_some())
        }
        BridgingKind::Io { runtime } => bridge_io_body(orig_name, &input_names_and_types, runtime),
    };

    Ok(quote! {
        #[cfg(feature = "jni")]
        #[export_name = concat!(env!("LIBSIGNAL_BRIDGE_FN_PREFIX_JNI"), #name)]
        #[allow(non_snake_case)]
        pub unsafe extern "C" fn #wrapper_name<'local>(
            mut env: ::jni::JNIEnv<'local>,
            // We only generate static methods.
            _class: ::jni::objects::JClass,
            #async_runtime_if_needed
            #(#input_args),*
        ) -> #result_ty {
            #body
        }
    })
}

fn generate_code_to_load_input(name: impl IdentFragment, ty: impl ToTokens) -> TokenStream2 {
    let name = format_ident!("{}", name);
    quote! {
        // See jni::ArgTypeInfo for information on this two-step process.
        let mut #name = <#ty as jni::ArgTypeInfo>::borrow(env, &#name)?;
        let #name = <#ty as jni::ArgTypeInfo>::load_from(&mut #name);
    }
}

fn bridge_fn_body(
    orig_name: &Ident,
    input_args: &[(&Ident, &Type)],
    await_needed: bool,
) -> TokenStream2 {
    let input_names = input_args.iter().map(|(name, _ty)| name);
    let input_processing = input_args
        .iter()
        .map(|(name, ty)| generate_code_to_load_input(name, ty));

    let await_if_needed = await_needed.then(|| {
        quote! {
            #[allow(unused)]
            use ::futures_util::future::FutureExt as _;
            let __result = __result.now_or_never().unwrap();
        }
    });

    quote! {
        jni::run_ffi_safe(&mut env, |env| {
            #(#input_processing)*
            let __result = #orig_name(#(#input_names),*);
            #await_if_needed
            // If the original function can't fail, wrap the result in Ok for uniformity,
            // and then throw any errors ahead of calling convert_into.
            // See TransformHelper::ok_if_needed.
            let __result = TransformHelper(__result).ok_if_needed()?.0;
            jni::ResultTypeInfo::convert_into(__result, env).map_err(Into::into)
        })
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

    fn storage_ident_for(name: &Ident) -> Ident {
        format_ident!("{}_stored", name)
    }

    let input_saving = input_args.iter().map(|(name, ty)| {
        let name_stored = storage_ident_for(name);
        quote! {
            // "Borrow" from each argument before starting the async work
            // (it's not exactly a borrow since it has to outlive the synchronous JNI call).
            // NOTE: If we want this to have different behavior from synchronous bridge_fns,
            // we can introduce an AsyncArgTypeInfo trait like Node has.
            let mut #name_stored = <#ty as jni::ArgTypeInfo>::borrow(env, &#name)?;
        }
    });

    let input_loading = input_args.iter().map(|(name, ty)| {
        let name_stored = storage_ident_for(name);
        quote! {
            // Inside the future, we load the expected types from the stored values.
            let #name = <#ty as jni::ArgTypeInfo>::load_from(&mut #name_stored);
        }
    });

    let input_names = input_args.iter().map(|(name, _ty)| name);
    let input_stored_names = input_args.iter().map(|(name, _ty)| storage_ident_for(name));

    quote! {
        jni::run_ffi_safe(&mut env, |env| {
            #load_async_runtime
            #(#input_saving)*
            jni::run_future_on_runtime(env, async_runtime, |__cancel| async move {
                // Wrap the actual work to catch any panics.
                let __future = jni::catch_unwind(std::panic::AssertUnwindSafe(async {
                    #(#input_loading)*
                    let __result = #orig_name(#(#input_names),*).await;
                    // If the original function can't fail, wrap the result in Ok for uniformity.
                    // See TransformHelper::ok_if_needed.
                    Ok(TransformHelper(__result).ok_if_needed()?.0)
                }));
                // Pass the stored inputs to the reporter to drop them while attached to the JVM.

                jni::FutureResultReporter::new(__future.await, (#(#input_stored_names),*))
            })
        })
    }
}

pub(crate) fn name_from_ident(ident: &Ident) -> String {
    ident.to_string().replace('_', "_1")
}
