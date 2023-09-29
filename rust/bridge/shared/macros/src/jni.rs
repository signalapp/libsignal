//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use proc_macro2::TokenStream as TokenStream2;
use quote::*;
use syn::*;
use syn_mid::Signature;

use crate::util::{extract_arg_names_and_types, result_type};

pub(crate) fn bridge_fn(name: &str, sig: &Signature) -> Result<TokenStream2> {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    // Generate a static method on org.signal.libsignal.internal.Native.
    // This naming convention comes from JNI:
    // https://docs.oracle.com/en/java/javase/20/docs/specs/jni/design.html#resolving-native-method-names
    let name = format_ident!("Java_org_signal_libsignal_internal_Native_{}", name);
    let orig_name = &sig.ident;

    let input_names_and_types = extract_arg_names_and_types(sig)?;

    let input_names = input_names_and_types.iter().map(|(name, _ty)| name);
    let input_args = input_names_and_types
        .iter()
        .map(|(name, ty)| quote!(#name: jni_arg_type!(#ty)));
    let input_processing = input_names_and_types.iter().map(|(name, ty)| {
        quote! {
            // See jni::ArgTypeInfo for information on this two-step process.
            let mut #name = <#ty as jni::ArgTypeInfo>::borrow(env, &#name)?;
            let #name = <#ty as jni::ArgTypeInfo>::load_from(&mut #name)
        }
    });

    // "Support" async operations by requiring them to complete synchronously.
    let await_if_needed = sig.asyncness.map(|_| {
        quote! {
            let __result = __result.now_or_never().unwrap();
        }
    });

    let output = result_type(&sig.output);

    Ok(quote! {
        #[cfg(feature = "jni")]
        #[no_mangle]
        pub unsafe extern "C" fn #name<'local>(
            mut env: jni::JNIEnv<'local>,
            // We only generate static methods.
            _class: jni::JClass,
            #(#input_args),*
        ) -> jni_result_type!(#output) {
            jni::run_ffi_safe(&mut env, |env| {
                #(#input_processing);*;
                let __result = #orig_name(#(#input_names),*);
                #await_if_needed;
                jni::ResultTypeInfo::convert_into(__result, env)
            })
        }
    })
}

pub(crate) fn name_from_ident(ident: &Ident) -> String {
    ident.to_string().replace('_', "_1")
}
