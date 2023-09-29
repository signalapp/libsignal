//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::*;
use syn::*;
use syn_mid::Signature;

use crate::util::{extract_arg_names_and_types, result_type};

fn bridge_fn_body(orig_name: &Ident, input_args: &[(&Ident, &Type)]) -> TokenStream2 {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let input_processing = input_args.iter().zip(0..).map(|((name, ty), i)| {
        let name_arg = format_ident!("{}_arg", name);
        let name_stored = format_ident!("{}_stored", name);
        quote! {
            // First, get the argument from Neon.
            let #name_arg = cx.argument::<<#ty as node::ArgTypeInfo>::ArgType>(#i)?;
            // Then load the value; see node::ArgTypeInfo for more information.
            let mut #name_stored = <#ty as node::ArgTypeInfo>::borrow(&mut cx, #name_arg)?;
            let #name = <#ty as node::ArgTypeInfo>::load_from(&mut #name_stored);
        }
    });

    let input_names = input_args.iter().map(|(name, _ty)| name);

    quote! {
        #(#input_processing)*
        let __result = #orig_name(#(#input_names),*);
        match TransformHelper(__result).ok_if_needed() {
            Ok(TransformHelper(success)) =>
                Ok(node::ResultTypeInfo::convert_into(success, &mut cx)?.upcast()),
            Err(failure) => {
                let module = cx.this();
                node::SignalNodeError::throw(failure, &mut cx, module, stringify!(#orig_name))
            }
        }
    }
}

fn bridge_fn_async_body(
    orig_name: &Ident,
    custom_name: &str,
    input_args: &[(&Ident, &Type)],
) -> TokenStream2 {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    fn storage_ident_for(name: &Ident) -> Ident {
        format_ident!("{}_stored", name)
    }
    fn scopeguard_ident_for(name: &Ident) -> Ident {
        format_ident!("{}_guard", name)
    }

    let input_saving = input_args.iter().zip(0..).map(|((name, ty), i)| {
        let name_arg = format_ident!("{}_arg", name);
        let name_stored = storage_ident_for(name);
        let name_guard = scopeguard_ident_for(name);
        quote! {
            // First, load each argument and save it in a context-independent form.
            // See node::AsyncArgTypeInfo for more information.
            let #name_arg = cx.borrow_mut().argument::<<#ty as node::AsyncArgTypeInfo>::ArgType>(#i)?;
            let #name_stored = <#ty as node::AsyncArgTypeInfo>::save_async_arg(&mut cx.borrow_mut(), #name_arg)?;
            // Make sure we Finalize any arguments we've loaded if there's an error.
            // Otherwise we could leak global references to JS objects.
            let mut #name_guard = scopeguard::guard(#name_stored, |#name_stored| {
                neon::prelude::Finalize::finalize(#name_stored, &mut *cx.borrow_mut())
            });
        }
    });

    let input_unwrapping = input_args.iter().map(|(name, _ty)| {
        let name_stored = storage_ident_for(name);
        let name_guard = scopeguard_ident_for(name);
        quote! {
            // Okay, we've loaded all the arguments; we can't fail from here on out.
            let mut #name_stored = scopeguard::ScopeGuard::into_inner(#name_guard);
        }
    });

    let input_loading = input_args.iter().map(|(name, ty)| {
        let name_stored = storage_ident_for(name);
        quote! {
            // Inside the future, we load the expected types from the stored values.
            let #name = <#ty as node::AsyncArgTypeInfo>::load_async_arg(&mut #name_stored);
        }
    });

    let input_names = input_args.iter().map(|(name, _ty)| name);

    let input_finalization = input_args.iter().map(|(name, _ty)| {
        let name_stored = storage_ident_for(name);
        quote! {
            // Clean up all the stored values at the end.
            neon::prelude::Finalize::finalize(#name_stored, cx);
        }
    });

    quote! {
        // Use a RefCell so that the early-exit cleanup functions can reference the Neon context
        // without taking ownership.
        let cx = std::cell::RefCell::new(cx);
        #(#input_saving)*
        #(#input_unwrapping)*
        // Okay, we're done sharing the Neon context
        let mut cx = cx.into_inner();
        // Save "this", the module that contains our errors.
        let __this = cx.this();
        let __this = neon::object::Object::root(&*__this, &mut cx);
        Ok(signal_neon_futures::promise(
            &mut cx,
            std::panic::AssertUnwindSafe(async move {
                #(#input_loading)*
                let __result = #orig_name(#(#input_names),*).await;
                // Send the result back to JavaScript.
                signal_neon_futures::settle_promise(move |cx| {
                    // Make sure we clean up our arguments even if we early-exit or panic.
                    // (Hopefully it's not Neon that panics...)
                    let mut cx = scopeguard::guard(cx, |cx| {
                        #(#input_finalization)*
                    });
                    let __this = __this.into_inner(*cx);
                    match __result {
                        Ok(success) => Ok(
                            node::ResultTypeInfo::convert_into(success, *cx)?.upcast(),
                        ),
                        Err(failure) => node::SignalNodeError::throw(
                            failure,
                            *cx,
                            __this,
                            #custom_name,
                        ),
                    }
                })
            })
        )?.upcast())
    }
}

pub(crate) fn bridge_fn(name: &str, sig: &Signature) -> Result<TokenStream2> {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let name_with_prefix = format_ident!("node_{}", name);
    let name_without_prefix = Ident::new(name, Span::call_site());

    let ts_signature_comment = generate_ts_signature_comment(name, sig);

    let input_args = extract_arg_names_and_types(sig)?;

    let body = match sig.asyncness {
        Some(_) => bridge_fn_async_body(&sig.ident, name, &input_args),
        None => bridge_fn_body(&sig.ident, &input_args),
    };

    Ok(quote! {
        #[cfg(feature = "node")]
        #[allow(non_snake_case)]
        #[doc = #ts_signature_comment]
        pub fn #name_with_prefix(
            mut cx: node::FunctionContext,
        ) -> node::JsResult<node::JsValue> {
            #body
        }

        #[cfg(feature = "node")]
        node_register!(#name_without_prefix);
    })
}

/// Generates a string, containing the *Rust* signature of a bridged function, that gen_ts_decl.py
/// can use to generate Native.d.ts.
fn generate_ts_signature_comment(name_without_prefix: &str, sig: &Signature) -> String {
    let ts_args: Vec<_> = sig
        .inputs
        .iter()
        .map(|arg| quote!(#arg).to_string())
        .collect();

    let result_type_format = if sig.asyncness.is_some() {
        |ty| format!("Promise<{}>", ty)
    } else {
        |ty| format!("{}", ty)
    };
    let result_type_str = result_type_format(result_type(&sig.output));

    format!(
        "ts: export function {}({}): {}",
        name_without_prefix,
        ts_args.join(", "),
        result_type_str
    )
}

pub(crate) fn name_from_ident(ident: &Ident) -> String {
    ident.to_string()
}
