//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::*;
use syn::*;
use syn_mid::Signature;

use crate::util::{extract_arg_names_and_types, result_type};
use crate::BridgingKind;

fn bridge_fn_body(orig_name: &Ident, input_args: &[(&Ident, &Type)]) -> TokenStream2 {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let input_processing = input_args
        .iter()
        .zip(0..)
        .map(|((name, ty), i)| generate_code_to_load_input(name, ty, i));

    let input_names = input_args.iter().map(|(name, _ty)| name);

    quote! {
        #(#input_processing)*
        let __result = #orig_name(#(#input_names),*);
        match TransformHelper(__result).ok_if_needed() {
            Ok(TransformHelper(success)) =>
                Ok(node::ResultTypeInfo::convert_into(success, &mut cx)?.upcast()),
            Err(failure) => {
                let module = cx.this()?;
                let throwable = node::SignalNodeError::into_throwable(failure, &mut cx, module, stringify!(#orig_name));
                neon::context::Context::throw(&mut cx, throwable)?
            }
        }
    }
}

/// Produces code to synchronously load an input of type `ty` from argument #`arg_index` into a
/// local variable named `name`.
///
/// "Synchronously load" = "using `node::ArgTypeInfo`"
fn generate_code_to_load_input(
    name: impl IdentFragment,
    ty: impl ToTokens,
    arg_index: usize,
) -> TokenStream2 {
    let name = format_ident!("{}", name);
    let name_arg = format_ident!("{}_arg", name);
    let name_stored = format_ident!("{}_stored", name);
    quote! {
        // First, get the argument from Neon.
        let #name_arg = cx.argument::<<#ty as node::ArgTypeInfo>::ArgType>(#arg_index)?;
        // Then load the value; see node::ArgTypeInfo for more information.
        let mut #name_stored = <#ty as node::ArgTypeInfo>::borrow(&mut cx, #name_arg)?;
        let #name = <#ty as node::ArgTypeInfo>::load_from(&mut #name_stored);
    }
}

fn bridge_fn_async_body(
    orig_name: &Ident,
    custom_name: &str,
    kind: &BridgingKind,
    input_args: &[(&Ident, &Type)],
) -> TokenStream2 {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let implicit_arg_count: usize = match kind {
        BridgingKind::Regular => 0,
        BridgingKind::Io { .. } => 1,
    };

    let set_up_async_runtime = match kind {
        BridgingKind::Regular => quote! {
            let async_runtime = &node::ChannelOnItsOriginalThread::new(&mut cx);
        },
        BridgingKind::Io { runtime } => {
            generate_code_to_load_input("async_runtime", quote!(&#runtime), 0)
        }
    };

    fn storage_ident_for(name: &Ident) -> Ident {
        format_ident!("{}_stored", name)
    }
    fn scopeguard_ident_for(name: &Ident) -> Ident {
        format_ident!("{}_guard", name)
    }

    let input_saving = input_args.iter().zip(implicit_arg_count..).map(|((name, ty), i)| {
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

    // Chunk the input storage in groups of 8, which is the largest tuple size Neon supports
    // Finalize for.
    let inputs_to_finalize = input_args.chunks(8).map(|chunk| {
        let names_stored = chunk.iter().map(|(name, _ty)| storage_ident_for(name));
        quote!((#(#names_stored),*))
    });

    quote! {
        #set_up_async_runtime
        // Use a RefCell so that the early-exit cleanup functions can reference the Neon context
        // without taking ownership.
        let cx = std::cell::RefCell::new(cx);
        #(#input_saving)*
        #(#input_unwrapping)*
        // Okay, we're done sharing the Neon context
        let mut cx = cx.into_inner();
        Ok(node::run_future_on_runtime(
            &mut cx,
            async_runtime,
            #custom_name,
            |__cancel| async move {
                // Wrap the actual work to catch any panics.
                let __future = node::catch_unwind(std::panic::AssertUnwindSafe(async {
                    #(#input_loading)*
                    ::tokio::select! {
                        __result = #orig_name(#(#input_names),*) => {
                            // If the original function can't fail, wrap the result in Ok for uniformity.
                            // See TransformHelper::ok_if_needed.
                            Ok(TransformHelper(__result).ok_if_needed().map(|x| x.0))
                        }
                        _ = __cancel => {
                            Err(node::CancellationError)
                        }
                    }
            }));
                // Pass the stored inputs to the reporter to finalize them before reporting the result.
                node::FutureResultReporter::new(
                    __future.await,
                    (#(#inputs_to_finalize),*)
                )
            }
        )?.upcast())
    }
}

pub(crate) fn bridge_fn(
    name: &str,
    sig: &Signature,
    bridging_kind: &BridgingKind,
) -> Result<TokenStream2> {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let name_with_prefix = format_ident!("node_{}", name);
    let name_without_prefix = Ident::new(name, Span::call_site());

    let ts_signature_comment = generate_ts_signature_comment(name, sig, bridging_kind);

    let input_args = extract_arg_names_and_types(sig)?;

    let body = match (sig.asyncness, bridging_kind) {
        (Some(_), _) => bridge_fn_async_body(&sig.ident, name, bridging_kind, &input_args),
        (None, BridgingKind::Regular) => bridge_fn_body(&sig.ident, &input_args),
        (None, BridgingKind::Io { .. }) => {
            return Err(Error::new(
                sig.ident.span(),
                format_args!("non-async function '{}' cannot use #[bridge_io]", sig.ident),
            ));
        }
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
fn generate_ts_signature_comment(
    name_without_prefix: &str,
    sig: &Signature,
    bridging_kind: &BridgingKind,
) -> String {
    let mut ts_args = vec![];
    match bridging_kind {
        BridgingKind::Regular => {}
        BridgingKind::Io { runtime } => {
            ts_args.push(format!("async_runtime: &{}", runtime.to_token_stream()))
        }
    }
    ts_args.extend(
        sig.inputs
            .iter()
            .map(|arg| arg.to_token_stream().to_string()),
    );

    let result_type_format = match (sig.asyncness, bridging_kind) {
        (Some(_), BridgingKind::Io { .. }) => |ty| format!("CancellablePromise<{}>", ty),
        (Some(_), _) => |ty| format!("Promise<{}>", ty),
        (None, _) => |ty| format!("{}", ty),
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
