//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::*;
use std::fmt::Display;
use syn::spanned::Spanned;
use syn::*;
use syn_mid::{FnArg, Pat, PatType, Signature};

use crate::ResultKind;

fn bridge_fn_body(orig_name: &Ident, input_args: &[(&Ident, &Type)]) -> TokenStream2 {
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

    let input_names = input_args.iter().map(|(name, _ty)| name);

    quote! {
        #(#input_borrowing)*
        #(#input_loading)*
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
    custom_name: &String,
    input_args: &[(&Ident, &Type)],
) -> TokenStream2 {
    let input_saving = input_args.iter().zip(0..).map(|((name, ty), i)| {
        let name_arg = format_ident!("{}_arg", name);
        let name_stored = format_ident!("{}_stored", name);
        let name_guard = format_ident!("{}_guard", name);
        quote! {
            // First, load each argument and save it in a context-independent form.
            let #name_arg = cx.borrow_mut().argument::<<#ty as node::AsyncArgTypeInfo>::ArgType>(#i)?;
            let #name_stored = <#ty as node::AsyncArgTypeInfo>::save_async_arg(&mut cx.borrow_mut(), #name_arg)?;
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
            let #name = <#ty as node::AsyncArgTypeInfo>::load_async_arg(&mut #name_stored);
        }
    });

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
        let mut cx = cx.into_inner();
        let __this = cx.this();
        let __this = neon::object::Object::root(&*__this, &mut cx);
        Ok(signal_neon_futures::promise(
            &mut cx,
            std::panic::AssertUnwindSafe(async move {
                #(#input_loading)*
                let __result = #orig_name(#(#input_names),*).await;
                signal_neon_futures::settle_promise(move |cx| {
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

pub(crate) fn bridge_fn(name: String, sig: &Signature, result_kind: ResultKind) -> TokenStream2 {
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
    };

    let input_args: Result<Vec<_>> = sig
        .inputs
        .iter()
        .map(|arg| match arg {
            FnArg::Receiver(tokens) => Err(Error::new(
                tokens.self_token.span,
                "cannot have 'self' parameter",
            )),
            FnArg::Typed(PatType {
                attrs: _,
                pat,
                colon_token: _,
                ty,
            }) => {
                if let Pat::Ident(name) = pat.as_ref() {
                    Ok((&name.ident, &**ty))
                } else {
                    Err(Error::new(pat.span(), "cannot use patterns in parameter"))
                }
            }
        })
        .collect();

    let input_args = match input_args {
        Ok(args) => args,
        Err(error) => return error.to_compile_error(),
    };

    let body = match sig.asyncness {
        Some(_) => bridge_fn_async_body(&sig.ident, &name, &input_args),
        None => bridge_fn_body(&sig.ident, &input_args),
    };

    let node_annotation = format!(
        "ts: export function {}({}): {}",
        name_without_prefix,
        sig.inputs
            .iter()
            .map(|arg| quote!(#arg).to_string())
            .collect::<Vec<_>>()
            .join(", "),
        result_type_str
    );

    quote! {
        #[allow(non_snake_case)]
        #[doc = #node_annotation]
        pub fn #name_with_prefix(
            mut cx: node::FunctionContext,
        ) -> node::JsResult<node::JsValue> {
            #body
        }

        node_register!(#name_without_prefix);
    }
}

pub(crate) fn name_from_ident(ident: &Ident) -> String {
    ident.to_string()
}
