//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use heck::{ToSnakeCase, ToUpperCamelCase};
use proc_macro2::TokenStream as TokenStream2;
use quote::*;
use syn::spanned::Spanned;
use syn::*;
use syn_mid::Signature;

use crate::util::{extract_arg_names_and_types, result_type};
use crate::{BridgingKind, ResultInfo, ResultKind};

pub(crate) fn bridge_fn(
    name: &str,
    sig: &Signature,
    result_info: ResultInfo,
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
        BridgingKind::Regular => match (result_info.kind, &sig.output) {
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
        BridgingKind::Regular => bridge_fn_body(sig, &input_names_and_types, result_info.kind),
        BridgingKind::Io { runtime } => bridge_io_body(&sig.ident, &input_names_and_types, runtime),
    };

    Ok(quote! {
        #[cfg(feature = "ffi")]
        #[unsafe(export_name = concat!(env!("LIBSIGNAL_BRIDGE_FN_PREFIX_FFI"), #name))]
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
                stringify!(#orig_name),
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

/// Generates a struct of C functions and a context pointer to serve as the bridged representation
/// of a trait.
///
/// The struct will be named "Ffi{MyTrait}Struct", and will have helper types for each callback
/// function as "Ffi{MyTrait}{OperationCamelCase}", plus one extra callback "Ffi{MyTrait}Destroy".
/// The struct will implement the original trait as well as `ffi::FfiDestroyable`. The original
/// trait will also be implemented for `ffi::OwnedCallbackStruct<Ffi{MyTrait}Struct>`, so that
/// `Box<dyn {MyTrait}>` handles cleanup properly.
pub(crate) fn bridge_trait(trait_to_bridge: &ItemTrait) -> Result<TokenStream2> {
    let trait_name = &trait_to_bridge.ident;
    let struct_name = format_ident!("Ffi{}Struct", trait_to_bridge.ident);
    let destroy_name = format_ident!("Ffi{}Destroy", trait_to_bridge.ident);

    let callbacks = trait_to_bridge
        .items
        .iter()
        .map(|item| bridge_callback_item(trait_name, item))
        .collect::<Result<Vec<_>>>()?;
    let callback_aliases = callbacks.iter().map(|c| &c.alias);
    let callback_fields = callbacks.iter().map(|c| &c.field);
    let callback_impls = callbacks.iter().map(|c| &c.implementation);
    let callback_forwarding_impls = callbacks.iter().map(|c| &c.forwarding_impl);

    Ok(quote! {
        // Aliases for the callback functions.
        #[cfg(feature = "ffi")]
        pub type #destroy_name = extern "C" fn(ctx: *mut std::ffi::c_void);
        #(
            #[cfg(feature = "ffi")]
            pub #callback_aliases;
        )*

        // The struct of callbacks, plus an opaque context pointer, in usual C style.
        //
        // This could be Copy as well, all C structs are Copy,
        // but leaving it out makes it clearer how manual ownership is being transferred.
        #[cfg(feature = "ffi")]
        #[derive(Clone)]
        #[repr(C)]
        pub struct #struct_name {
            ctx: *mut std::ffi::c_void,
            #(#callback_fields,)*
            destroy: #destroy_name,
        }

        #[cfg(feature = "ffi")]
        impl ffi::FfiDestroyable for #struct_name {
            fn destroy(&mut self) {
                (self.destroy)(self.ctx);
            }
        }

        #[cfg(feature = "ffi")]
        impl #trait_name for #struct_name {
            #(#callback_impls)*
        }

        #[cfg(feature = "ffi")]
        impl #trait_name for ffi::OwnedCallbackStruct<#struct_name> {
            #(#callback_forwarding_impls)*
        }
    })
}

struct Callback {
    alias: TokenStream2,
    field: TokenStream2,
    implementation: TokenStream2,
    forwarding_impl: TokenStream2,
}

fn bridge_callback_item(trait_name: &Ident, item: &TraitItem) -> Result<Callback> {
    let TraitItem::Fn(item) = item else {
        return Err(Error::new(item.span(), "only fns are supported"));
    };

    let sig = &item.sig;
    let req_name = &item.sig.ident;
    let result_info = ResultInfo::from(&sig.output);
    let result_ty = result_type(&sig.output);

    // type FfiMyTraitOperation = extern "C" fn(ctx: *mut c_void, foo: ffi_result_type!(u32)) -> c_int
    let callback_ty_name = format_ident!(
        "Ffi{}{}",
        trait_name,
        req_name.to_string().to_upper_camel_case(),
        span = req_name.span()
    );
    let callback_args = item.sig.inputs.iter().filter_map(|arg| match arg {
        FnArg::Receiver(_) => match result_info.kind {
            ResultKind::Regular => Some(quote!(out: *mut ffi_arg_type!(#result_ty))),
            ResultKind::Void => None,
        },
        FnArg::Typed(arg) => {
            let Pat::Ident(arg_name) = &*arg.pat else {
                // We'll error about this elsewhere.
                return None;
            };
            let ty = &arg.ty;
            Some(quote!(#arg_name: ffi_result_type!(#ty)))
        }
    });
    let alias = quote! {
        type #callback_ty_name = extern "C" fn(
            ctx: *mut std::ffi::c_void,
            #(#callback_args,)*
        ) -> std::ffi::c_int // note the lack of trailing semicolon
    };

    // operation: FfiMyTraitOperation
    let field_name = &req_name;
    let field = quote! {
        #field_name: #callback_ty_name // note the lack of trailing comma
    };

    // fn operation(foo: u32) {
    //   ffi::CallbackError::log_on_error(
    //       "operation"
    //       (self.operation)(self.ctx, ffi::ResultTypeInfo::convert_into(foo).expect("can convert"))
    //   )
    // }
    let out_ptr_arg = match result_info.kind {
        ResultKind::Regular => quote!(, __result.as_mut_ptr()), // note the LEADING comma
        ResultKind::Void => quote!(),
    };
    let arg_conversions = item.sig.inputs.iter().map(|arg| match arg {
        FnArg::Receiver(_) => quote!(self.ctx #out_ptr_arg),
        FnArg::Typed(arg) => {
            let Pat::Ident(arg_name) = &*arg.pat else {
                return Error::new(arg.pat.span(), "only simple argument syntax is supported")
                    .into_compile_error();
            };
            quote! {
                // Note that we use *Result*TypeInfo for callback arguments,
                // since we are passing values from Rust into C.
                ffi::ResultTypeInfo::convert_into(#arg_name)
                    .expect(concat!("can convert argument for ", stringify!(#req_name)))
            }
        }
    });
    let implementation = if result_info.failable {
        quote! {
            // #sig carries everything from `fn` to the return type and possible where-clause.
            // All we provide is the body.
            #sig {
                let mut __result = std::mem::MaybeUninit::zeroed();
                ffi::CallbackError::check((self.#field_name)(#(#arg_conversions,)*))
                    .map_err(|e| WithContext {
                        operation: stringify!(#req_name),
                        inner: e
                    })?;
                <<#result_ty as ResultLike>::Success as ffi::CallbackResultTypeInfo>::convert_from_callback(
                    // SAFETY: if the C function returns 0 (success), they had better initialize this.
                    // (Exception: a void function has no out-parameter, but `()` is trivially initialized.)
                    unsafe { __result.assume_init() }
                ).map_err(|e| WithContext {
                    operation: stringify!(#req_name),
                    inner: e
                }.into())
            }
        }
    } else {
        quote! {
            #sig {
                // Not implemented: callbacks that *do* have a return value but *don't* have a place for errors.
                // We can handle those some if we need them.
                ffi::CallbackError::log_on_error(
                    stringify!(#req_name),
                    (self.#field_name)(#(#arg_conversions,)*)
                )
            }
        }
    };

    // fn operation(foo: u32) {
    //   self.0.operation(foo)
    // }
    let arg_names = item.sig.inputs.iter().filter_map(|arg| match arg {
        FnArg::Receiver(_) => None,
        FnArg::Typed(arg) => {
            let Pat::Ident(arg_name) = &*arg.pat else {
                // We'll error about this elsewhere.
                return None;
            };
            Some(arg_name)
        }
    });
    let forwarding_impl = quote! {
        #[inline]
        #sig {
            self.0.#req_name(#(#arg_names),*)
        }
    };

    Ok(Callback {
        alias,
        field,
        implementation,
        forwarding_impl,
    })
}
