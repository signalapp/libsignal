//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use heck::ToLowerCamelCase as _;
use itertools::Itertools as _;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::*;
use syn::spanned::Spanned as _;
use syn::*;
use syn_mid::Signature;

use crate::BridgingKind;
use crate::util::{crates, extract_arg_names_and_types, result_type};

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
                let throwable = node::SignalNodeError::into_throwable(failure, &mut cx, stringify!(#orig_name));
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
    nice: bool,
) -> Result<TokenStream2> {
    // Scroll down to the end of the function to see the quote template.
    // This is the best way to understand what we're trying to produce.

    let name_with_prefix = format_ident!("node_{}", name);
    let name_without_prefix = Ident::new(name, Span::call_site());

    let input_args = extract_arg_names_and_types(sig)?;
    let ts_metadata = generate_ts_metadata(
        name,
        sig.asyncness.is_some(),
        &input_args,
        result_type(&sig.output),
        bridging_kind,
        nice,
    );

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
        pub fn #name_with_prefix(
            mut cx: node::FunctionContext,
        ) -> node::JsResult<node::JsValue> {
            #body
        }
        #[cfg(all(feature = "metadata", feature = "node"))]
        #ts_metadata

        #[cfg(feature = "node")]
        node_register!(#name_without_prefix);
    })
}

/// Generates the code to embed `libsignal_bridge_types::metadata` metadata
fn generate_ts_metadata(
    name_without_prefix: &str,
    asyncness: bool,
    input_args: &[(&Ident, &Type)],
    result_type: TokenStream2,
    bridging_kind: &BridgingKind,
    nice: bool,
) -> TokenStream2 {
    let krate = crates::libsignal_bridge_types();
    let (argument_names, argument_types): (Vec<_>, Vec<_>) = input_args
        .iter()
        .map(|(name, ty)| (name.to_string(), ty.to_token_stream()))
        .unzip();
    let return_type_format = match (asyncness, bridging_kind) {
        (true, BridgingKind::Io { .. }) => "CancellablePromise<{return_type}>",
        (true, _) => "Promise<{return_type}>",
        (false, _) => "{return_type}",
    };
    let md = quote!(#krate::metadata);
    let metadata_name = format_ident!("_BRIDGE_NODE_METADATA_{name_without_prefix}");
    let type_info_trait = if asyncness {
        quote!(AsyncArgTypeInfo)
    } else {
        quote!(ArgTypeInfo)
    };
    let nice_metadata = if nice {
        quote! {
            let mut arguments = Vec::new();
            #(arguments.push((
                #argument_names.into(),
                <#argument_types as #krate::node::NiceArgConverter>::register_ts_arg_converter(ctx)
            ));)*
            let return_type: ResultMetadataTransformHelper<#result_type> = Default::default();
            let return_type = return_type.register_ts_result_converter(ctx);
            ctx.nice_functions.insert(
                #name_without_prefix.into(),
                #md::node::NiceFunction {
                    is_tokio_async: #asyncness,
                    arguments,
                    return_type,
                },
            );
        }
    } else {
        quote!()
    };
    let async_runtime_argument = match bridging_kind {
        BridgingKind::Regular => quote!(),
        BridgingKind::Io { runtime } => quote! {
            arguments.push((
                "asyncRuntime".into(),
                <&#runtime as #krate::node::#type_info_trait>::register_ts_ffi_type(ctx)
            ));
        },
    };
    quote! {
        #[#md::linkme::distributed_slice(#md::node::NODE_ITEMS)]
        #[linkme(crate = #md::linkme)]
        static #metadata_name: #md::FnWithModule<#md::node::TsMetadataContext> = #md::FnWithModule {
            module_path: module_path!(),
            apply: |ctx| {
                use #md::node::result_type_helper::*;
                let return_type: ResultMetadataTransformHelper<#result_type> = Default::default();
                let return_type = return_type.register_ts_ffi_type(ctx);
                let mut arguments = Vec::new();
                #async_runtime_argument
                #(arguments.push((
                    #argument_names.into(),
                    <#argument_types as #krate::node::#type_info_trait>::register_ts_ffi_type(ctx)
                ));)*
                ctx.native_functions.insert(
                    #name_without_prefix.into(),
                    #md::node::NativeFunction { arguments, return_type: format!(#return_type_format) },
                );
                #nice_metadata
            },
        };
    }
}

fn to_lower_camel_case_preserve_underscores(x: &str) -> String {
    let x_sans_underscore = x.trim_start_matches('_');
    let core = x_sans_underscore.to_lower_camel_case();
    format!("{}{core}", &x[0..(x.len() - x_sans_underscore.len())])
}

pub(crate) fn name_from_ident(ident: &Ident) -> String {
    ident.to_string()
}

/// Generates a wrapper around a globally-owned JS object expected to match the bridged
/// representation of a trait.
///
/// The wrapper will be named "Node{MyTrait}" and will implement the original trait, as well as
/// `neon::types::Finalize`.
pub(crate) fn bridge_trait(trait_to_bridge: &ItemTrait, js_name: &str) -> Result<TokenStream2> {
    let trait_name = &trait_to_bridge.ident;
    let wrapper_name = format_ident!("Node{}", trait_to_bridge.ident);
    let krate = crates::libsignal_bridge_types();

    let callbacks = trait_to_bridge
        .items
        .iter()
        .map(|x| bridge_callback_item(x, &krate))
        .collect::<Result<Vec<_>>>()?;
    let callback_impls = callbacks.iter().map(|c| &c.implementation);
    let callback_bridge_trait_functions = callbacks.iter().map(|c| &c.bridge_trait_function);
    let md = quote!(#krate::metadata);
    let metadata_name = format_ident!("_BRIDGE_NODE_METADATA_{trait_name}");

    Ok(quote! {
        #[cfg(feature = "node")]
        pub struct #wrapper_name(node::RootAndChannel);

        #[cfg(feature = "node")]
        impl #wrapper_name {
            pub fn new(
                cx: &mut node::FunctionContext,
                object: node::Handle<node::JsObject>,
            ) -> node::NeonResult<Self> {
                Ok(Self(node::RootAndChannel::new(cx, object)?))
            }
        }

        #[cfg(feature = "node")]
        impl node::Finalize for #wrapper_name {
            fn finalize<'a, C: node::Context<'a>>(self, cx: &mut C) {
                self.0.finalize(cx);
            }
        }

        #[cfg(feature = "node")]
        impl #trait_name for #wrapper_name {
            #(#callback_impls)*
        }

        #[cfg(all(feature = "node", feature = "metadata"))]
        #[#md::linkme::distributed_slice(#md::node::NODE_ITEMS)]
        #[linkme(crate = #md::linkme)]
        static #metadata_name: #md::FnWithModule<#md::node::TsMetadataContext> = #md::FnWithModule {
            module_path: module_path!(),
            apply: |ctx| {
                let mut functions = Vec::new();
                #(#callback_bridge_trait_functions)*
                ctx.bridge_traits.insert(#js_name.to_string(), functions);
            },
        };
    })
}

struct Callback {
    implementation: TokenStream2,
    /// Push a `node::BridgeTraitFunction` onto the local `functions` Vec
    /// `ctx: &mut TsMetadataContext` is in scope
    bridge_trait_function: TokenStream2,
}

fn bridge_callback_item(item: &TraitItem, krate: &TokenStream2) -> Result<Callback> {
    let TraitItem::Fn(item) = item else {
        return Err(Error::new(item.span(), "only fns are supported"));
    };

    let sig = &item.sig;
    let req_name = &item.sig.ident;
    let js_operation_name = req_name.to_string().to_lower_camel_case();

    // fn operation(foo: u32) {
    //     self.0.send_and_log_on_error("operation", move |cx, object| {
    //         let js_foo = node::ResultTypeInfo::convert_into(foo, cx)?.upcast();
    //         let _result = call_method(
    //             cx,
    //             object,
    //             "operation",
    //             [js_foo],
    //         )?;
    //         Ok(())
    //     })
    // }
    let arg_conversions = item.sig.inputs.iter().filter_map(|arg| match arg {
        FnArg::Receiver(_) => None,
        FnArg::Typed(arg) => {
            let Pat::Ident(arg_name) = &*arg.pat else {
                return Some(
                    Error::new(arg.pat.span(), "only simple argument syntax is supported")
                        .into_compile_error(),
                );
            };
            let js_arg_name = format_ident!("js_{}", arg_name.ident);
            Some(quote! {
                // Note that we use *Result*TypeInfo for callback arguments,
                // since we are passing values from Rust into JS.
                let #js_arg_name = node::ResultTypeInfo::convert_into(#arg_name, cx)?
                    .upcast() // note no trailing semicolon
            })
        }
    });
    let converted_args = item.sig.inputs.iter().filter_map(|arg| match arg {
        FnArg::Receiver(_) => None,
        FnArg::Typed(arg) => {
            let Pat::Ident(arg_name) = &*arg.pat else {
                return Some(
                    Error::new(arg.pat.span(), "only simple argument syntax is supported")
                        .into_compile_error(),
                );
            };
            Some(format_ident!("js_{}", arg_name.ident).into_token_stream())
        }
    });
    let implementation = if sig.asyncness.is_some() {
        quote! {
            // #sig carries everything from `fn` to the return type and possible where-clause.
            // All we provide is the body.
            #sig {
                self.0.get_promise(
                    #js_operation_name,
                    move |cx, object| {
                        #(#arg_conversions;)*
                        node::call_method(
                            cx,
                            object,
                            #js_operation_name,
                            [#(#converted_args),*],
                        )?.downcast_or_throw(cx)
                    },
                )
                .await
            }
        }
    } else {
        quote! {
            #sig {
                self.0.send_and_log_on_error(#js_operation_name, move |cx, object| {
                    #(#arg_conversions;)*
                    let _result = node::call_method(
                        cx,
                        object,
                        #js_operation_name,
                        [#(#converted_args),*],
                    )?;
                    Ok(())
                })
            }
        }
    };

    let args = item
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Receiver(_) => None,
            FnArg::Typed(arg) => {
                let Pat::Ident(arg_name) = &*arg.pat else {
                    // Diagnosed elsewhere.
                    return None;
                };
                Some((&arg_name.ident, &arg.ty))
            }
        })
        .collect_vec();
    let arg_names = args
        .iter()
        .map(|(x, _)| to_lower_camel_case_preserve_underscores(&x.to_string()))
        .collect_vec();
    let arg_types = args.iter().map(|(_, x)| x).collect_vec();
    let result_ty = result_type(&sig.output);

    let return_type = if sig.asyncness.is_some() {
        quote! {{
            use #krate::metadata::node::result_type_helper::*;
            let return_type: CallbackResultMetadataTransformHelper<#result_ty> = Default::default();
            let return_type = return_type.register_ts_ffi_type(ctx);
            format!("Promise<{return_type}>")
        }}
    } else {
        if !matches!(sig.output, ReturnType::Default) {
            return Err(Error::new(
                item.span(),
                "non-async callbacks with results are not supported for Node",
            ));
        }
        quote!("void".to_string())
    };

    Ok(Callback {
        implementation,
        bridge_trait_function: quote! {
            let mut arguments = Vec::new();
            #(arguments.push((
                #arg_names.to_string(),
                <#arg_types as #krate::node::ResultTypeInfo>::register_ts_ffi_type(ctx),
            ));)*
            let return_type = #return_type;
            functions.push(#krate::metadata::node::BridgeTraitFunction {
                name: #js_operation_name.to_string(),
                body: #krate::metadata::node::NativeFunction {
                    arguments,
                    return_type,
                },
            });
        },
    })
}
