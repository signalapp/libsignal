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
use crate::util::{
    DeriveInputInfo, Impl, arg_type_info_storage_decl, crates, extract_arg_names_and_types,
    nice_type_metadata, result_type,
};

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

pub(crate) fn derive_bridged_as_value(
    input: &DeriveInput,
    target: &syn::Path,
) -> syn::Result<TokenStream2> {
    if matches!(input.data, Data::Union(_)) {
        return Err(syn::Error::new_spanned(input, "Unions aren't supported"));
    }
    let result = derive_bridged_as_value_return(input, target)?;
    let arg = derive_bridged_as_value_arg(input, target)?;
    Ok(quote! {
        #result
        #arg
    })
}
fn derive_bridged_as_value_arg(
    input: &DeriveInput,
    target: &syn::Path,
) -> syn::Result<TokenStream2> {
    let krate = crates::libsignal_bridge_types();
    let ident = &input.ident;
    // We setup both arg impls (async and non-async) up here.
    let mut impl_arg_type_info = Impl::new(
        input,
        target,
        Some(parse_quote!(#krate::node::ArgTypeInfo<'storage, 'context>)),
    );
    impl_arg_type_info
        .extra_params
        .extend([parse_quote!('storage), parse_quote!('context: 'storage)]);
    let mut impl_async_arg_type_info = Impl::new(
        input,
        target,
        Some(parse_quote!(#krate::node::AsyncArgTypeInfo<'storage>)),
    );
    impl_async_arg_type_info
        .extra_params
        .push(parse_quote!('storage));
    let DeriveInputInfo {
        patterns: field_patterns,
        field_names,
        field_types,
        variant_indices: variant_numbers,
        variant_names,
    } = DeriveInputInfo::new(input, target);
    let get_variant = match &input.data {
        Data::Struct(_) => quote!(0),
        Data::Enum(_) => quote! {{
            let value = foreign_arg.get(cx, "__type")?;
            <i32 as #krate::node::SimpleArgTypeInfo>::convert_from(cx, value)?
        }},
        Data::Union(_) => unreachable!(),
    };
    impl_arg_type_info.extra_where.extend(
        field_types
            .iter()
            .flatten()
            .map(|ty| parse_quote!(#ty: #krate::node::ArgTypeInfo<'storage, 'context>)),
    );
    impl_async_arg_type_info.extra_where.extend(
        field_types
            .iter()
            .flatten()
            .map(|ty| parse_quote!(#ty: #krate::node::AsyncArgTypeInfo<'storage>)),
    );
    let mut impl_nice_arg_converter = Impl::new(
        input,
        target,
        Some(parse_quote!(#krate::node::NiceArgConverter)),
    );
    let register_ts_nice_type = nice_type_metadata(
        input,
        &parse_quote!(ctx),
        &parse_quote!(derived_types),
        &parse_quote!(#krate::node::NiceArgConverter),
        &parse_quote!(register_ts_nice_type),
        &mut impl_nice_arg_converter.extra_where,
    )?;
    let register_ts_arg_converter = nice_type_metadata(
        input,
        &parse_quote!(ctx),
        &parse_quote!(derived_arg_converters),
        &parse_quote!(#krate::node::NiceArgConverter),
        &parse_quote!(register_ts_arg_converter),
        &mut impl_nice_arg_converter.extra_where,
    )?;
    let stored_decl_name = format_ident!("{ident}NodeArgStoredType");
    let stored_decl = arg_type_info_storage_decl(&stored_decl_name, input, target);
    Ok(quote! {
        #[cfg(feature = "node")]
        #stored_decl
        #[cfg(feature = "node")]
        impl<
            #(#variant_names: ::neon::types::Finalize),*
        > ::neon::types::Finalize for #stored_decl_name<#(#variant_names),*> {
            fn finalize<'a, C: ::neon::context::Context<'a>>(self, cx: &mut C) {
                match self {#(
                    Self::#variant_names(x) => x.finalize(cx),
                )*}
            }
        }
        #[cfg(feature = "node")]
        #impl_arg_type_info {
            type ArgType = ::neon::types::JsObject;
            type StoredType = #stored_decl_name<#(
                (
                    #(<#field_types as #krate::node::ArgTypeInfo<'storage, 'context>>::StoredType),*
                ),
            )*>;
            fn borrow(
                cx: &mut ::neon::context::FunctionContext<'context>,
                foreign_arg: ::neon::handle::Handle<'context, Self::ArgType>,
            ) -> ::neon::result::NeonResult<Self::StoredType> {
                use ::neon::object::Object as _;
                let foreign_variant = #get_variant;
                match foreign_variant {
                    #(#variant_numbers => {
                        #(
                            let #field_names: ::neon::handle::Handle<<#field_types as #krate::node::ArgTypeInfo<'storage, 'context>>::ArgType> =
                                foreign_arg.get(cx, stringify!(#field_names))?;
                            let #field_names = <#field_types as #krate::node::ArgTypeInfo<'storage, 'context>>::borrow(cx, #field_names)?;
                        )*
                        Ok(#stored_decl_name::#variant_names((#(#field_names),*)))
                    },)*
                    _ => ::neon::context::Context::throw_range_error(cx, concat!("Invalid variant __type for ", stringify!(#ident))),
                }
            }
            fn load_from(stored_arg: &'storage mut Self::StoredType) -> Self {
                match stored_arg {#(
                    #stored_decl_name::#variant_names((#(#field_names),*)) => {
                        #(let #field_names = #krate::node::ArgTypeInfo::load_from(#field_names);)*
                        #field_patterns
                    },
                )*}
            }
            #[cfg(feature = "metadata")]
            fn register_ts_ffi_type(_ctx: &mut #krate::metadata::node::TsMetadataContext) -> String {
                #krate::metadata::node::names::arg_ffi_type(stringify!(#ident))
            }
        }
        #[cfg(feature = "node")]
        #impl_async_arg_type_info {
            type ArgType = ::neon::types::JsObject;
            type StoredType = #stored_decl_name<#(
                (
                    #(<#field_types as #krate::node::AsyncArgTypeInfo<'storage>>::StoredType),*
                ),
            )*>;
            fn save_async_arg(
                cx: &mut ::neon::context::FunctionContext,
                foreign_arg: ::neon::prelude::Handle<Self::ArgType>,
            ) -> ::neon::result::NeonResult<Self::StoredType> {
                use ::neon::object::Object as _;
                let foreign_variant = #get_variant;
                match foreign_variant {
                    #(#variant_numbers => {
                        #(
                            let #field_names: ::neon::handle::Handle<<#field_types as #krate::node::AsyncArgTypeInfo<'storage>>::ArgType> =
                                foreign_arg.get(cx, stringify!(#field_names))?;
                            let #field_names = <#field_types as #krate::node::AsyncArgTypeInfo<'storage>>::save_async_arg(cx, #field_names)?;
                        )*
                        Ok(#stored_decl_name::#variant_names((#(#field_names),*)))
                    },)*
                    _ => ::neon::context::Context::throw_range_error(cx, concat!("Invalid variant __type for ", stringify!(#ident))),
                }
            }
            fn load_async_arg(stored_arg: &'storage mut Self::StoredType) -> Self {
                match stored_arg {#(
                    #stored_decl_name::#variant_names((#(#field_names),*)) => {
                        #(let #field_names = #krate::node::AsyncArgTypeInfo::load_async_arg(#field_names);)*
                        #field_patterns
                    },
                )*}
            }
            #[cfg(feature = "metadata")]
            fn register_ts_ffi_type(_ctx: &mut #krate::metadata::node::TsMetadataContext) -> String {
                #krate::metadata::node::names::arg_ffi_type(stringify!(#ident))
            }
        }
        #[cfg(all(feature = "node", feature = "metadata"))]
        #impl_nice_arg_converter {
            fn register_ts_arg_converter(
                ctx: &mut #krate::node::TsMetadataContext
            ) -> #krate::metadata::node::TsArgConverter {
                #register_ts_nice_type
                #register_ts_arg_converter
                #krate::node::TsArgConverter {
                    nice_type: stringify!(#ident).to_string(),
                    ffi_type: <Self as #krate::node::ArgTypeInfo>::register_ts_ffi_type(ctx),
                    converter_function:
                        #krate::metadata::node::names::arg_converter_function(stringify!(#ident)),
                }
            }
        }
    })
}
fn derive_bridged_as_value_return(
    input: &DeriveInput,
    target: &syn::Path,
) -> syn::Result<TokenStream2> {
    let krate = crates::libsignal_bridge_types();
    let ident = &input.ident;
    let mut impl_nice_result_converter = Impl::new(
        input,
        target,
        Some(parse_quote!(#krate::node::NiceResultConverter)),
    );
    let mut impl_result_type_info = Impl::new(
        input,
        target,
        Some(parse_quote!(#krate::node::ResultTypeInfo<'node_context>)),
    );
    impl_result_type_info
        .extra_params
        .push(parse_quote!('node_context));
    let register_ts_nice_type = nice_type_metadata(
        input,
        &parse_quote!(ctx),
        &parse_quote!(derived_types),
        &parse_quote!(#krate::node::NiceResultConverter),
        &parse_quote!(register_ts_nice_type),
        &mut impl_nice_result_converter.extra_where,
    )?;
    let register_ts_result_converter = nice_type_metadata(
        input,
        &parse_quote!(ctx),
        &parse_quote!(derived_return_converters),
        &parse_quote!(#krate::node::NiceResultConverter),
        &parse_quote!(register_ts_result_converter),
        &mut impl_nice_result_converter.extra_where,
    )?;
    let DeriveInputInfo {
        patterns,
        field_names: fields,
        variant_indices,
        field_types,
        variant_names: _,
    } = DeriveInputInfo::new(input, target);
    impl_result_type_info.extra_where.extend(
        field_types
            .into_iter()
            .flatten()
            .map(|ty| parse_quote!(#ty: #krate::node::ResultTypeInfo<'node_context>)),
    );
    Ok(quote! {
        #[cfg(feature = "node")]
        #impl_result_type_info {
            type ResultType = neon::types::JsValue;
            fn convert_into(
                self,
                cx: &mut ::neon::context::Cx<'node_context>,
            ) -> ::neon::result::JsResult<'node_context, Self::ResultType> {
                use ::neon::prelude::*;
                match self {
                    #(#patterns => {
                        #(let #fields = #krate::node::ResultTypeInfo::convert_into(#fields, cx)?;)*
                        let nice_object_out = cx.empty_object();
                        let nice_type_name = cx.number(#variant_indices as f64);
                        nice_object_out.prop(cx, "__type").set(nice_type_name)?;
                        #(nice_object_out.prop(cx, stringify!(#fields)).set(#fields)?;)*
                        Ok(nice_object_out.upcast())
                    })*
                }
            }
            #[cfg(feature = "metadata")]
            fn register_ts_ffi_type(ctx: &mut #krate::metadata::node::TsMetadataContext) -> String {
                #krate::metadata::node::names::return_ffi_type(stringify!(#ident))
            }
        }
        #[cfg(all(feature = "metadata", feature = "node"))]
        #impl_nice_result_converter {
            fn register_ts_result_converter(
                ctx: &mut #krate::metadata::node::TsMetadataContext
            ) -> #krate::node::TsReturnConverter {
                #register_ts_nice_type
                #register_ts_result_converter
                #krate::node::TsReturnConverter {
                    nice_type: stringify!(#ident).to_string(),
                    ffi_type: <Self as #krate::node::ResultTypeInfo>::register_ts_ffi_type(ctx),
                    converter_function:
                        #krate::metadata::node::names::return_converter_function(stringify!(#ident)),
                }
            }
        }
    })
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
