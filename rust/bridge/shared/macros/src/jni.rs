//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use heck::ToLowerCamelCase;
use itertools::Itertools;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::*;
use syn::spanned::Spanned as _;
use syn::*;
use syn_mid::Signature;

use crate::util::{
    BridgeAsValueOptions, DeriveInputInfo, Impl, NiceMetadataNames, arg_type_info_storage_decl,
    crates, extract_arg_names_and_types, nice_metadata, nice_type_metadata, result_type,
};
use crate::{BridgingKind, ResultInfo};

pub(crate) fn bridge_fn(
    name: &str,
    sig: &Signature,
    bridging_kind: &BridgingKind,
    nice: bool,
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
    let metadata = nice_metadata(
        &orig_name.to_string(),
        sig.asyncness.is_some(),
        &input_names_and_types,
        &output,
        nice,
        &NiceMetadataNames {
            backend_name: format_ident!("jni"),
            metadata_context: format_ident!("KtMetadataContext"),
            register_arg_converter: format_ident!("register_kt_arg_converter"),
            register_result_converter: format_ident!("register_kt_result_converter"),
        },
    );
    Ok(quote! {
        #[cfg(feature = "jni")]
        #[unsafe(export_name = concat!(env!("LIBSIGNAL_BRIDGE_FN_PREFIX_JNI"), #name))]
        #[allow(non_snake_case)]
        pub unsafe extern "C" fn #wrapper_name<'local>(
            mut env: ::jni::EnvUnowned<'local>,
            // We only generate static methods.
            _class: ::jni::objects::JClass,
            #async_runtime_if_needed
            #(#input_args),*
        ) -> #result_ty {
            let _trace = libsignal_debug::trace_block!(concat!("bridge::", #name));
            #body
        }
        #metadata
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
            jni::run_future_on_runtime(env, async_runtime, stringify!(#orig_name), |__cancel| async move {
                // Wrap the actual work to catch any panics.
                let __future = jni::catch_unwind(std::panic::AssertUnwindSafe(async {
                    #(#input_loading)*
                        ::tokio::select! {
                            __result = #orig_name(#(#input_names),*) => {
                                // If the original function can't fail, wrap the result in Ok for uniformity.
                                // See TransformHelper::ok_if_needed.
                                Ok(TransformHelper(__result).ok_if_needed()?.0)
                            }
                            _ = __cancel => {
                                Err(jni::FutureCancelled.into())
                            }
                        }
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

/// Generates a wrapper around a globally-owned Java object expected to match the bridged
/// representation of a trait.
///
/// The wrapper will be named "Jni{MyTrait}" and will implement the original trait. Additionally, an
/// alias for `JObject` will be generated named "Java{MyTrait}", for use by gen_java_decl.
pub(crate) fn bridge_trait(
    trait_to_bridge: &ItemTrait,
    java_class_path: &str,
) -> Result<TokenStream2> {
    let (_package_name, java_class_name) = java_class_path.rsplit_once('.').ok_or_else(|| {
        Error::new(
            Span::call_site(),
            "JNI name should be a fully qualified class name in \"binary name\" format",
        )
    })?;

    let trait_name = &trait_to_bridge.ident;
    let object_alias_name = format_ident!("Java{}", java_class_name);
    let wrapper_name = format_ident!("Jni{}", trait_to_bridge.ident);

    let callbacks = trait_to_bridge
        .items
        .iter()
        .map(|item| bridge_callback_item(item, &wrapper_name))
        .collect::<Result<Vec<_>>>()?;
    let callback_impls = callbacks.iter().map(|c| &c.implementation);

    Ok(quote! {
        #[cfg(feature = "jni")]
        pub type #object_alias_name<'a> = jni::JObject<'a>;

        #[cfg(feature = "jni")]
        pub struct #wrapper_name(jni::GlobalAndVM);

        #[cfg(feature = "jni")]
        impl #wrapper_name {
            pub fn new<'a>(
                env: &mut ::jni::Env<'a>,
                object: &#object_alias_name<'a>,
            ) -> Result<Self, jni::BridgeLayerError> {
                Ok(Self(jni::GlobalAndVM::new(env, object, jni::ClassName(#java_class_path))?))
            }
        }

        #[cfg(feature = "jni")]
        impl #trait_name for #wrapper_name {
            #(#callback_impls)*
        }
    })
}

struct Callback {
    implementation: TokenStream2,
}

fn bridge_callback_item(item: &TraitItem, wrapper_name: &Ident) -> Result<Callback> {
    let TraitItem::Fn(item) = item else {
        return Err(Error::new(item.span(), "only fns are supported"));
    };

    let sig = &item.sig;
    let req_name = &item.sig.ident;
    let java_operation_name = req_name.to_string().to_lower_camel_case();
    let result_info = ResultInfo::from(&sig.output);
    let result_ty = result_type(&sig.output);

    // fn operation(foo: u32) {
    //     self.0.attach_and_log_on_error("operation", move |env, object| {
    //         let java_foo = JValueOwned::from(
    //             jni::ResultTypeInfo::convert_into(foo, env)?
    //         );
    //         call_method_checked(
    //             env,
    //             object,
    //             "operation",
    //             JniArgs {
    //                 sig: concat!("(", jni::jni_signature_for::<u32>(), ")V"),
    //                 args: [JValue::from(&java_foo)],
    //                 _return: PhantomData
    //             },
    //         )
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
            let java_arg_name = format_ident!("java_{}", arg_name.ident);
            Some(quote! {
                let #java_arg_name = jni::JValueOwned::from(
                    // Note that we use *Result*TypeInfo for callback arguments,
                    // since we are passing values from Rust into Java.
                    jni::ResultTypeInfo::convert_into(#arg_name, env)?
                ) // note no trailing semicolon
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
            Some(format_ident!("java_{}", arg_name.ident).into_token_stream())
        }
    });
    let arg_signatures = item.sig.inputs.iter().filter_map(|arg| match arg {
        FnArg::Receiver(_) => None,
        FnArg::Typed(arg) => {
            let ty = &arg.ty;
            Some(quote!(jni::jni_signature_for::<#ty>()))
        }
    });
    let implementation = if result_info.failable {
        quote! {
            // #sig carries everything from `fn` to the return type and possible where-clause.
            // All we provide is the body.
            #sig {
                let _trace = libsignal_debug::trace_block!(concat!(
                    "bridge_callbacks::",
                    stringify!(#wrapper_name),
                    "::",
                    #java_operation_name,
                ));
                self.0.attach(#java_operation_name, move |env, __object| {
                    #(#arg_conversions;)*
                    let __signature = ::jni::signature::RuntimeMethodSignature::from_str(
                        const_str::concat!("(", #(#arg_signatures,)* ")", jni::jni_signature_for_result::<#result_ty>()),
                    ).expect("valid jni signature");
                    let __result = jni::call_method_checked(
                        env,
                        __object,
                        #java_operation_name,
                        jni::JniArgs {
                            sig: __signature.method_signature(),
                            args: [#(jni::JValue::from(&#converted_args)),*],
                            // Some result types have 'local in them, so we have to provide that lifetime here.
                            _return: std::marker::PhantomData::<for<'local> fn(&'local ()) -> jni_arg_type!(#result_ty)>,
                        }
                    )?;
                    jni::CallbackResultTypeInfo::convert_from_callback(env, __result)
                })
            }
        }
    } else {
        quote! {
            #sig {
                let _trace = libsignal_debug::trace_block!(concat!(
                    "bridge_callbacks::",
                    stringify!(#wrapper_name),
                    "::",
                    #java_operation_name,
                ));
                // Not implemented: callbacks that *do* have a return value but *don't* have a place for errors.
                // We can handle those some if we need them.
                self.0.attach_and_log_on_error(#java_operation_name, move |env, __object| {
                    #(#arg_conversions;)*
                    let __signature = ::jni::signature::RuntimeMethodSignature::from_str(
                        const_str::concat!("(", #(#arg_signatures,)* ")V"),
                    ).expect("valid jni signature");
                    jni::call_method_checked(
                        env,
                        __object,
                        #java_operation_name,
                        jni::JniArgs {
                            sig: __signature.method_signature(),
                            args: [#(jni::JValue::from(&#converted_args)),*],
                            _return: std::marker::PhantomData::<fn(&())>,
                        }
                    )
                });
            }
        }
    };

    Ok(Callback { implementation })
}

pub(crate) fn derive_bridged_as_value(
    input: &DeriveInput,
    target: &syn::Path,
    options: &BridgeAsValueOptions,
) -> syn::Result<TokenStream2> {
    if matches!(input.data, Data::Union(_)) {
        return Err(syn::Error::new_spanned(input, "Unions aren't supported"));
    }
    let ident = &input.ident;
    let base_class = quote!(org.signal.libsignal.internal.#ident);
    let result = options
        .result
        .then(|| derive_bridged_as_value_return(input, target, &base_class))
        .transpose()?;
    let arg = options
        .arg
        .then(|| derive_bridged_as_value_arg(input, target, &base_class))
        .transpose()?;
    Ok(quote! {
        #result
        #arg
    })
}

fn derive_bridged_as_value_arg(
    input: &DeriveInput,
    target: &syn::Path,
    base_class: &TokenStream2,
) -> syn::Result<TokenStream2> {
    let krate = crates::libsignal_bridge_types();
    let ident = &input.ident;
    let mut impl_arg_type_info = Impl::new(
        input,
        target,
        Some(parse_quote!(#krate::jni::ArgTypeInfo<'storage, 'param, 'context>)),
    );
    impl_arg_type_info.extra_params.extend([
        parse_quote!('storage),
        parse_quote!('param: 'storage),
        parse_quote!('context: 'param),
    ]);
    let DeriveInputInfo {
        patterns: field_patterns,
        field_names,
        field_types,
        variant_indices: _,
        variant_names,
    } = DeriveInputInfo::new(input, target);
    impl_arg_type_info
        .extra_where
        .extend(field_types.iter().flatten().map(|ty|parse_quote!(
            #ty: #krate::jni::ArgTypeInfo<'storage, 'param, 'context/*, ArgType=#krate::jni_arg_type!(#ty)*/>
        )));
    let mut impl_nice_arg_converter = Impl::new(
        input,
        target,
        Some(parse_quote!(#krate::jni::NiceArgConverter)),
    );
    let register_kt_nice_type = nice_type_metadata(
        input,
        &parse_quote!(ctx),
        &parse_quote!(derived_types),
        &parse_quote!(#krate::jni::NiceArgConverter),
        &parse_quote!(register_kt_nice_type),
        &mut impl_nice_arg_converter.extra_where,
    )?;
    let register_kt_arg_converter = nice_type_metadata(
        input,
        &parse_quote!(ctx),
        &parse_quote!(derived_arg_converters),
        &parse_quote!(#krate::jni::NiceArgConverter),
        &parse_quote!(register_kt_arg_converter),
        &mut impl_nice_arg_converter.extra_where,
    )?;
    let stored_decl_name = format_ident!("{ident}JniArgStoredType");
    let stored_decl = arg_type_info_storage_decl(&stored_decl_name, input, target);
    // This macro operates similarly to the other nice derive ArgTypeInfo impls. It determines
    // which variant is being provided via a series of instanceof checks.
    let classes = match &input.data {
        Data::Struct(_) => vec![quote!(#base_class::FfiArgType)],
        Data::Enum(_) => variant_names
            .iter()
            .map(|variant| quote!(#base_class::#variant::FfiArgType))
            .collect_vec(),
        Data::Union(_) => unreachable!(),
    };
    let field_names_str = field_names
        .iter()
        .map(|fields| fields.iter().map(ToString::to_string).collect_vec())
        .collect_vec();
    Ok(quote! {
        #[cfg(feature = "jni")]
        #stored_decl
        #[cfg(feature = "jni")]
        #impl_arg_type_info {
            type ArgType = ::jni::objects::JObject<'context>;
            type StoredType = #stored_decl_name<#(
                (
                    #(<#field_types as #krate::jni::ArgTypeInfo<'storage, 'param, 'context>>::StoredType,)*
                ),
            )*>;
            fn borrow(
                env: &mut ::jni::Env<'context>,
                foreign_arg: &Self::ArgType,
            ) -> Result<Self::StoredType, #krate::jni::BridgeLayerError> {
                use #krate::jni::HandleJniError;
                // We use bind_java_type! to cache the class lookup. We can't cache the field
                // lookup, beacuse bind_java_type! requires that field signatures are known at
                // macro _elaboration_ time.
                #(::jni::bind_java_type! {
                    #variant_names => #classes,
                    hooks = {
                        load_class = |env, load_context, initialize| {
                            #krate::jni::loader_context().as_ref().unwrap_or(load_context)
                                .load_class_for_type::<#variant_names>(env, initialize)
                        },
                    },
                })*
                const CONTEXT_STR: &str = concat!(stringify!(ident), "::borrow");
                #(
                    if let Some(jni_arg) = match env.as_cast::<#variant_names>(foreign_arg) {
                        Ok(jni_arg) => Ok(Some(jni_arg)),
                        Err(::jni::errors::Error::WrongObjectType) => Ok(None),
                        Err(e) => Err(e),
                    }.check_exceptions(env, CONTEXT_STR)? {
                        #(
                            let #field_names = env.get_field(
                                jni_arg.as_ref(),
                                ::jni::jni_str!(#field_names_str),
                                <<
                                    #field_types as #krate::jni::ArgTypeInfo<'storage, 'param, 'context>
                                >::ArgType as #krate::jni::ConvertibleFromJValue>::SIGNATURE,
                            ).and_then(|raw|
                                <<
                                    #field_types as #krate::jni::ArgTypeInfo<'storage, 'param, 'context>
                                >::ArgType as #krate::jni::ConvertibleFromJValue>::try_convert(env, raw),
                            ).check_exceptions(env, CONTEXT_STR)?;
                        )*
                        #(
                            let #field_names = <
                                #field_types as #krate::jni::ArgTypeInfo<'storage, 'param, 'context>
                            >::borrow(env, &#field_names)?;
                        )*
                        return Ok(#stored_decl_name::#variant_names((#(#field_names, )*)));
                    }
                )*
                Err(#krate::jni::BridgeLayerError::BadArgument(
                    concat!("Invalid variant for enum ", stringify!(#base_class)).to_string()
                ))
            }
            fn load_from(stored_arg: &'storage mut Self::StoredType) -> Self {
                match stored_arg {#(
                    #stored_decl_name::#variant_names((#(#field_names,)*)) => {
                        #(let #field_names = #krate::jni::ArgTypeInfo::load_from(#field_names);)*
                        #field_patterns
                    },
                )*}
            }
        }
        #[cfg(all(feature = "jni", feature = "metadata"))]
        #impl_nice_arg_converter {
            fn register_kt_arg_converter(
                ctx: &mut #krate::jni::KtMetadataContext
            ) -> #krate::metadata::jni::KtArgConverter {
                #register_kt_nice_type
                #register_kt_arg_converter
                #krate::metadata::jni::KtArgConverter {
                    nice_type: stringify!(#base_class).to_string(),
                    ffi_type: "Object".to_string(),
                    ffi_field_type_erased: "Any?".to_string(),
                    converter_function: concat!("(", stringify!(#base_class), "::toFfiArgTypeObject)").to_string()
                }
            }
        }
    })
}

fn derive_bridged_as_value_return(
    input: &DeriveInput,
    target: &syn::Path,
    base_class: &TokenStream2,
) -> syn::Result<TokenStream2> {
    let krate = crates::libsignal_bridge_types();
    let ident = &input.ident;
    let mut impl_nice_result_converter = Impl::new(
        input,
        target,
        Some(parse_quote!(#krate::jni::NiceResultConverter)),
    );
    let mut impl_result_type_info = Impl::new(
        input,
        target,
        Some(parse_quote!(#krate::jni::ResultTypeInfo<'jni_context>)),
    );
    impl_result_type_info
        .extra_params
        .push(parse_quote!('jni_context));
    let register_kt_nice_type = nice_type_metadata(
        input,
        &parse_quote!(ctx),
        &parse_quote!(derived_types),
        &parse_quote!(#krate::jni::NiceResultConverter),
        &parse_quote!(register_kt_nice_type),
        &mut impl_nice_result_converter.extra_where,
    )?;
    let register_kt_result_converter = nice_type_metadata(
        input,
        &parse_quote!(ctx),
        &parse_quote!(derived_return_converters),
        &parse_quote!(#krate::jni::NiceResultConverter),
        &parse_quote!(register_kt_result_converter),
        &mut impl_nice_result_converter.extra_where,
    )?;
    let DeriveInputInfo {
        patterns,
        field_names: fields,
        variant_indices: _,
        field_types,
        variant_names,
    } = DeriveInputInfo::new(input, target);
    impl_result_type_info.extra_where.extend(
        field_types
            .into_iter()
            .flatten()
            .map(|ty| parse_quote!(#ty: #krate::jni::ResultTypeInfo<'jni_context>)),
    );
    // To produce the right nice type, the macro invokes #ident.#variant.fromNative(native args)
    // Unlike with other client languages, fromNative invokes the underlying return converters
    // directly (and so the final return converter for this derived type will be 'identity').
    let (class_names, classes) = match &input.data {
        Data::Struct(_) => (vec![base_class.to_string()], vec![base_class.clone()]),
        Data::Enum(_) => (
            variant_names
                .iter()
                .map(|variant| format!("org.signal.libsignal.internal.{ident}${variant}"))
                .collect_vec(),
            variant_names
                .iter()
                .map(|variant| quote!(org.signal.libsignal.internal.#ident::#variant))
                .collect_vec(),
        ),
        Data::Union(_) => unreachable!(),
    };
    Ok(quote! {
        #[cfg(feature = "jni")]
        #impl_result_type_info {
            type ResultType = ::jni::objects::JObject<'jni_context>;
            fn convert_into(
                self,
                jni_env: &mut ::jni::Env<'jni_context>
            ) -> ::std::result::Result<Self::ResultType, #krate::jni::BridgeLayerError> {
                use #krate::jni::HandleJniError;
                use ::jni::objects::JObject;
                const CONTEXT_STR: &str = concat!(stringify!(ident), "::convert_into");
                match self {
                    #(#patterns => {
                        #(let #fields = #krate::jni::ResultTypeInfo::convert_into(#fields, jni_env)?;)*
                        let class = #krate::jni::find_class(jni_env, #krate::jni::ClassName(#class_names))
                            .check_exceptions(jni_env, CONTEXT_STR)?;
                        #(let #fields = #krate::jni::box_primitive_if_needed(jni_env, #fields.into())?;)*
                        #krate::jni::call_static_method_checked(
                            jni_env,
                            &class,
                            "fromNative",
                            jni_args!(
                                (
                                    // TODO: figuring out the exact types here is difficult. We can
                                    // change it, but for now, let's just box everything into an
                                    // object.
                                    #(#fields => java.lang.Object,)*
                                ) -> #classes
                            ),
                        )
                    })*
                }
            }
        }
        #[cfg(all(feature = "metadata", feature = "jni"))]
        #impl_nice_result_converter {
            fn register_kt_result_converter(
                ctx: &mut #krate::metadata::jni::KtMetadataContext
            ) -> #krate::jni::KtReturnConverter {
                #register_kt_result_converter
                #register_kt_nice_type
                #krate::jni::KtReturnConverter {
                    nice_type: stringify!(#base_class).to_string(),
                    ffi_type: "Object".to_string(),
                    converter_function: concat!("downcastFromObject<", stringify!(#base_class), ">").to_string(),
                }
            }
        }
    })
}
