//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use heck::ToLowerCamelCase;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::*;
use syn::spanned::Spanned as _;
use syn::*;
use syn_mid::Signature;

use crate::BridgingKind;
use crate::util::{extract_arg_names_and_types, result_type};

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
        #[unsafe(export_name = concat!(env!("LIBSIGNAL_BRIDGE_FN_PREFIX_JNI"), #name))]
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
        .map(bridge_callback_item)
        .collect::<Result<Vec<_>>>()?;
    let callback_impls = callbacks.iter().map(|c| &c.implementation);

    Ok(quote! {
        #[cfg(feature = "jni")]
        pub type #object_alias_name<'a> = jni::JObject<'a>;

        #[cfg(feature = "jni")]
        pub struct #wrapper_name(jni::GlobalAndVM);

        #[cfg(feature = "jni")]
        impl #wrapper_name {
            pub fn new(
                env: &mut jni::JNIEnv<'_>,
                object: &#object_alias_name<'_>,
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

fn bridge_callback_item(item: &TraitItem) -> Result<Callback> {
    let TraitItem::Fn(item) = item else {
        return Err(Error::new(item.span(), "only fns are supported"));
    };

    let sig = &item.sig;
    let req_name = &item.sig.ident;
    let java_operation_name = req_name.to_string().to_lower_camel_case();

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
    let implementation = quote! {
        // #sig carries everything from `fn` to the return type and possible where-clause.
        // All we provide is the body.
        #sig {
            self.0.attach_and_log_on_error(#java_operation_name, move |env, object| {
                #(#arg_conversions;)*
                jni::call_method_checked(
                    env,
                    object,
                    #java_operation_name,
                    jni::JniArgs {
                        sig: const_str::concat!("(", #(#arg_signatures,)* ")V"),
                        args: [#(jni::JValue::from(&#converted_args)),*],
                        _return: std::marker::PhantomData::<fn()>,
                    }
                )
            });
        }
    };

    Ok(Callback { implementation })
}
