//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::*;
use syn_mid::{FnArg, Pat, PatType, Signature};

pub(crate) mod crates {
    use super::*;
    fn pkg_name() -> String {
        std::env::var("CARGO_PKG_NAME").expect("Missing CARGO_PKG_NAME")
    }
    pub(crate) fn libsignal_bridge_types() -> TokenStream2 {
        if pkg_name() == "libsignal-bridge-types" {
            quote!(crate)
        } else {
            quote!(::libsignal_bridge_types)
        }
    }
}

/// Returns the tokens of the type in `output_as_written`, or `()` if no return type was written.
pub(crate) fn result_type(output_as_written: &ReturnType) -> TokenStream2 {
    match output_as_written {
        ReturnType::Default => quote!(()),
        ReturnType::Type(_, ty) => quote!(#ty),
    }
}

/// Traverses the inputs of `sig` and extracts the name and type.
///
/// Only supports "simple" arguments of the form `name: Type`. Produces a [`syn::Error`] if the
/// signature includes a `self` parameter, or a parameter with a complex pattern like
/// `(x, y): Point`.
pub(crate) fn extract_arg_names_and_types(sig: &Signature) -> Result<Vec<(&Ident, &Type)>> {
    sig.inputs
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
        .collect()
}

pub(crate) struct NiceMetadataNames {
    pub(crate) backend_name: Ident,
    pub(crate) metadata_context: Ident,
    pub(crate) register_arg_converter: Ident,
    pub(crate) register_result_converter: Ident,
}

pub(crate) fn nice_metadata(
    name_without_prefix: &str,
    asyncness: bool,
    input_args: &[(&Ident, &Type)],
    result_type: &TokenStream2,
    nice: bool,
    NiceMetadataNames {
        backend_name,
        metadata_context,
        register_arg_converter,
        register_result_converter,
    }: &NiceMetadataNames,
) -> TokenStream2 {
    let krate = crates::libsignal_bridge_types();
    let md = quote!(#krate::metadata);
    let metadata_name = format_ident!("_BRIDGE_{backend_name}_METADATA_{name_without_prefix}");
    let (arg_names, arg_types) = input_args.iter().copied().unzip::<_, _, Vec<_>, Vec<_>>();
    let linkme_name = format_ident!("{}_ITEMS", backend_name.to_string().to_ascii_uppercase());
    let backend_name_str = backend_name.to_string();
    if nice {
        quote! {
            #[cfg(all(feature = #backend_name_str, feature = "metadata"))]
            #[#md::linkme::distributed_slice(#md::#backend_name::#linkme_name)]
            #[linkme(crate = #md::linkme)]
            static #metadata_name: #md::FnWithModule<#md::#backend_name::#metadata_context> = #md::FnWithModule {
                module_path: module_path!(),
                apply: |ctx| {
                    use #md::#backend_name::result_type_helper::*;
                    let mut arguments = Vec::new();
                    #(arguments.push((
                        stringify!(#arg_names).into(),
                        <#arg_types as #krate::#backend_name::NiceArgConverter>::#register_arg_converter(ctx),
                    ));)*
                    let return_type: ResultMetadataTransformHelper<#result_type> = Default::default();
                    let return_type = return_type.#register_result_converter(ctx);
                    ctx.nice_functions.insert(
                        #name_without_prefix.into(),
                        #md::#backend_name::NiceFunction {
                            is_tokio_async: #asyncness,
                            arguments,
                            return_type,
                        },
                    );
                }
            };
        }
    } else {
        quote!()
    }
}
