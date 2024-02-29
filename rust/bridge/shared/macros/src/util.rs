//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::spanned::Spanned;
use syn::*;
use syn_mid::{FnArg, Pat, PatType, Signature};

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
