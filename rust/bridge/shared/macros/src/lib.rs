//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![feature(box_patterns)]

use proc_macro::TokenStream;
use quote::*;
use syn::punctuated::Punctuated;
use syn::*;
use syn_mid::ItemFn;

mod ffi;
mod jni;
mod node;

fn value_for_meta_key<'a>(
    meta_values: &'a Punctuated<MetaNameValue, Token![,]>,
    key: &str,
) -> Option<&'a Lit> {
    meta_values
        .iter()
        .find(|meta| meta.path.get_ident().map_or(false, |ident| ident == key))
        .map(|meta| &meta.lit)
}

fn name_for_meta_key(
    meta_values: &Punctuated<MetaNameValue, Token![,]>,
    key: &str,
    enabled: bool,
    default: impl FnOnce() -> String,
) -> Result<Option<String>> {
    if !enabled {
        return Ok(None);
    }
    match value_for_meta_key(meta_values, key) {
        Some(Lit::Str(name_str)) => Ok(Some(name_str.value())),
        Some(Lit::Bool(LitBool { value: false, .. })) => Ok(None),
        Some(value) => Err(Error::new(value.span(), "name must be a string literal")),
        None => Ok(Some(default())),
    }
}

#[derive(Clone, Copy)]
enum ResultKind {
    Regular,
    Buffer,
    Void,
}

impl ResultKind {
    fn has_env(self) -> bool {
        match self {
            Self::Regular | Self::Void => false,
            Self::Buffer => true,
        }
    }
}

fn bridge_fn_impl(attr: TokenStream, item: TokenStream, result_kind: ResultKind) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);

    let item_names =
        parse_macro_input!(attr with Punctuated<MetaNameValue, Token![,]>::parse_terminated);
    let ffi_name = match name_for_meta_key(&item_names, "ffi", cfg!(feature = "ffi"), || {
        ffi::name_from_ident(&function.sig.ident)
    }) {
        Ok(name) => name,
        Err(error) => return error.to_compile_error().into(),
    };
    let jni_name = match name_for_meta_key(&item_names, "jni", cfg!(feature = "jni"), || {
        jni::name_from_ident(&function.sig.ident)
    }) {
        Ok(name) => name,
        Err(error) => return error.to_compile_error().into(),
    };
    let node_name = match name_for_meta_key(&item_names, "node", cfg!(feature = "node"), || {
        node::name_from_ident(&function.sig.ident)
    }) {
        Ok(name) => name,
        Err(error) => return error.to_compile_error().into(),
    };

    let ffi_feature = ffi_name.as_ref().map(|_| quote!(feature = "ffi"));
    let jni_feature = jni_name.as_ref().map(|_| quote!(feature = "jni"));
    let node_feature = node_name.as_ref().map(|_| quote!(feature = "node"));
    let maybe_features = [ffi_feature, jni_feature, node_feature];
    let feature_list = maybe_features.iter().flatten();

    let ffi_fn = ffi_name.map(|name| ffi::bridge_fn(name, &function.sig, result_kind));
    let jni_fn = jni_name.map(|name| jni::bridge_fn(name, &function.sig, result_kind));
    let node_fn = node_name.map(|name| node::bridge_fn(name, &function.sig, result_kind));

    quote!(
        #[allow(non_snake_case)]
        #[cfg(any(#(#feature_list,)*))]
        #function

        #ffi_fn

        #jni_fn

        #node_fn
    )
    .into()
}

#[proc_macro_attribute]
pub fn bridge_fn(attr: TokenStream, item: TokenStream) -> TokenStream {
    bridge_fn_impl(attr, item, ResultKind::Regular)
}

#[proc_macro_attribute]
pub fn bridge_fn_buffer(attr: TokenStream, item: TokenStream) -> TokenStream {
    bridge_fn_impl(attr, item, ResultKind::Buffer)
}

#[proc_macro_attribute]
pub fn bridge_fn_void(attr: TokenStream, item: TokenStream) -> TokenStream {
    bridge_fn_impl(attr, item, ResultKind::Void)
}
