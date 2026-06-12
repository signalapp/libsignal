//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use itertools::Itertools as _;
use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, TokenStreamExt, format_ident, quote};
use syn::spanned::Spanned;
use syn::*;
use syn_mid::{FnArg, Pat, PatType, Signature};

pub(crate) mod crates {
    use std::sync::LazyLock;

    use super::*;
    static PKG_NAME: LazyLock<String> =
        LazyLock::new(|| std::env::var("CARGO_PKG_NAME").expect("Missing CARGO_PKG_NAME"));
    pub(crate) fn libsignal_bridge_types() -> TokenStream2 {
        if PKG_NAME.as_str() == "libsignal-bridge-types" {
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

/// A utility to generate the header of an `impl` statement
///
/// It's used like:
/// ```ignore
/// let my_impl = Impl::new(my_derive_input, Some(parse_quote!(crate::MyTrait)));
/// quote! {
///     #my_impl {
///         // fns & co.
///     }
/// }
/// ```
/// which will expand to (assuming `my_derive_input` is for `MyStruct<'a, T>`):
/// ```ignore
/// let my_impl = Impl::new(my_derive_input, Some(parse_quote!(crate::MyTrait)));
/// quote! {
///     impl<'a, T> crate::MyTrait for MyStruct<'a, T> {
///         // fns & co.
///     }
/// }
/// ```
///
/// The benefit of the `Impl` helper is that we can add extra where clauses or generic parameters
/// to the `Impl`.
///
/// So
/// ```ignore
/// let mut my_impl = Impl::new(my_derive_input, Some(parse_quote!(crate::MyTrait<'b, U>)));
/// my_impl.extra_params.extend([parse_quote!('b), parse_quote!(U)]);
/// my_impl.extra_where.push(parse_quote!(T: Eq));
/// ```
/// will yield
/// ```ignore
/// impl<'a, 'b, T, U> crate::MyTrait<'b, U> for MyStruct<'a, T>
///    where T: Eq
/// {}
/// ```
pub(crate) struct Impl {
    pub(crate) target: Path,
    pub(crate) trait_name: Option<Path>,
    pub(crate) generics: Generics,
    pub(crate) extra_where: Vec<WherePredicate>,
    pub(crate) extra_params: Vec<GenericParam>,
}

impl ToTokens for Impl {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        let (_, item_generics, _) = self.generics.split_for_impl();
        let mut g = self.generics.clone();
        g.make_where_clause()
            .predicates
            .extend(self.extra_where.iter().cloned());
        g.params.extend(self.extra_params.iter().cloned());
        let (impl_, _, where_) = g.split_for_impl();
        let target = &self.target;
        let trait_name = self
            .trait_name
            .as_ref()
            .map(|trait_name| quote!(#trait_name for));
        tokens.append_all(quote!(impl #impl_ #trait_name #target #item_generics #where_));
    }
}

impl Impl {
    /// Generate an `Impl` for `impl #trait_name for #value`
    ///
    /// From this baseline, we can add extra generic parameters and add to the where clause
    pub(crate) fn new(value: &DeriveInput, target: &Path, trait_name: Option<Path>) -> Self {
        Self {
            target: target.clone(),
            trait_name,
            generics: value.generics.clone(),
            extra_where: Vec::new(),
            extra_params: Vec::new(),
        }
    }
}

/// Emit code to generate a `libsignal_bridge_types::metadata::Struct` for the given trait
///
/// For example, passing in `NiceArgConverter` as `trait_name` and `register_ts_arg_converter` as
/// the `trait_fn`.
///
/// `where_clause` will get populated with, for example `i32: NiceArgConverter` if `i32` is a type
/// in `fields`.
pub(crate) fn nice_struct_metadata(
    fields: &Fields,
    trait_name: &Path,
    trait_fn: &Ident,
    where_clause: &mut Vec<WherePredicate>,
) -> TokenStream2 {
    let is_tuple = matches!(fields, Fields::Unnamed(_) | Fields::Unit);
    let krate = crates::libsignal_bridge_types();
    let field_names = get_field_names(fields);
    let field_types = fields.iter().map(|field| &field.ty).collect_vec();
    for ty in &field_types {
        where_clause.push(parse_quote!(#ty: #trait_name));
    }
    quote! {
        #krate::metadata::Struct {
            is_tuple: #is_tuple,
            fields: vec![#(
                (
                    stringify!(#field_names).to_string(),
                    <#field_types as #trait_name>::#trait_fn(ctx),
                ),
            )*],
        }
    }
}

/// What are fields named?
///
/// For tuple structs, fields are named like: `_0`, `_1`, ...
fn get_field_names(fields: &Fields) -> Vec<Ident> {
    fields
        .iter()
        .enumerate()
        .map(|(i, field)| {
            field
                .ident
                .as_ref()
                .cloned()
                .unwrap_or_else(|| format_ident!("_{i}"))
        })
        .collect_vec()
}

/// A struct `struct Foo { fields }` is treated as:
/// ```ignore
/// enum Foo {
///     Foo { fields }
/// }
/// ```
pub(crate) struct DeriveInputInfo {
    /// For each variant, what pattern is needed to extract its fields
    ///
    /// TODO: improve this documentation
    ///
    /// See [`extract_fields_pattern`]
    pub(crate) patterns: Vec<TokenStream2>,
    /// For each variant, what are the field names
    ///
    /// See [`get_field_names`] for how this applies to tuple structs
    pub(crate) field_names: Vec<Vec<Ident>>,
    /// For each variant, what are the field types
    pub(crate) field_types: Vec<Vec<Type>>,
    /// For each variant, what's its index
    pub(crate) variant_indices: Vec<i32>,
    /// For each variant, what's its name
    pub(crate) variant_names: Vec<Ident>,
}
impl DeriveInputInfo {
    pub fn new(input: &DeriveInput, target: &syn::Path) -> Self {
        // The pattern needed to match against this variant
        let mut patterns = Vec::new();
        let mut variant_indices = Vec::new();
        // Just the names of the fields of each variant
        let mut field_names = Vec::new();
        let mut field_types = Vec::new();
        let mut variant_names = Vec::new();
        match &input.data {
            Data::Struct(data) => {
                let ef = extract_fields_pattern(&data.fields);
                patterns.push(quote!(#target #ef));
                field_names.push(get_field_names(&data.fields));
                variant_indices.push(0);
                field_types.push(data.fields.iter().map(|field| field.ty.clone()).collect());
                variant_names.push(input.ident.clone());
            }
            Data::Enum(data) => {
                for (i, variant) in data.variants.iter().enumerate() {
                    let ef = extract_fields_pattern(&variant.fields);
                    let variant_name = &variant.ident;
                    patterns.push(quote!(#target::#variant_name #ef));
                    variant_indices.push(i32::try_from(i).expect("not too many variants"));
                    field_names.push(get_field_names(&variant.fields));
                    field_types.push(
                        variant
                            .fields
                            .iter()
                            .map(|field| field.ty.clone())
                            .collect(),
                    );
                    variant_names.push(variant_name.clone());
                }
            }
            Data::Union(_) => unreachable!("Checked above"),
        }
        Self {
            patterns,
            variant_indices,
            field_names,
            field_types,
            variant_names,
        }
    }
}

/// What pattern is needed to destructure the given `fields`?
///
/// # Examples
/// - For `struct Foo { x: A, y: B }`, return `{x, y}`
/// - For `struct Foo(A, B)`, return `(_0, _1)`
/// - For `struct Foo`, return an empty token stream
fn extract_fields_pattern(fields: &Fields) -> TokenStream2 {
    let names = get_field_names(fields);
    match fields {
        Fields::Named(_) => quote!({#(#names),*}),
        Fields::Unnamed(_) => quote!((#(#names),*)),
        Fields::Unit => quote!(),
    }
}

/// Generate code to add `input`'s metadata to the metadata context in `ctx`
///
/// `trait_name`/`trait_fn` are, for example, `NiceArgConverter`/`register_ts_arg_converter`
///
/// `metadata_field` is the name of the field in e.g. `TsMetadataContext` where the metadata should
/// be added (e.g. `derived_arg_converters`).
///
/// Neccessary type constraints are added to `where_clause`
pub(crate) fn nice_type_metadata(
    input: &DeriveInput,
    ctx: &Expr,
    metadata_field: &Ident,
    trait_name: &Path,
    trait_fn: &Ident,
    where_clause: &mut Vec<WherePredicate>,
) -> syn::Result<TokenStream2> {
    let krate = crates::libsignal_bridge_types();
    let ident = &input.ident;
    Ok(match &input.data {
        Data::Struct(data) => {
            let ns = nice_struct_metadata(&data.fields, trait_name, trait_fn, where_clause);
            quote! {
                let ns = #ns;
                #krate::metadata::insert_checked(
                    &mut #ctx.#metadata_field,
                    stringify!(#ident).to_string(),
                    ns.into(),
                );
            }
        }
        Data::Enum(data) => {
            let variants = data.variants.iter().map(|variant| {
                let name = &variant.ident;
                let ns = nice_struct_metadata(&variant.fields, trait_name, trait_fn, where_clause);
                quote! {
                    (stringify!(#name).to_string(), #ns)
                }
            });
            quote! {
                let variants = vec![#(#variants),*];
                #krate::metadata::insert_checked(
                    &mut #ctx.#metadata_field,
                    stringify!(#ident).into(),
                    #krate::metadata::Enum {
                        variants,
                    }.into(),
                );
            }
        }
        Data::Union(_) => unreachable!("checked earlier"),
    })
}

/// Because the arg impl requires intermediate storage, we introduce the ArgStoredType.
///
/// For structs, it looks like:
/// `enum Foo<T> { Foo(T) }`
/// For enums, it looks like:
/// `enum Foo<A, B, ...> { A(A), B(B), ... }`
///
/// We need a custom type because:
/// 1. For enums, the intermediate data is distinct for each variant
/// 2. We could avoid declaring a fresh type, and just use nested Eithers, but that'd be more
///    annoying than just declaring this type.
///
/// We use one generic type per variant (each containing a tuple), because it's easier to work
/// with in our macros than it'd be to have one generic type for each field.
pub(crate) fn arg_type_info_storage_decl(
    name: &Ident,
    input: &DeriveInput,
    target: &syn::Path,
) -> TokenStream2 {
    let DeriveInputInfo { variant_names, .. } = DeriveInputInfo::new(input, target);
    quote! {
        #[doc(hidden)]
        #[allow(unused)]
        pub enum #name<#(#variant_names),*> {
            #(#variant_names(#variant_names)),*
        }
    }
}
