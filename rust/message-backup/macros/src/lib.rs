//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;

use heck::ToSnakeCase;
use proc_macro::TokenStream;
use proc_macro2::{Delimiter, Group, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::spanned::Spanned;
use syn::{
    self, parse2, parse_macro_input, Attribute, DeriveInput, Field, Ident, LitStr, MetaList,
    TypePath,
};

macro_rules! tokens_alias {
    ($name:ident, $path:path) => {
        struct $name;
        impl ToTokens for $name {
            fn to_tokens(&self, tokens: &mut TokenStream2) {
                quote!($path).to_tokens(tokens)
            }
        }
    };
}

tokens_alias!(
    VisitUnknownFields,
    crate::unknown::visit_static::VisitUnknownFields
);
tokens_alias!(
    VisitContainerUnknownFields,
    crate::unknown::visit_static::VisitContainerUnknownFields
);
tokens_alias!(Visitor, crate::unknown::visit_static::Visitor);
tokens_alias!(PathType, crate::unknown::Path<'_>);
tokens_alias!(Path, crate::unknown::Path);
tokens_alias!(Part, crate::unknown::Part);
tokens_alias!(VisitorArgName, visitor);
tokens_alias!(PathArgName, path);

#[proc_macro_derive(VisitUnknownFields, attributes(field_name))]
pub fn derive_visit_unknown_fields(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item);
    derive_visit_unknown_fields_impl(input).into()
}

fn derive_visit_unknown_fields_impl(input: DeriveInput) -> TokenStream2 {
    if input.generics.lifetimes().next().is_some()
        || input.generics.type_params().next().is_some()
        || input.generics.const_params().next().is_some()
    {
        return syn::Error::new_spanned(input.generics, "generics are not supported")
            .into_compile_error();
    }

    match input.data {
        syn::Data::Union(u) => {
            syn::Error::new_spanned(u.union_token, "unions are not supported").into_compile_error()
        }
        syn::Data::Enum(e) => derive_has_unknown_fields_enum_impl(input.ident, e),
        syn::Data::Struct(e) => derive_has_unknown_fields_struct_impl(input.ident, e),
    }
}

fn derive_has_unknown_fields_struct_impl(ident: Ident, e: syn::DataStruct) -> TokenStream2 {
    let visit_fields: Vec<_> = e.fields.into_iter().map(VisitField::from).collect();
    let field_idents = visit_fields.iter().map(|f| &f.ident);
    let destruct = Group::new(Delimiter::Brace, quote!(#(#field_idents),*));

    quote! {
        impl #VisitUnknownFields for #ident {
            fn visit_unknown_fields(&self, #PathArgName: #PathType, #VisitorArgName: &mut impl #Visitor) {
                let Self #destruct = self;

                #({ #visit_fields };)*
            }
        }
    }
}

fn derive_has_unknown_fields_enum_impl(ident: Ident, e: syn::DataEnum) -> TokenStream2 {
    let arms = e.variants.into_iter().map(|variant| {
        let ident = &variant.ident;
        let delimiter = match &variant.fields {
            syn::Fields::Unnamed(_) => Delimiter::Parenthesis,
            syn::Fields::Unit => Delimiter::None,
            syn::Fields::Named(_) => {
                unreachable!("generated protobuf code doesn't have enum variants with named fields")
            }
        };

        // This is either an enum or oneof in a protobuf. If there is exactly
        // one field, generate a name for the inner field from the variant name.
        let mut fields = variant.fields;
        {
            let mut it = fields.iter_mut();

            if let (Some(first), None) = (it.next(), it.next()) {
                let field_name = {
                    let candidate = variant.ident.to_string().to_snake_case();
                    match candidate.as_str() {
                        "self" => "self_".to_string(),
                        _ => candidate,
                    }
                };
                first.ident = Some(Ident::new(&field_name, first.span()))
            }
        }

        let visit_fields: Vec<_> = fields.into_iter().map(VisitField::from).collect();
        let field_names = visit_fields.iter().map(|f| &f.ident);
        let fields = Group::new(delimiter, quote!(#(#field_names),*));

        quote! {
            Self::#ident #fields => { #(#visit_fields);* }
        }
    });

    quote! {
        impl #VisitUnknownFields for #ident {
            fn visit_unknown_fields(&self, path: #PathType, #VisitorArgName: &mut impl #Visitor) {
                match self {
                    #(#arms,)*
                };
            }
        }
    }
}

/// Produces a token stream for visiting a single field.
struct VisitField {
    ident: Ident,
    proto_field_name: Option<String>,
    field_type: FieldType,
}

impl ToTokens for VisitField {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        let Self {
            ident: field_ident,
            field_type,
            proto_field_name,
        } = self;

        let field_name = proto_field_name
            .as_ref()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(field_ident.to_string()));
        match field_type {
            FieldType::Single => quote! {
                let path = #Path::Branch {
                    parent: &#PathArgName,
                    field_name: #field_name,
                    part: #Part::Field,
                };
                #VisitUnknownFields::visit_unknown_fields(#field_ident, #PathArgName, #VisitorArgName)
            },
            FieldType::Container => quote! {
                #VisitContainerUnknownFields::visit_unknown_fields_within(
                    #field_ident,
                    #PathArgName,
                    #field_name,
                    #VisitorArgName
                )
            },
        }.to_tokens(tokens)
    }
}

impl From<Field> for VisitField {
    fn from(field: Field) -> Self {
        let proto_field_name = field
            .attrs
            .into_iter()
            .find_map(FieldNameAttr::new)
            .map(|f| f.field_name);
        let ident = field.ident.expect("tuple structs aren't supported");
        let field_type = field.ty.into();
        Self {
            ident,
            proto_field_name,
            field_type,
        }
    }
}

/// Parsed attribute that indicates the name of a field in the source .proto
/// file.
///
/// The attribute looks like `#[field_name("protoName")]` where the string
/// literal `protoName` is the original name of the field in the .proto file.
struct FieldNameAttr {
    field_name: String,
}

impl FieldNameAttr {
    const ATTR_LABEL: &'static str = "field_name";

    fn new(attr: Attribute) -> Option<Self> {
        match attr.meta {
            syn::Meta::List(MetaList { path, tokens, .. }) if path.is_ident(Self::ATTR_LABEL) => {
                let str: LitStr = parse2(tokens).expect("not a string literal");
                Some(Self {
                    field_name: str.value(),
                })
            }
            _ => None,
        }
    }
}

/// Whether a field is a scalar or a container.
enum FieldType {
    Single,
    /// Some kind of wrapped field, or a `protobuf::SpecialFields`.
    Container,
}

impl From<syn::Type> for FieldType {
    fn from(value: syn::Type) -> Self {
        if let syn::Type::Path(TypePath { path, qself: None }) = value {
            let p = path.to_token_stream().to_string();
            if p.starts_with(&quote!(::std::vec::Vec).to_string()) {
                return FieldType::Container;
            }
            if p.starts_with(&quote!(::std::collections::HashMap).to_string()) {
                return FieldType::Container;
            }
            if p.starts_with(&quote!(::std::option::Option).to_string()) {
                return FieldType::Container;
            }
            if p.starts_with(&quote!(::protobuf::SpecialFields).to_string()) {
                return FieldType::Container;
            }
        }
        FieldType::Single
    }
}

#[cfg(test)]
mod test {
    use quote::ToTokens;
    use syn::parse_quote;
    use test_case::test_case;

    use super::*;

    fn message() -> (syn::DeriveInput, syn::ItemImpl) {
        (
            parse_quote! {
                struct Foo {
                    pub pub_field: bool,
                    priv_field: String,
                }
            },
            parse_quote! {
                impl crate::unknown::visit_static::VisitUnknownFields for Foo {
                    fn visit_unknown_fields(
                            &self,
                            path: crate::unknown::Path<'_>,
                            visitor: &mut impl crate::unknown::visit_static::Visitor)
                    {
                        let Self {
                            pub_field, priv_field
                        } = self;

                        {
                            let path = crate::unknown::Path::Branch {
                                parent: & path,
                                field_name: "pub_field",
                                part: crate::unknown::Part::Field,
                            };
                            crate::unknown::visit_static::VisitUnknownFields::visit_unknown_fields(pub_field, path, visitor)
                        };
                        {
                            let path = crate::unknown::Path::Branch {
                                parent: & path,
                                field_name: "priv_field",
                                part: crate::unknown::Part::Field,
                            };
                            crate::unknown::visit_static::VisitUnknownFields::visit_unknown_fields(priv_field, path, visitor)
                        };
                    }
                }
            },
        )
    }

    fn oneof() -> (syn::DeriveInput, syn::ItemImpl) {
        (
            parse_quote! {
                enum Foo {
                    AField(AField),
                    BField(BField),
                }
            },
            parse_quote! {
                impl crate::unknown::visit_static::VisitUnknownFields for Foo {
                    fn visit_unknown_fields(
                            &self,
                            path: crate::unknown::Path<'_>,
                            visitor: &mut impl crate::unknown::visit_static::Visitor)
                    {
                        match self {
                            Self::AField(a_field) => {
                                let path = crate::unknown::Path::Branch {
                                    parent: & path,
                                    field_name: "a_field",
                                    part: crate::unknown::Part::Field,
                                };
                                crate::unknown::visit_static::VisitUnknownFields::visit_unknown_fields(a_field, path, visitor)
                            },
                            Self::BField(b_field) => {
                                let path = crate::unknown::Path::Branch {
                                    parent: & path,
                                    field_name: "b_field",
                                    part: crate::unknown::Part::Field,
                                };
                                crate::unknown::visit_static::VisitUnknownFields::visit_unknown_fields(b_field, path, visitor)
                            },
                        };
                    }
                }
            },
        )
    }

    #[test_case(message)]
    #[test_case(oneof)]
    fn has_unknown_fields(input_and_output: fn() -> (syn::DeriveInput, syn::ItemImpl)) {
        let (type_definition, expected_impl) = input_and_output();

        let tokens = derive_visit_unknown_fields_impl(type_definition);
        println!("{tokens}");

        let output: syn::ItemImpl = syn::parse2(tokens).unwrap();

        assert!(
            output == expected_impl,
            "got:\n{}\nwanted:\n{}",
            output.to_token_stream(),
            expected_impl.to_token_stream()
        );
    }
}
