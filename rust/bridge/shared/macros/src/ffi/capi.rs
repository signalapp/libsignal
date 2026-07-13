//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use itertools::Itertools;
use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, format_ident, quote};
use syn::{DeriveInput, Expr, ExprLit, Fields, ItemFn, Lit, LitStr, Pat, parse_quote};

use crate::util::{DeriveInputInfo, Impl, crates, result_type};

pub fn derive_is_c_type(input: &DeriveInput) -> syn::Result<TokenStream> {
    let krate = crates::libsignal_bridge_types();
    let mut trait_impl = Impl::new(
        input,
        &input.ident.clone().into(),
        Some(parse_quote!(#krate::ffi::capi::IsCType)),
    );
    trait_impl.mark_unsafe();
    let mut export_name = input.ident.to_string();
    let mut export_name_override: Option<syn::Path> = None;
    let mut is_opaque = false;
    let mut must_export = false;
    for attr in input.attrs.iter() {
        if !attr.path().is_ident("capi") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("opaque") {
                is_opaque = true;
                Ok(())
            } else if meta.path.is_ident("must_export") {
                must_export = true;
                Ok(())
            } else if meta.path.is_ident("export_name") {
                export_name = meta.value()?.parse::<LitStr>()?.value();
                Ok(())
            } else if meta.path.is_ident("export_name_override") {
                export_name_override = Some(meta.value()?.parse()?);
                Ok(())
            } else {
                Err(syn::Error::new_spanned(&meta.path, "Invalid option"))
            }
        })?;
    }
    let DeriveInputInfo {
        variant_names,
        field_names,
        field_types,
        ..
    } = DeriveInputInfo::new(input, &input.ident.clone().into());
    let mut validation = None;
    let (utility_typedefs, layout) = if is_opaque {
        (
            quote! {
                format!("typedef struct {type_name} {type_name};").into()
            },
            quote!(None),
        )
    } else {
        let repr = Repr::from_input(input)?;
        match &input.data {
            syn::Data::Struct(data) => match repr {
                Repr::C => {
                    let field_names: Vec<_> = data
                        .fields
                        .iter()
                        .enumerate()
                        .map::<syn::Result<String>, _>(|(i, field)| {
                            let mut name = field
                                .ident
                                .as_ref()
                                .map(|ident| ident.to_string())
                                .unwrap_or_else(|| format!("_{i}"));
                            for attr in &field.attrs {
                                if !attr.path().is_ident("capi") {
                                    continue;
                                }
                                attr.parse_nested_meta(|meta| {
                                    if meta.path.is_ident("rename") {
                                        name = meta.value()?.parse::<LitStr>()?.value();
                                        Ok(())
                                    } else {
                                        Err(syn::Error::new_spanned(&meta.path, "Invalid option"))
                                    }
                                })?;
                            }
                            Ok(name)
                        })
                        .try_collect()?;
                    let field_types = data.fields.iter().map(|field| &field.ty).collect_vec();
                    let field_layouts = quote!(const {
                        [#(
                            <#field_types as #krate::ffi::capi::IsCType>::LAYOUT
                                .expect("Struct fields can't be opaque").layout,
                        )*]
                    });
                    let field_indices = (0..data.fields.len()).collect_vec();
                    let members = data.fields.members().collect_vec();
                    (
                        quote! {{
                            let offsets = CTypeMemoryLayoutTyped::<Self>::for_struct(#field_layouts).1;
                            #krate::metadata::ffi::capi::UtilityTypedef::StructTypedef {
                                type_name: type_name.clone(),
                                fields: vec![
                                    #((
                                        #field_names.to_string(),
                                        <#field_types as IsCType>::register_c_type(ctx).ptr_type_name().clone(),
                                        offsets[#field_indices],
                                    ),)*
                                ],
                            }
                        }},
                        quote! {
                            let (layout, offsets) = CTypeMemoryLayoutTyped::<Self>::for_struct(#field_layouts);
                            if VALIDATE_LAYOUT {
                                #(assert!(
                                    std::mem::offset_of!(Self, #members) == offsets[#field_indices]
                                );)*
                            }
                            Some(layout)
                        },
                    )
                }
                Repr::Transparent => {
                    if data.fields.len() != 1 {
                        return Err(syn::Error::new_spanned(
                            input,
                            "We only (currently) support #[repr(transparent)] structs with one field.",
                        ));
                    }
                    let ty = &data.fields.iter().next().expect("exactly one field").ty;
                    (
                        quote! {
                            format!("typedef {} {type_name};", <#ty as IsCType>::register_c_type(ctx).ptr_type_name())
                        },
                        quote! {
                            if let Some(layout) = <#ty as IsCType>::LAYOUT {
                                Some(CTypeMemoryLayoutTyped::from_layout(layout.layout()))
                            } else {
                                None
                            }
                        },
                    )
                }
                Repr::U8 => {
                    return Err(syn::Error::new_spanned(
                        input,
                        "We only support #[repr(C)] and #[repr(transparent)] for structs",
                    ));
                }
            },
            syn::Data::Enum(data) => {
                let has_payloads = !data
                    .variants
                    .iter()
                    .all(|variant| matches!(&variant.fields, Fields::Unit));
                let values: Vec<_> = data
                    .variants
                    .iter()
                    .scan(0, |default_next_value, variant| {
                        Some(
                            match &variant.discriminant {
                                Some((
                                    _,
                                    Expr::Lit(ExprLit {
                                        lit: Lit::Int(lit), ..
                                    }),
                                )) => lit.base10_parse::<i32>(),
                                Some((_, expr)) => {
                                    Err(syn::Error::new_spanned(expr, "Expected int literal"))
                                }
                                None => Ok(*default_next_value),
                            }
                            .inspect(|new_value| *default_next_value = new_value + 1),
                        )
                    })
                    .try_collect()?;
                if has_payloads {
                    if repr != Repr::C {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            "#[repr(C)] is required on enums with payloads",
                        ));
                    }
                    (
                        quote! {
                            #krate::metadata::ffi::capi::UtilityTypedef::EnumWithPayloads {
                                type_name: type_name.clone(),
                                ty: #krate::metadata::Enum {
                                    variants: vec![
                                        #((
                                            stringify!(#variant_names).to_string(),
                                            #krate::metadata::Struct {
                                                is_tuple: false, // ignored for the C struct
                                                fields: vec![#(
                                                    (
                                                        stringify!(#field_names).to_string(),
                                                        <#field_types as IsCType>::register_c_type(ctx).ptr_type_name().clone(),
                                                    )
                                                ),*],
                                            },
                                        )),*
                                    ],
                                }
                            }
                        },
                        quote! {
                            Some(CTypeMemoryLayoutTyped::<Self>::for_struct([
                                <i32 as IsCType>::LAYOUT.expect("i32 isn't opaque").layout(),
                                {
                                    // Compute the layout for a C union of all the variants.
                                    // size, align represent the size and alignment of the final
                                    // union.
                                    let size = 0;
                                    let align = 1;
                                    #(
                                        // For this particular variant, what's its layout?
                                        let variant = expect_valid_layout(std::alloc::Layout::from_size_align(
                                            0, 1
                                        ));
                                        #(let variant = expect_valid_layout(
                                            variant.extend(
                                                <#field_types as IsCType>::LAYOUT
                                                .expect("enum payload isn't opaque")
                                                .layout()
                                            )
                                        ).0;)*
                                        let variant = variant.pad_to_align();
                                        // The size/align of the union is the max size/align of any
                                        // of its components.
                                        let size =
                                            if variant.size() > size { variant.size() } else { size };
                                        let align =
                                            if variant.align() > align { variant.align() } else { align };
                                    )*
                                    expect_valid_layout(std::alloc::Layout::from_size_align(
                                        size, align
                                    )).pad_to_align()
                                }
                            ]).0)
                        },
                    )
                } else {
                    let (repr_ty, crepr_ty) = match repr {
                        Repr::C => (quote!(None), quote!(i32)),
                        Repr::U8 => (quote!(Some("uint8_t".to_string())), quote!(u8)),
                        Repr::Transparent => {
                            return Err(syn::Error::new(
                                Span::call_site(),
                                "#[repr(transparent)] doesn't make sense on an enum",
                            ));
                        }
                    };
                    let ident = &input.ident;
                    validation = Some(quote! {
                        #(if #ident::#variant_names as i128 != #values as i128 {
                            panic!(concat!(
                                "Variant value mismatch ",
                                stringify!(#ident), "::", stringify!(#variant_names),
                            ));
                        })*
                    });
                    (
                        quote! {
                            #krate::metadata::ffi::capi::UtilityTypedef::EnumWithoutPayloads{
                                type_name: type_name.clone(),
                                variants: vec![#(
                                    (stringify!(#variant_names).to_string(), #values as i128),
                                )*],
                                repr_ty: #repr_ty,
                            }
                        },
                        quote!(Some(CTypeMemoryLayoutTyped::new(
                            <#crepr_ty as IsCType>::LAYOUT.expect("repr isn't opaque").size(),
                            <#crepr_ty as IsCType>::LAYOUT.expect("repr isn't opaque").align(),
                        ))),
                    )
                }
            }
            syn::Data::Union(_data) => {
                if repr != Repr::C {
                    return Err(syn::Error::new_spanned(input, "Union must be repr(C)"));
                }
                return Err(syn::Error::new_spanned(input, "Union not yet implemented"));
            }
        }
    };
    let must_export = if must_export {
        let ident = &input.ident;
        let md = quote!(#krate::metadata);
        quote! {
            #[cfg(all(feature = "ffi", feature = "metadata"))]
            const _: () = {
                #[#md::linkme::distributed_slice(#md::ffi::FFI_ITEMS)]
                #[linkme(crate = #md::linkme)]
                static _METADATA: #md::FnWithModule<#md::ffi::SwiftMetadataContext> = #md::FnWithModule {
                    module_path: module_path!(),
                    apply: |ctx| {
                        <#ident as #krate::ffi::capi::IsCType>::register_c_type(ctx);
                    }
                };
            };
        }
    } else {
        quote!()
    };
    let dependencies = if is_opaque {
        quote!(Default::default())
    } else {
        quote!(std::collections::BTreeSet::from_iter([
            #(#(
                <#field_types as IsCType>::register_c_type(ctx).rust_type,
            )*)*
        ]))
    };
    let generics_names = input
        .generics
        .type_params()
        .map(|ty| &ty.ident)
        .collect_vec();
    trait_impl.extra_where.extend(
        generics_names
            .iter()
            .map(|ty| parse_quote!(#ty: #krate::ffi::capi::IsCType)),
    );
    let export_name_override = export_name_override.map(|export_name_override| {
        quote! {
            if let Some(x) = #export_name_override([
                #(<#generics_names as #krate::ffi::capi::IsCType>::register_c_type(ctx),)*
            ]) {
                mangling_component = x;
            }
        }
    });
    Ok(quote! {
        #must_export
        #[cfg(feature = "ffi")]
        const _: () = {
            #[cfg(feature = "metadata")]
            use #krate::metadata::insert_checked;
            #[cfg(feature = "metadata")]
            use #krate::metadata::ffi::*;
            #[cfg(feature = "metadata")]
            use #krate::metadata::ffi::capi::*;
            use #krate::ffi::capi::*;
            #validation
            #trait_impl {
                const LAYOUT: Option<CTypeMemoryLayoutTyped<Self>> = const { #layout };
                #[cfg(feature = "metadata")]
                fn register_c_type_inner(
                    ctx: &mut SwiftMetadataContext
                ) -> CType {
                    #[allow(unused)]
                    let mut mangling_component = #export_name.to_string();
                    #(
                        mangling_component.push_str(
                            &<#generics_names as IsCType>::register_c_type(ctx).mangling_component
                        );
                    )*
                    #export_name_override
                    let type_name = format!("Signal{mangling_component}");
                    let utility_typedefs = #utility_typedefs;
                    CType {
                        rust_type: RustType::of::<Self>(),
                        dependencies: #dependencies,
                        type_name,
                        ptr_type_name: None,
                        mangling_component,
                        utility_typedefs,
                        layout: Self::LAYOUT.map(|layout| layout.layout),
                    }
                }
            }
        };
    })
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Repr {
    C,
    U8,
    Transparent,
}

impl Repr {
    fn from_input(input: &DeriveInput) -> syn::Result<Repr> {
        let mut out = None;
        for attr in input.attrs.iter() {
            if attr.path().is_ident("repr") {
                attr.parse_nested_meta(|meta| {
                    let new_repr = if meta.path.is_ident("C") {
                        Repr::C
                    } else if meta.path.is_ident("transparent") {
                        Repr::Transparent
                    } else if meta.path.is_ident("u8") {
                        Repr::U8
                    } else {
                        return Err(syn::Error::new_spanned(
                            input,
                            "Expected #[repr(C)] or #[repr(u8)] or #[repr(transparent)]",
                        ));
                    };
                    if let Some(out) = out
                        && out != new_repr
                    {
                        return Err(syn::Error::new_spanned(
                            &meta.path,
                            format!("Conflicting reprs {out:?} and {new_repr:?}"),
                        ));
                    }
                    out = Some(new_repr);
                    Ok(())
                })?;
            }
        }
        out.ok_or_else(|| syn::Error::new_spanned(input, "Missing #[repr]"))
    }
}

pub fn c_export(attr: &TokenStream, item: &TokenStream) -> syn::Result<TokenStream> {
    let krate = crates::libsignal_bridge_types();
    let md = quote!(#krate::metadata);
    if let Ok(item) = syn::parse2::<syn::ItemType>(item.clone()) {
        let ident = &item.ident;
        let target = &item.ty;
        let mut export_name = ident.to_string();
        syn::parse::Parser::parse2(
            syn::meta::parser(|meta| {
                if meta.path.is_ident("export_name") {
                    export_name = meta.value()?.parse::<LitStr>()?.value();
                    Ok(())
                } else {
                    Err(meta.error("unsupported property"))
                }
            }),
            attr.clone(),
        )?;
        return Ok(quote! {
            #[allow(unused)]
            #item
            #[cfg(all(feature = "ffi", feature = "metadata"))]
            const _: () = {
                #[#md::linkme::distributed_slice(#md::ffi::FFI_ITEMS)]
                #[linkme(crate = #md::linkme)]
                static _METADATA: #md::FnWithModule<#md::ffi::SwiftMetadataContext> = #md::FnWithModule {
                    module_path: module_path!(),
                    apply: |ctx| {
                        use #krate::ffi::capi::IsCType;
                        use #md::ffi::*;
                        use #md::ffi::capi::*;
                        let contents = <#target as IsCType>::register_c_type(ctx);
                        ctx.c_extra_typedefs.insert(
                            format!("typedef {} Signal{};", contents.ptr_type_name(), #export_name)
                        );
                    }
                };
            };
        });
    }
    let item: ItemFn = syn::parse2(item.clone())?;
    if item
        .sig
        .abi
        .as_ref()
        .and_then(|abi| abi.name.as_ref())
        .is_none_or(|abi| abi.value().as_str() != "C")
    {
        return Err(syn::Error::new_spanned(
            item.sig.fn_token,
            "Missing extern \"C\"",
        ));
    }
    let mut name = None;
    for attr in item.attrs.iter() {
        if attr.path().is_ident("unsafe") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("no_mangle") {
                    let ident = &item.sig.ident;
                    if name.is_some() {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            "Conflicting mangling directives",
                        ));
                    }
                    name = Some(quote!(stringify!(#ident)));
                } else if meta.path.is_ident("export_name") {
                    let expr: Expr = meta.value()?.parse()?;
                    name = Some(expr.to_token_stream());
                }
                Ok(())
            })?;
        }
    }
    let name = name
        .ok_or_else(|| syn::Error::new(Span::call_site(), "Missing export mangling directive"))?;
    let mut arg_names = Vec::new();
    let mut arg_types = Vec::new();
    for (i, input) in item.sig.inputs.iter().enumerate() {
        match input {
            syn::FnArg::Receiver(receiver) => {
                return Err(syn::Error::new_spanned(
                    receiver,
                    "Function cannot take Self",
                ));
            }
            syn::FnArg::Typed(pat_type) => {
                arg_types.push(&pat_type.ty);
                arg_names.push(match &*pat_type.pat {
                    Pat::Ident(pat_ident) => pat_ident.ident.clone(),
                    _ => format_ident!("_{i}"),
                });
            }
        }
    }
    let result = result_type(&item.sig.output);
    Ok(quote! {
        #item
        #[cfg(all(feature = "ffi", feature = "metadata"))]
        const _: () = {
            use #krate::ffi::capi::IsCType;
            use #md::ffi::*;
            use #md::ffi::capi::*;
            #(let _ = <#arg_types as IsCType>::LAYOUT.expect("argument isn't opaque");)*
            let _ = <#result as IsCType>::LAYOUT;
            #[#md::linkme::distributed_slice(#md::ffi::FFI_ITEMS)]
            #[linkme(crate = #md::linkme)]
            static _METADATA: #md::FnWithModule<#md::ffi::SwiftMetadataContext> = #md::FnWithModule {
                module_path: module_path!(),
                apply: |ctx| {
                    let proto = CFunctionPrototype {
                        result: <#result as IsCType>::register_c_type(ctx),
                        args: vec![#(
                            (
                                stringify!(#arg_names).to_string(),
                                <#arg_types as IsCType>::register_c_type(ctx),
                            )
                        ),*],
                    };
                    let name = #name;
                    #md::insert_checked(&mut ctx.c_functions, name.into(), proto);
                }
            };
        };
    })
}
