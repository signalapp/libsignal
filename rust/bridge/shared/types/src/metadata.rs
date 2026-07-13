//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! This module provides metadata about the bridge layer which will be consumed downstream for
//! various purposes:
//!
//! - To emit `Native.ts`, see `libsignal-node-native_ts`
//!
//! While some metadata facilities are shared, they're specialized to each client language.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt::Debug;

use derive_more::From;
// This is pub so that it can be used in bridge macros.
pub use linkme;
use linkme::distributed_slice;
use serde::Serialize;

/// If we're inserting a duplicate key, make sure that the new and old values equal.
pub fn insert_checked<T: Debug + Eq>(dst: &mut BTreeMap<String, T>, k: String, v: T) {
    match dst.entry(k) {
        Entry::Vacant(entry) => {
            entry.insert(v);
        }
        Entry::Occupied(entry) => assert_eq!(entry.get(), &v),
    }
}

pub fn remove_all_checked<T: Debug + Eq>(
    remove_from: &mut BTreeMap<String, T>,
    if_in: &BTreeMap<String, T>,
) {
    for (k, v) in if_in.iter() {
        if let Some(v2) = remove_from.remove(k) {
            assert_eq!(v, &v2, "key={k:?}");
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Struct<FieldType> {
    pub is_tuple: bool,
    /// `(name, type)`
    ///
    /// names should be `_0`, `_1`, ... for a tuple struct
    pub fields: Vec<(String, FieldType)>,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Enum<FieldType> {
    /// `(variant name, contents)`
    pub variants: Vec<(String, Struct<FieldType>)>,
}

pub type NiceType = String;

#[derive(From, Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum StructOrEnum<FieldType> {
    Struct(Struct<FieldType>),
    Enum(Enum<FieldType>),
}

#[cfg(feature = "node")]
pub mod node {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    pub struct TsArgConverter {
        /// What's the high-level typescript type?
        pub nice_type: NiceType,
        /// What's the low-level typescript type that gets passed to native?
        pub ffi_type: String,
        /// What function should be used to convert between the types?
        pub converter_function: String,
    }
    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    pub struct TsReturnConverter {
        /// What's the high-level typescript type?
        pub nice_type: NiceType,
        /// What's the low-level typescript type that gets passed to native?
        pub ffi_type: String,
        /// What function should be used to convert between the types?
        pub converter_function: String,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct NiceFunction {
        pub is_tokio_async: bool,
        /// (name, type)
        pub arguments: Vec<(String, TsArgConverter)>,
        pub return_type: TsReturnConverter,
    }

    #[derive(Debug, Clone, Serialize, Default)]
    pub struct TsMetadataContext {
        pub opaque_types: BTreeSet<String>,
        pub native_functions: BTreeMap<String, NativeFunction>,
        pub bridge_traits: BTreeMap<String, Vec<BridgeTraitFunction>>,
        pub nice_functions: BTreeMap<String, NiceFunction>,

        pub derived_types: BTreeMap<String, StructOrEnum<NiceType>>,
        pub derived_return_converters: BTreeMap<String, StructOrEnum<TsReturnConverter>>,
        pub derived_arg_converters: BTreeMap<String, StructOrEnum<TsArgConverter>>,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct NativeFunction {
        /// (name, type)
        pub arguments: Vec<(String, String)>,
        pub return_type: String,
    }
    #[derive(Debug, Clone, Serialize)]
    pub struct BridgeTraitFunction {
        pub name: String,
        pub body: NativeFunction,
    }

    /// These functions should mutate the attached [TsMetadataContext] to register their item.
    #[distributed_slice]
    pub static NODE_ITEMS: [FnWithModule<TsMetadataContext>];

    pub mod names {
        pub fn return_ffi_type(ty: &str) -> String {
            format!("ReturnFfi{ty}")
        }
        pub fn return_converter_function(ty: &str) -> String {
            format!("returnConverter{ty}")
        }
        pub fn arg_ffi_type(ty: &str) -> String {
            format!("ArgFfi{ty}")
        }
        pub fn arg_converter_function(ty: &str) -> String {
            format!("argConverter{ty}")
        }
    }

    /// See [crate::support]'s `transform_helper` for how this works, and the rationale.
    ///
    /// These functions provide the metadata-side (`register_ts_ffi_type()`) of `.ok_if_needed()`
    ///
    /// ```
    /// # use libsignal_bridge_types::metadata::node::result_type_helper::*;
    /// let x: ResultMetadataTransformHelper<i32> = Default::default();
    /// assert_eq!(x.register_ts_ffi_type(&mut Default::default()).as_str(), "number");
    /// let y: ResultMetadataTransformHelper<Result<i32, String>> = Default::default();
    /// assert_eq!(y.register_ts_ffi_type(&mut Default::default()).as_str(), "number");
    /// ```
    pub mod result_type_helper {
        use std::marker::PhantomData;

        use derive_where::derive_where;

        use super::*;
        use crate::node::{CallbackResultTypeInfo, NiceResultConverter, ResultTypeInfo};

        #[derive_where(Default)]
        pub struct ResultMetadataTransformHelper<T>(PhantomData<T>);
        impl<'a, T: ResultTypeInfo<'a>> ResultMetadataTransformHelper<T> {
            pub fn register_ts_ffi_type(&self, ctx: &mut TsMetadataContext) -> String {
                T::register_ts_ffi_type(ctx)
            }
        }
        impl<T: NiceResultConverter> ResultMetadataTransformHelper<T> {
            pub fn register_ts_result_converter(
                &self,
                ctx: &mut TsMetadataContext,
            ) -> TsReturnConverter {
                T::register_ts_result_converter(ctx)
            }
        }
        pub trait ResultMetadataTransformHelperTrait {
            fn register_ts_ffi_type(&self, ctx: &mut TsMetadataContext) -> String;
        }
        impl<'a, T: ResultTypeInfo<'a>, E> ResultMetadataTransformHelperTrait
            for ResultMetadataTransformHelper<Result<T, E>>
        {
            fn register_ts_ffi_type(&self, ctx: &mut TsMetadataContext) -> String {
                T::register_ts_ffi_type(ctx)
            }
        }
        pub trait ResultMetadataTransformHelperTraitConverter {
            fn register_ts_result_converter(
                &self,
                ctx: &mut TsMetadataContext,
            ) -> TsReturnConverter;
        }
        impl<T: NiceResultConverter, E> ResultMetadataTransformHelperTraitConverter
            for ResultMetadataTransformHelper<Result<T, E>>
        {
            fn register_ts_result_converter(
                &self,
                ctx: &mut TsMetadataContext,
            ) -> TsReturnConverter {
                T::register_ts_result_converter(ctx)
            }
        }
        #[derive_where(Default)]
        pub struct CallbackResultMetadataTransformHelper<T>(PhantomData<T>);

        impl<T: CallbackResultTypeInfo> CallbackResultMetadataTransformHelper<T> {
            pub fn register_ts_ffi_type(&self, ctx: &mut TsMetadataContext) -> String {
                T::register_ts_ffi_type(ctx)
            }
        }
        pub trait CallbackResultMetadataTransformHelperTrait {
            fn register_ts_ffi_type(&self, ctx: &mut TsMetadataContext) -> String;
        }
        impl<T: CallbackResultTypeInfo, E> CallbackResultMetadataTransformHelperTrait
            for CallbackResultMetadataTransformHelper<Result<T, E>>
        {
            fn register_ts_ffi_type(&self, ctx: &mut TsMetadataContext) -> String {
                T::register_ts_ffi_type(ctx)
            }
        }
    }
}

#[cfg(feature = "jni")]
pub mod jni {
    use std::collections::BTreeMap;

    use serde::Serialize;

    use super::*;

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    pub struct KtArgConverter {
        /// What's the high-level kotlin type?
        pub nice_type: String,
        /// What's the low-level kotlin type that gets passed to native?
        pub ffi_type: String,
        /// What's the kotlin spelling of the type that this type erases to (for a field lookup)
        pub ffi_field_type_erased: String,
        /// What function should be used to convert between the types?
        ///
        /// This will be invoked like `<converter_function>(my_value)`. As a result, instance
        /// methods should be specified like `"(Object::toString)"` so that they'll result in code
        /// like `(Object::toString)(my_value)`.
        pub converter_function: String,
    }
    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    pub struct KtReturnConverter {
        /// What's the high-level kotlin type?
        pub nice_type: String,
        /// What's the low-level kotlin type that gets passed to native?
        pub ffi_type: String,
        /// What function should be used to convert between the types?
        ///
        /// This will be invoked like `<converter_function>(my_value)`. As a result, instance
        /// methods should be specified like `"(Object::toString)"` so that they'll result in code
        /// like `(Object::toString)(my_value)`.
        pub converter_function: String,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct NiceFunction {
        pub is_tokio_async: bool,
        /// (name, type)
        pub arguments: Vec<(String, KtArgConverter)>,
        pub return_type: KtReturnConverter,
    }

    #[derive(Debug, Clone, Serialize, Default)]
    pub struct KtMetadataContext {
        pub nice_functions: BTreeMap<String, NiceFunction>,

        pub derived_types: BTreeMap<String, StructOrEnum<NiceType>>,
        pub derived_return_converters: BTreeMap<String, StructOrEnum<KtReturnConverter>>,
        pub derived_arg_converters: BTreeMap<String, StructOrEnum<KtArgConverter>>,
    }

    /// These functions should mutate the attached [KtMetadataContext] to register their item.
    #[distributed_slice]
    pub static JNI_ITEMS: [FnWithModule<KtMetadataContext>];

    pub mod result_type_helper {
        use std::marker::PhantomData;

        use derive_where::derive_where;

        use super::*;
        use crate::jni::NiceResultConverter;

        #[derive_where(Default)]
        pub struct ResultMetadataTransformHelper<T>(PhantomData<T>);
        impl<T: NiceResultConverter> ResultMetadataTransformHelper<T> {
            pub fn register_kt_result_converter(
                &self,
                ctx: &mut KtMetadataContext,
            ) -> KtReturnConverter {
                T::register_kt_result_converter(ctx)
            }
        }
        pub trait ResultMetadataTransformHelperTraitConverter {
            fn register_kt_result_converter(
                &self,
                ctx: &mut KtMetadataContext,
            ) -> KtReturnConverter;
        }
        impl<T: NiceResultConverter, E> ResultMetadataTransformHelperTraitConverter
            for ResultMetadataTransformHelper<Result<T, E>>
        {
            fn register_kt_result_converter(
                &self,
                ctx: &mut KtMetadataContext,
            ) -> KtReturnConverter {
                T::register_kt_result_converter(ctx)
            }
        }
    }
}

#[cfg(feature = "ffi")]
pub mod ffi;

pub struct FnWithModule<Ctx> {
    /// The module the function is defined in
    pub module_path: &'static str,
    pub apply: fn(&mut Ctx),
}

pub fn preserve_underscores(
    inner: impl Fn(&str) -> String + 'static,
) -> impl Fn(String) -> String + 'static {
    move |x| {
        let x_sans_underscore = x.trim_start_matches('_');
        let core = inner(x_sans_underscore);
        format!("{}{core}", &x[0..(x.len() - x_sans_underscore.len())])
    }
}
