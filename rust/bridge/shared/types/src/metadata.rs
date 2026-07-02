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
pub mod ffi {
    use std::collections::{BTreeMap, BTreeSet};

    use serde::Serialize;

    use super::*;

    #[derive(Debug, Clone, Serialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
    pub struct SwiftArgConverter {
        /// What's the high-level swift type?
        pub nice_type: String,
        /// What's the type which implements the Swift `ArgConverter` protocol
        pub converter_type: String,
    }
    #[derive(Debug, Clone, Serialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
    pub struct SwiftReturnConverter {
        /// What's the high-level swift type?
        pub nice_type: String,
        /// What's the type which implements the Swift `ResultConverter` protocol
        pub converter_type: String,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct NiceFunction {
        pub is_tokio_async: bool,
        /// (name, type)
        pub arguments: Vec<(String, SwiftArgConverter)>,
        pub return_type: SwiftReturnConverter,
    }

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    pub struct FfiBorrowedSliceConstructor {
        pub converter_type: String,
        pub borrowed_slice: String,
    }

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    pub struct FfiOwnedBufferOfMaxAlignedProject {
        pub converter_type: String,
        pub buffer_type: String,
    }

    #[derive(Debug, Clone, Serialize, Default)]
    pub struct SwiftMetadataContext {
        pub nice_functions: BTreeMap<String, NiceFunction>,

        pub fixed_byte_array_lengths: BTreeSet<usize>,

        pub derived_types: BTreeMap<String, StructOrEnum<NiceType>>,
        pub derived_return_converters: BTreeMap<String, StructOrEnum<SwiftReturnConverter>>,
        pub derived_arg_converters: BTreeMap<String, StructOrEnum<SwiftArgConverter>>,

        /// Map from the name of a `FfiBorrowedSliceConstructor` to information about the constructor
        pub ffi_borrowed_slice_cons: BTreeMap<String, FfiBorrowedSliceConstructor>,
        /// Map from the name of a `FfiOwnedBufferOfMaxAlignedProject` to information about the constructor
        pub ffi_owned_buffer_of_max_aligned_project:
            BTreeMap<String, FfiOwnedBufferOfMaxAlignedProject>,
    }

    /// How would cbindgen mangle this rust type?
    pub fn cbindgen_mangle<T>() -> String {
        let partial = cbindgen_mangle_partial(std::any::type_name::<T>());
        match partial.as_str() {
            "BorrowedSliceOfi8" => "SignalBorrowedSliceOfc_char".to_string(),
            "BorrowedSliceOfu8" => "SignalBorrowedBuffer".to_string(),
            "BorrowedSliceOfBorrowedSliceOfu8" => "SignalBorrowedSliceOfBuffers".to_string(),
            "BorrowedMutableSliceOfu8" => "SignalBorrowedMutableBuffer".to_string(),
            "OwnedBufferOfu8" => "SignalOwnedBuffer".to_string(),
            _ => format!("Signal{}", partial),
        }
    }
    fn cbindgen_mangle_partial(input: &str) -> String {
        // This is a rough approximation of the actual algorithm
        #[derive(Clone, Debug, PartialEq, Eq)]
        enum Token {
            Path(String),
            LAngle,
            RAngle,
            Comma,
        }
        let mut current_path = String::new();
        let mut tokens = Vec::new();
        // We set remove_underscores in the cbindgen config, so the encoding is ambiguous, but
        // also we can eliminate a bunch of tokens which don't make it into the final C type.
        for ch in input
            .replace("*const i8", "CStringPtr")
            .replace("*const ", "")
            .replace("*mut ", "")
            .replace(['[', ']', ';'], "")
            .chars()
        {
            if ch == ':' || ch == '_' || ch.is_alphanumeric() {
                current_path.push(ch);
            } else if ch.is_whitespace() {
                continue;
            } else {
                if !current_path.is_empty() {
                    tokens.push(Token::Path(std::mem::take(&mut current_path)));
                }
                tokens.push(match ch {
                    '<' => Token::LAngle,
                    '>' => Token::RAngle,
                    ',' => Token::Comma,
                    _ => panic!("Unexpected character {ch:?} in {input:?}"),
                });
            }
        }
        if !current_path.is_empty() {
            tokens.push(Token::Path(std::mem::take(&mut current_path)));
        }
        let mut tokens = tokens.into_iter().peekable();
        type Tokens = std::iter::Peekable<std::vec::IntoIter<Token>>;
        fn parse_type(tokens: &mut Tokens) -> String {
            let token = tokens.next();
            let Some(Token::Path(path)) = token else {
                panic!("Unexpected token {token:?}")
            };
            let path = path
                .rsplit_once("::")
                .map(|(_, last)| last)
                .unwrap_or(&path);
            let mut parts = vec![path.to_string()];
            if let Some(Token::LAngle) = tokens.peek() {
                let _langle = tokens.next();
                while tokens.peek() != Some(&Token::RAngle) {
                    if tokens.peek() == Some(&Token::Comma) {
                        let _comma = tokens.next();
                        continue;
                    }
                    parts.push(parse_type(tokens));
                }
                assert_eq!(tokens.next(), Some(Token::RAngle));
            }
            parts.join("")
        }
        parse_type(&mut tokens)
    }

    /// These functions should mutate the attached [SwiftMetadataContext] to register their item.
    #[distributed_slice]
    pub static FFI_ITEMS: [FnWithModule<SwiftMetadataContext>];

    pub mod result_type_helper {
        use std::marker::PhantomData;

        use derive_where::derive_where;

        use super::*;
        use crate::ffi::NiceResultConverter;

        #[derive_where(Default)]
        pub struct ResultMetadataTransformHelper<T>(PhantomData<T>);
        impl<T: NiceResultConverter> ResultMetadataTransformHelper<T> {
            pub fn register_swift_result_converter(
                &self,
                ctx: &mut SwiftMetadataContext,
            ) -> SwiftReturnConverter {
                T::register_swift_result_converter(ctx)
            }
        }
        pub trait ResultMetadataTransformHelperTraitConverter {
            fn register_swift_result_converter(
                &self,
                ctx: &mut SwiftMetadataContext,
            ) -> SwiftReturnConverter;
        }
        impl<T: NiceResultConverter, E> ResultMetadataTransformHelperTraitConverter
            for ResultMetadataTransformHelper<Result<T, E>>
        {
            fn register_swift_result_converter(
                &self,
                ctx: &mut SwiftMetadataContext,
            ) -> SwiftReturnConverter {
                T::register_swift_result_converter(ctx)
            }
        }
    }
    pub mod names {
        pub fn return_converter(ty: &str) -> String {
            format!("DerivedReturnConverter{ty}")
        }
        pub fn arg_converter(ty: &str) -> String {
            format!("DerivedArgConverter{ty}")
        }
        pub fn fixed_byte_array_helper(len: usize) -> String {
            format!("FixedByteArrayHelper{len}")
        }
    }
}

pub struct FnWithModule<Ctx> {
    /// The module the function is defined in
    pub module_path: &'static str,
    pub apply: fn(&mut Ctx),
}
