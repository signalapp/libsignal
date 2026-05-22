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

// This is pub so that it can be used in bridge macros.
pub use linkme;
use linkme::distributed_slice;
use serde::Serialize;

#[cfg(feature = "node")]
pub mod node {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[derive(Debug, Clone, Serialize)]
    pub struct TsArgConverter {
        /// What's the high-level typescript type?
        pub nice_type: String,
        /// What's the low-level typescript type that gets passed to native?
        pub ffi_type: String,
        /// What function should be used to convert between the types?
        pub converter_function: String,
    }
    #[derive(Debug, Clone, Serialize)]
    pub struct TsReturnConverter {
        /// What's the high-level typescript type?
        pub nice_type: String,
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

    use linkme::distributed_slice;
    use serde::Serialize;

    use super::*;

    #[derive(Debug, Clone, Serialize)]
    pub struct KtArgConverter {
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

pub struct FnWithModule<Ctx> {
    /// The module the function is defined in
    pub module_path: &'static str,
    pub apply: fn(&mut Ctx),
}
