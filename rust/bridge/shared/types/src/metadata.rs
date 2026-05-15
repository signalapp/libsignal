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

    #[derive(Debug, Clone, Serialize, Default)]
    pub struct TsMetadataContext {
        pub opaque_types: BTreeSet<String>,
        pub native_functions: BTreeMap<String, NativeFunction>,
        pub bridge_traits: BTreeMap<String, Vec<BridgeTraitFunction>>,
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

        use crate::metadata::node::TsMetadataContext;
        use crate::node::{CallbackResultTypeInfo, ResultTypeInfo};

        #[derive_where(Default)]
        pub struct ResultMetadataTransformHelper<T>(PhantomData<T>);
        impl<'a, T: ResultTypeInfo<'a>> ResultMetadataTransformHelper<T> {
            pub fn register_ts_ffi_type(&self, ctx: &mut TsMetadataContext) -> String {
                T::register_ts_ffi_type(ctx)
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

pub struct FnWithModule<Ctx> {
    /// The module the function is defined in
    pub module_path: &'static str,
    pub apply: fn(&mut Ctx),
}
