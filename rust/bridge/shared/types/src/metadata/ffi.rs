use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::Serialize;

use super::*;
pub mod capi;

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

    pub c_types: BTreeMap<capi::RustType, Arc<capi::CType>>,
    pub c_struct_offsets: BTreeMap<capi::RustType, BTreeMap<String, usize>>,
    pub c_functions: BTreeMap<String, capi::CFunctionPrototype>,
    pub c_extra_typedefs: BTreeSet<String>,
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
