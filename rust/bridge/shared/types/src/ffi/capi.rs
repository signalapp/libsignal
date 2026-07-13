//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::alloc::Layout;
use std::marker::PhantomData;
#[cfg(feature = "metadata")]
use std::{collections::BTreeSet, sync::Arc};

#[cfg(feature = "metadata")]
use itertools::Itertools as _;
pub use libsignal_bridge_macros::{IsCType, c_export};

#[cfg(feature = "metadata")]
use crate::{ffi::SwiftMetadataContext, metadata::ffi::capi::*};

/// We only validate that we have the correct layout on 64-bit platforms.
pub const VALIDATE_LAYOUT: bool = {
    #[cfg(target_pointer_width = "64")]
    {
        true
    }
    #[cfg(target_pointer_width = "32")]
    {
        false
    }
};

pub const fn expect_valid_layout<T: Copy>(layout: Result<T, std::alloc::LayoutError>) -> T {
    if let Ok(layout) = layout {
        layout
    } else {
        panic!("Invalid layout")
    }
}

/// Just like a [`Layout`], except that the existance of this value witnesses the fact
/// that `T`'s layout matches the layout described in `layout`.
///
/// # Motivation
/// We emit `static_assert`s in `signal_ffi(_testing).h` to ensure that C's view of memory layout
/// matches Rust's. These assertions look like:
///
/// ```c
/// static_assert(sizeof(MyStruct) == 12, "");
/// static_assert(alignof(MyStruct) == 2, "");
/// static_assert(offsetof(MyStruct, x) == 6, "");
/// ```
///
/// These static asserts have constants computed at _metadata-generation-time_. So, to ensure that
/// metadata generation is platform-agnostic, these constants should be computed in a
/// platform-agnostic manner. Using Rust's built-in [`std::mem::size_of`] et al for this purpose
/// would only serve to ensure that the constants match the platform on which metadata was
/// generated.
///
/// So, we end up with this struct. We implement, in const-generic code, the standard C layout
/// algorithms. It is these platform-agnostically-generated constants which get checked against the
/// C layout. We separately generate const assertions that the Rust-side structs also match the
/// constants that we generate.
///
/// Note that this current generation assumes 8-byte pointers. This isn't an intrinsic limitation,
/// but it's acceptable for now, since we only build the FFI library for 64-bit platforms.
#[derive(Clone, Copy)]
pub struct CTypeMemoryLayoutTyped<T: ?Sized> {
    pub layout: Layout,
    phantom: PhantomData<*const T>,
}
impl<T> CTypeMemoryLayoutTyped<T> {
    /// Returns `(layout, field offsets)`
    pub const fn for_struct<const NUM_FIELDS: usize>(
        fields: [Layout; NUM_FIELDS],
    ) -> (Self, [usize; NUM_FIELDS]) {
        let mut layout = expect_valid_layout(Layout::from_size_align(0, 1));
        let mut offsets = [0; NUM_FIELDS];
        let mut i = 0;
        while i < NUM_FIELDS {
            let (new_layout, offset) = expect_valid_layout(layout.extend(fields[i]));
            layout = new_layout;
            offsets[i] = offset;
            i += 1;
        }
        (Self::from_layout(layout.pad_to_align()), offsets)
    }
    /// This function will panic if `layout` doesn't match the Rust layout for `T`.
    pub const fn from_layout(layout: Layout) -> Self {
        let actual_layout = Layout::new::<T>();
        if VALIDATE_LAYOUT {
            if layout.size() != actual_layout.size() {
                panic!("sizeof mismatch");
            }
            if layout.align() != actual_layout.align() {
                panic!("alignof mismatch");
            }
        }
        Self {
            layout,
            phantom: PhantomData,
        }
    }
    pub const fn new(size: usize, align: usize) -> Self {
        Self::from_layout(expect_valid_layout(Layout::from_size_align(size, align)))
    }
    pub const fn layout(&self) -> Layout {
        self.layout
    }
    pub const fn size(&self) -> usize {
        self.layout.size()
    }
    pub const fn align(&self) -> usize {
        self.layout.align()
    }
}

/// A type which can be C-bridged
///
/// # Safety
/// 1. Don't override `register_c_type`
/// 2. Don't call `register_c_type_inner` directly on other types (call `register_c_type`)
/// 3. The types and typedefs returned from `CType` must correctly model the Rust type
/// 4. If not treated as opaque, `Self` must have a stable `repr` (e.g. `repr(C)`)
pub unsafe trait IsCType: 'static {
    /// If present, what's the layout for the current type.
    ///
    /// This can be `None` for opaque types.
    const LAYOUT: Option<CTypeMemoryLayoutTyped<Self>>;

    #[cfg(feature = "metadata")]
    fn register_c_type_inner(ctx: &mut SwiftMetadataContext) -> CType;
    #[cfg(feature = "metadata")]
    fn register_c_type(ctx: &mut SwiftMetadataContext) -> Arc<CType> {
        let ty = RustType::of::<Self>();
        if let Some(out) = ctx.c_types.get(&ty) {
            return out.clone();
        }
        let cty = Arc::new(Self::register_c_type_inner(ctx));
        assert_eq!(ty, cty.rust_type);
        let old = ctx.c_types.insert(ty, cty.clone());
        assert!(old.is_none());
        cty
    }
}

macro_rules! c_type {
    ($ty:ty => $layout:expr, $cty:expr $(, $mangled:expr)?) => {
        unsafe impl IsCType for $ty {
            const LAYOUT: Option<CTypeMemoryLayoutTyped<Self>> = $layout;
            #[cfg(feature = "metadata")]
            fn register_c_type_inner(_ctx: &mut SwiftMetadataContext) -> CType {
                CType {
                    rust_type: RustType::of::<Self>(),
                    dependencies: Default::default(),
                    type_name: $cty.to_string(),
                    ptr_type_name: None,
                    mangling_component: {
                        #[allow(unused)]
                        let mut out = stringify!($ty);
                        $(out = $mangled;)?
                        out.to_string()
                    },
                    utility_typedefs: Default::default(),
                    layout: Self::LAYOUT.map(|layout| layout.layout),
                }
            }
        }
    };
}

const fn prim_layout<T>(size: usize) -> Option<CTypeMemoryLayoutTyped<T>> {
    Some(CTypeMemoryLayoutTyped::new(size, size))
}

// TODO: is this the right mapping?
c_type!(() => None, "void", "Unit");
c_type!(std::ffi::c_void => None, "void", "c_void");

c_type!(bool => prim_layout(1), "bool");
c_type!(f32 => prim_layout(4), "float");
c_type!(f64 => prim_layout(8), "double");
c_type!(isize => prim_layout(8), "ssize_t");
c_type!(i8 => prim_layout(1), "int8_t", "c_char");
c_type!(i16 => prim_layout(2), "int16_t");
c_type!(i32 => prim_layout(4), "int32_t");
c_type!(i64 => prim_layout(8), "int64_t");
c_type!(usize => prim_layout(8), "size_t");
c_type!(u8 => prim_layout(1), "uint8_t", "c_uchar");
c_type!(u16 => prim_layout(2), "uint16_t");
c_type!(u32 => prim_layout(4), "uint32_t");
c_type!(u64 => prim_layout(8), "uint64_t");

unsafe impl<T: IsCType> IsCType for *const T {
    const LAYOUT: Option<CTypeMemoryLayoutTyped<Self>> = prim_layout(8);
    #[cfg(feature = "metadata")]
    fn register_c_type_inner(ctx: &mut SwiftMetadataContext) -> CType {
        let t = T::register_c_type(ctx);
        let mut type_name = format!("SignalType_ConstPointer_{}", t.type_name);
        let mut mangling_component = t.mangling_component.clone();
        if t.rust_type == RustType::of::<std::ffi::c_char>() {
            mangling_component = "CStringPtr".to_string();
            type_name = format!("Signal{mangling_component}");
        }
        CType {
            rust_type: RustType::of::<Self>(),
            dependencies: BTreeSet::from_iter([t.rust_type]),
            type_name: type_name.clone(),
            ptr_type_name: Some(format!("const {}*", t.type_name)),
            // This isn't a good choice, but it stems from the configuration of cbindgen.
            mangling_component,
            utility_typedefs: format!("typedef const {}* {type_name};", t.type_name).into(),
            layout: Self::LAYOUT.map(|layout| layout.layout),
        }
    }
}

unsafe impl<T: IsCType> IsCType for *mut T {
    const LAYOUT: Option<CTypeMemoryLayoutTyped<Self>> = prim_layout(8);
    #[cfg(feature = "metadata")]
    fn register_c_type_inner(ctx: &mut SwiftMetadataContext) -> CType {
        let t = T::register_c_type(ctx);
        let type_name = format!("SignalType_MutPointer_{}", t.type_name);
        CType {
            rust_type: RustType::of::<Self>(),
            dependencies: BTreeSet::from_iter([t.rust_type]),
            type_name: type_name.clone(),
            ptr_type_name: Some(format!("{}*", t.type_name)),
            // This isn't a good choice, but it stems from the configuration of cbindgen.
            mangling_component: t.mangling_component.clone(),
            utility_typedefs: format!("typedef {}* {type_name};", t.type_name).into(),
            layout: Self::LAYOUT.map(|layout| layout.layout),
        }
    }
}

unsafe impl<T: IsCType, const N: usize> IsCType for [T; N] {
    const LAYOUT: Option<CTypeMemoryLayoutTyped<Self>> = const {
        let t = T::LAYOUT.expect("no opaque arrays");
        Some(CTypeMemoryLayoutTyped::new(t.size() * N, t.align()))
    };
    #[cfg(feature = "metadata")]
    fn register_c_type_inner(ctx: &mut SwiftMetadataContext) -> CType {
        let t = T::register_c_type(ctx);
        let type_name = format!("SignalType_FixedArray{N}_{}", t.type_name);
        CType {
            rust_type: RustType::of::<Self>(),
            dependencies: BTreeSet::from_iter([t.rust_type]),
            type_name: type_name.clone(),
            ptr_type_name: None,
            // This isn't a good choice, but it stems from the configuration of cbindgen.
            mangling_component: format!("{}{N}", t.mangling_component),
            utility_typedefs: format!("typedef {} {type_name}[{N}];", t.type_name).into(),
            layout: Self::LAYOUT.map(|layout| layout.layout),
        }
    }
}

macro_rules! function_types {
    (@{$($unsafe:tt)?} $($arg_types:ident),*) => {
        unsafe impl<ReturnType: IsCType, $($arg_types: IsCType),*> IsCType for $($unsafe)? extern "C" fn($($arg_types),*) -> ReturnType {
            const LAYOUT: Option<CTypeMemoryLayoutTyped<Self>> = prim_layout(8);
            #[cfg(feature="metadata")]
            fn register_c_type_inner(ctx: &mut SwiftMetadataContext) -> CType {
                let rt = ReturnType::register_c_type(ctx);
                let args: Vec<Arc<CType>> = vec![$($arg_types::register_c_type(ctx)),*];
                let unsafe_ = if stringify!($($unsafe)?).is_empty() {
                    ""
                } else {
                    "Unsafe"
                };
                let type_name = format!(
                    "SignalType_{unsafe_}FunctionPointer_{}_{}",
                    rt.type_name,
                    args.iter().map(|arg| &arg.type_name).join("_")
                );
                CType {
                    rust_type: RustType::of::<Self>(),
                    dependencies: BTreeSet::from_iter(
                        std::iter::once(rt.rust_type).chain(args.iter().map(|ty| ty.rust_type)),
                    ),
                    type_name: type_name.clone(),
                    ptr_type_name: None,
                    // We didn't use function pointers in generics with cbindgen, so we can do
                    // whatever we want here.
                    mangling_component: type_name.clone(),
                    utility_typedefs: format!(
                        "typedef {} (*{type_name})({});",
                        rt.type_name,
                        if args.is_empty() {
                            "void".to_string()
                        } else {
                            args.iter().map(|arg| &arg.type_name).join(", ")
                        }
                    ).into(),
                    layout: Self::LAYOUT.map(|layout| layout.layout),
                }
            }
        }
    };
    ($([$($arg_types:ident),*$(,)?]),*$(,)?) => {
        $(
            function_types!(@{} $($arg_types),*);
            function_types!(@{unsafe} $($arg_types),*);
        )*
    };
}
function_types! {
    [],
    [A],
    [A, B],
    [A, B, C],
    [A, B, C, D],
    [A, B, C, D, E],
    [A, B, C, D, E, F],
    [A, B, C, D, E, F, G],
}
