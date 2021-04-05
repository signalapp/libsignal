//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libc::{c_char, c_uchar, c_void};
use libsignal_protocol::*;
use paste::paste;
use std::ffi::CStr;
use std::{borrow::Cow, ops::Deref};

use super::*;

/// Converts arguments from their FFI form to their Rust form.
///
/// `ArgTypeInfo` has two required methods: `borrow` and `load_from`. The use site looks like this:
///
/// ```
/// # use libsignal_bridge::ffi::*;
/// # struct Foo;
/// # impl SimpleArgTypeInfo for Foo {
/// #     type ArgType = isize;
/// #     fn convert_from(foreign: isize) -> SignalFfiResult<Self> { Ok(Foo) }
/// # }
/// # fn main() -> SignalFfiResult<()> {
/// #     let ffi_arg = 2;
/// let mut ffi_arg_borrowed = Foo::borrow(ffi_arg)?;
/// let rust_arg = Foo::load_from(&mut ffi_arg_borrowed)?;
/// #     Ok(())
/// # }
/// ```
///
/// `ArgTypeInfo` is used to implement the `bridge_fn` macro, but can also be used outside it.
///
/// If the Rust type can be directly loaded from `ArgType` with no local storage or lifetime needed,
/// implement [`SimpleArgTypeInfo`] instead.
///
/// Implementers should also see the `ffi_arg_type` macro in `convert.rs`.
pub trait ArgTypeInfo<'storage>: Sized {
    /// The FFI form of the argument (e.g. `libc::c_uchar`).
    type ArgType;
    /// Local storage for the argument (ideally borrowed rather than copied).
    type StoredType: 'storage;
    /// "Borrows" the data in `foreign`, usually to establish a local lifetime or owning type.
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType>;
    /// Loads the Rust value from the data that's been `stored` by [`borrow()`](Self::borrow()).
    fn load_from(stored: &'storage mut Self::StoredType) -> SignalFfiResult<Self>;
}

/// A simpler interface for [`ArgTypeInfo`] for when no local storage is needed.
///
/// This trait is easier to use when writing FFI functions manually:
///
/// ```
/// # use libsignal_bridge::ffi::*;
/// # struct Foo;
/// impl SimpleArgTypeInfo for Foo {
///     type ArgType = isize;
///     fn convert_from(foreign: isize) -> SignalFfiResult<Self> {
///         // ...
///         # Ok(Foo)
///     }
/// }
///
/// # fn main() -> SignalFfiResult<()> {
/// #     let ffi_arg = 2;
/// let rust_arg = Foo::convert_from(ffi_arg)?;
/// #     Ok(())
/// # }
/// ```
///
/// However, some types do need the full flexibility of `ArgTypeInfo`.
pub trait SimpleArgTypeInfo: Sized {
    /// The FFI form of the argument (e.g. `libc::c_uchar`).
    ///
    /// Must be [`Copy`] to help the compiler optimize out local storage.
    type ArgType: Copy;
    /// Converts the data in `foreign` to the Rust type.
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self>;
}

impl<'a, T> ArgTypeInfo<'a> for T
where
    T: SimpleArgTypeInfo,
    T::ArgType: 'a,
{
    type ArgType = <Self as SimpleArgTypeInfo>::ArgType;
    type StoredType = Self::ArgType;
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        Ok(foreign)
    }
    fn load_from(stored: &'a mut Self::StoredType) -> SignalFfiResult<Self> {
        Self::convert_from(*stored)
    }
}

/// Converts "sized" arguments from their FFI form to their Rust form.
///
/// This is used for buffers and such passed as a base+length pair. Implementing types are usually
/// slices; the `ArgType` will usually be a pointer.
///
/// `SizedArgTypeInfo` is used to implement the `bridge_fn` macro for slice-typed arguments, but
/// can also be used outside it.
///
/// ```
/// # use libsignal_bridge::ffi::*;
/// # struct Foo;
/// # impl SizedArgTypeInfo for Foo {
/// #     type ArgType = isize;
/// #     fn convert_from(foreign: isize, size: usize) -> SignalFfiResult<Self> { Ok(Foo) }
/// # }
/// # fn main() -> SignalFfiResult<()> {
/// #     let ffi_arg = 2;
/// #     let ffi_arg_len = 3;
/// let rust_arg = Foo::convert_from(ffi_arg, ffi_arg_len)?;
/// #     Ok(())
/// # }
/// ```
pub trait SizedArgTypeInfo: Sized {
    /// The FFI form of the "base" argument (e.g. `*const u8`).
    ///
    /// Note that the "length" argument type is not customizable; it is always `usize`
    /// (`size_t` in C).
    type ArgType;
    /// Converts the data in `foreign` to the Rust type.
    fn convert_from(foreign: Self::ArgType, size: usize) -> SignalFfiResult<Self>;
}

/// Converts result values from their Rust form to their FFI form.
///
/// `ResultTypeInfo` is used to implement the `bridge_fn` macro, but can also be used outside it.
///
/// ```
/// # use libsignal_bridge::ffi::*;
/// # struct Foo;
/// # impl ResultTypeInfo for Foo {
/// #     type ResultType = isize;
/// #     fn convert_into(self) -> SignalFfiResult<isize> { Ok(1) }
/// # }
/// # fn main() -> SignalFfiResult<()> {
/// #     let rust_result = Foo;
/// let ffi_result = rust_result.convert_into()?;
/// #     Ok(())
/// # }
/// ```
///
/// Implementers should also see the `ffi_result_type` macro in `convert.rs`.
pub trait ResultTypeInfo: Sized {
    /// The FFI form of the result (e.g. `libc::c_uchar`).
    type ResultType;
    /// Converts the data in `self` to the FFI type, similar to `try_into()`.
    fn convert_into(self) -> SignalFfiResult<Self::ResultType>;
}

impl SizedArgTypeInfo for &[u8] {
    type ArgType = *const c_uchar;
    fn convert_from(input: Self::ArgType, input_len: usize) -> SignalFfiResult<Self> {
        if input.is_null() {
            if input_len != 0 {
                return Err(SignalFfiError::NullPointer);
            }
            // We can't just fall through because slice::from_raw_parts still expects a non-null pointer. Reference a dummy buffer instead.
            return Ok(&[]);
        }

        unsafe { Ok(std::slice::from_raw_parts(input, input_len)) }
    }
}

impl SizedArgTypeInfo for &mut [u8] {
    type ArgType = *mut c_uchar;
    fn convert_from(input: Self::ArgType, input_len: usize) -> SignalFfiResult<Self> {
        if input.is_null() {
            if input_len != 0 {
                return Err(SignalFfiError::NullPointer);
            }
            // We can't just fall through because slice::from_raw_parts_mut still expects a non-null pointer. Reference a dummy buffer instead.
            return Ok(&mut []);
        }

        unsafe { Ok(std::slice::from_raw_parts_mut(input, input_len)) }
    }
}

impl<const LEN: usize> SimpleArgTypeInfo for &mut [u8; LEN] {
    type ArgType = *mut [u8; LEN];
    fn convert_from(input: Self::ArgType) -> SignalFfiResult<Self> {
        unsafe { input.as_mut() }.ok_or(SignalFfiError::NullPointer)
    }
}

/// `u32::MAX` (`UINT_MAX`, `~0u`) is used to represent `None` here.
impl SimpleArgTypeInfo for Option<u32> {
    type ArgType = u32;
    fn convert_from(foreign: u32) -> SignalFfiResult<Self> {
        if foreign == u32::MAX {
            Ok(None)
        } else {
            Ok(Some(foreign))
        }
    }
}

/// Converts a non-`NULL` C string to a Rust String.
impl SimpleArgTypeInfo for String {
    type ArgType = *const c_char;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: *const c_char) -> SignalFfiResult<Self> {
        if foreign.is_null() {
            return Err(SignalFfiError::NullPointer);
        }

        match unsafe { CStr::from_ptr(foreign).to_str() } {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => Err(SignalFfiError::InvalidUtf8String),
        }
    }
}

/// Converts a possibly-`NULL` C string to a Rust String (or `None`).
impl SimpleArgTypeInfo for Option<String> {
    type ArgType = *const c_char;
    fn convert_from(foreign: *const c_char) -> SignalFfiResult<Self> {
        if foreign.is_null() {
            Ok(None)
        } else {
            String::convert_from(foreign).map(Some)
        }
    }
}

impl SimpleArgTypeInfo for Context {
    type ArgType = *mut c_void;
    fn convert_from(foreign: *mut c_void) -> SignalFfiResult<Self> {
        Ok(Some(foreign))
    }
}

impl SimpleArgTypeInfo for uuid::Uuid {
    type ArgType = *const [u8; 16];
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        match unsafe { foreign.as_ref() } {
            Some(array) => Ok(uuid::Uuid::from_bytes(*array)),
            None => Err(SignalFfiError::NullPointer),
        }
    }
}

macro_rules! store {
    ($name:ident) => {
        paste! {
            impl<'a> ArgTypeInfo<'a> for &'a mut dyn libsignal_protocol::$name {
                type ArgType = *const [<Ffi $name Struct>];
                type StoredType = &'a [<Ffi $name Struct>];
                fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
                    match unsafe { foreign.as_ref() } {
                        None => Err(SignalFfiError::NullPointer),
                        Some(store) => Ok(store),
                    }
                }
                fn load_from(stored: &'a mut Self::StoredType) -> SignalFfiResult<Self> {
                    Ok(stored)
                }
            }
        }
    };
}

store!(IdentityKeyStore);
store!(PreKeyStore);
store!(SenderKeyStore);
store!(SessionStore);
store!(SignedPreKeyStore);

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, SignalProtocolError> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, device_transfer::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, signal_crypto::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

/// Allocates and returns a new Rust-owned C string.
impl ResultTypeInfo for String {
    type ResultType = *const libc::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        self.deref().convert_into()
    }
}

/// Allocates and returns a new Rust-owned C string (or `NULL`).
impl ResultTypeInfo for Option<String> {
    type ResultType = *const libc::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        self.as_deref().convert_into()
    }
}

/// Allocates and returns a new Rust-owned C string.
impl ResultTypeInfo for &str {
    type ResultType = *const libc::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let cstr = CString::new(self).expect("No NULL characters in string being returned to C");
        Ok(cstr.into_raw())
    }
}

/// Allocates and returns a new Rust-owned C string (or `NULL`).
impl ResultTypeInfo for Option<&str> {
    type ResultType = *const libc::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        match self {
            Some(s) => s.convert_into(),
            None => Ok(std::ptr::null()),
        }
    }
}
/// `u32::MAX` (`UINT_MAX`, `~0u`) is used to represent `None` here.
impl ResultTypeInfo for Option<u32> {
    type ResultType = u32;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self.unwrap_or(u32::MAX))
    }
}

/// A dummy type used to implement [`crate::support::Env`].
pub(crate) struct Env;

/// Returns a Rust-owned boxed `[u8]`, which will be split up into a pointer/length pair.
impl crate::support::Env for Env {
    type Buffer = Box<[u8]>;
    fn buffer<'a, T: Into<Cow<'a, [u8]>>>(self, input: T) -> Self::Buffer {
        input.into().into()
    }
}

/// Implementation of [`bridge_handle`](crate::support::bridge_handle) for FFI.
macro_rules! ffi_bridge_handle {
    ( $typ:ty as false $(, $($_:tt)*)? ) => {};
    ( $typ:ty as $ffi_name:ident, clone = false ) => {
        impl ffi::SimpleArgTypeInfo for &$typ {
            type ArgType = *const $typ;
            #[allow(clippy::not_unsafe_ptr_arg_deref)]
            fn convert_from(foreign: *const $typ) -> ffi::SignalFfiResult<Self> {
                unsafe { ffi::native_handle_cast(foreign) }
            }
        }
        impl ffi::SimpleArgTypeInfo for Option<&$typ> {
            type ArgType = *const $typ;
            fn convert_from(foreign: *const $typ) -> ffi::SignalFfiResult<Self> {
                if foreign.is_null() {
                    Ok(None)
                } else {
                    <&$typ>::convert_from(foreign).map(Some)
                }
            }
        }
        impl ffi::SimpleArgTypeInfo for &mut $typ {
            type ArgType = *mut $typ;
            #[allow(clippy::not_unsafe_ptr_arg_deref)]
            fn convert_from(foreign: *mut $typ) -> ffi::SignalFfiResult<Self> {
                unsafe { ffi::native_handle_cast_mut(foreign) }
            }
        }
        impl ffi::SizedArgTypeInfo for &[& $typ] {
            type ArgType = *const *const $typ;
            fn convert_from(input: Self::ArgType, input_len: usize) -> ffi::SignalFfiResult<Self> {
                if input.is_null() {
                    if input_len != 0 {
                        return Err(ffi::SignalFfiError::NullPointer);
                    }
                    // We can't just fall through because slice::from_raw_parts still expects a non-null pointer. Reference a dummy buffer instead.
                    return Ok(&[]);
                }

                let slice_of_pointers = unsafe { std::slice::from_raw_parts(input, input_len) };

                if slice_of_pointers.contains(&std::ptr::null()) {
                    return Err(ffi::SignalFfiError::NullPointer);
                }

                let base_ptr_for_slice_of_refs = input as *const & $typ;

                unsafe { Ok(std::slice::from_raw_parts(base_ptr_for_slice_of_refs, input_len)) }
            }
        }
        impl ffi::ResultTypeInfo for $typ {
            type ResultType = *mut $typ;
            fn convert_into(self) -> ffi::SignalFfiResult<Self::ResultType> {
                Ok(Box::into_raw(Box::new(self)))
            }
        }
        impl ffi::ResultTypeInfo for Option<$typ> {
            type ResultType = *mut $typ;
            fn convert_into(self) -> ffi::SignalFfiResult<Self::ResultType> {
                match self {
                    Some(obj) => obj.convert_into(),
                    None => Ok(std::ptr::null_mut()),
                }
            }
        }
        ffi_bridge_destroy!($typ as $ffi_name);
    };
    ( $typ:ty as $ffi_name:ident ) => {
        ffi_bridge_handle!($typ as $ffi_name, clone = false);
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<signal_ $ffi_name _clone>](
                new_obj: *mut *mut $typ,
                obj: *const $typ,
            ) -> *mut ffi::SignalFfiError {
                ffi::run_ffi_safe(|| {
                    let obj = ffi::native_handle_cast::<$typ>(obj)?;
                    ffi::box_object::<$typ>(new_obj, Ok(obj.clone()))
                })
            }
        }
    };
    ( $typ:ty $(, clone = $_:tt)? ) => {
        paste! {
            ffi_bridge_handle!($typ as [<$typ:snake>] $(, clone = $_)? );
        }
    };
}

macro_rules! trivial {
    ($typ:ty) => {
        impl SimpleArgTypeInfo for $typ {
            type ArgType = Self;
            fn convert_from(foreign: Self) -> SignalFfiResult<Self> {
                Ok(foreign)
            }
        }
        impl ResultTypeInfo for $typ {
            type ResultType = Self;
            fn convert_into(self) -> SignalFfiResult<Self> {
                Ok(self)
            }
        }
    };
}

trivial!(i32);
trivial!(u8);
trivial!(u32);
trivial!(u64);
trivial!(usize);
trivial!(bool);

/// Syntactically translates `bridge_fn` argument types to FFI types for `cbindgen`.
///
/// This is a syntactic transformation (because that's how Rust macros work), so new argument types
/// will need to be added here directly even if they already implement [`ArgTypeInfo`]. The default
/// behavior for references is to pass them through as pointers; the default behavior for
/// `&mut dyn Foo` is to assume there's a struct called `ffi::FfiFooStruct` and produce a pointer
/// to that.
///
/// Types that implement [`SizedArgTypeInfo`] should only include their base type here.
/// (For example, `(&[u8]) => (*const libc::c_uchar);`.)
macro_rules! ffi_arg_type {
    (u8) => (u8);
    (u32) => (u32);
    (u64) => (u64);
    (Option<u32>) => (u32);
    (usize) => (libc::size_t);
    (&[u8]) => (*const libc::c_uchar);
    (&mut [u8]) => (*mut libc::c_uchar);
    (String) => (*const libc::c_char);
    (Option<String>) => (*const libc::c_char);
    (Option<&str>) => (*const libc::c_char);
    (Context) => (*mut libc::c_void);
    (Uuid) => (*const [u8; 16]);
    (&[& $typ:ty]) => (*const *const $typ);
    (&mut dyn $typ:ty) => (*const paste!(ffi::[<Ffi $typ Struct>]));
    (& $typ:ty) => (*const $typ);
    (&mut $typ:ty) => (*mut $typ);
    (Option<& $typ:ty>) => (*const $typ);
}

/// Syntactically translates `bridge_fn` result types to FFI types for `cbindgen`.
///
/// This is a syntactic transformation (because that's how Rust macros work), so new result types
/// will need to be added here directly even if they already implement [`ResultTypeInfo`]. The
/// default behavior is to assume we're returning an opaque boxed value `*mut Foo` (`Foo *` in C).
macro_rules! ffi_result_type {
    // These rules only match a single token for a Result's success type.
    // We can't use `:ty` because we need the resulting tokens to be matched recursively rather than
    // treated as a single unit, and we can't match multiple tokens because Rust's macros match
    // eagerly. Therefore, if you need to return a more complicated Result type, you'll have to add // another rule for its form.
    (Result<$typ:tt $(, $_:ty)?>) => (ffi_result_type!($typ));
    (Result<&$typ:tt $(, $_:ty)?>) => (ffi_result_type!(&$typ));
    (Result<Option<&$typ:tt> $(, $_:ty)?>) => (ffi_result_type!(&$typ));
    (Result<$typ:tt<$($args:tt),+> $(, $_:ty)?>) => (ffi_result_type!($typ<$($args)+>));

    (u8) => (u8);
    (i32) => (i32);
    (u32) => (u32);
    (Option<u32>) => (u32);
    (u64) => (u64);
    (bool) => (bool);
    (&str) => (*const libc::c_char);
    (String) => (*const libc::c_char);
    (Option<String>) => (*const libc::c_char);
    (Option<&str>) => (*const libc::c_char);
    (Option<$typ:ty>) => (*mut $typ);
    ( $typ:ty ) => (*mut $typ);
}
