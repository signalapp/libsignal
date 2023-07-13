//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libc::{c_char, c_uchar, c_void};
use libsignal_protocol::*;
use paste::paste;
use std::convert::TryInto;
use std::ffi::CStr;
use std::ops::Deref;

use crate::io::InputStream;
use crate::support::{FixedLengthBincodeSerializable, Serialized};

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

impl<'a> ArgTypeInfo<'a> for &'a [u8] {
    type ArgType = BorrowedSliceOf<c_uchar>;
    type StoredType = Self::ArgType;
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        Ok(foreign)
    }
    fn load_from(stored: &'a mut Self::StoredType) -> SignalFfiResult<Self> {
        unsafe { Ok(stored.as_slice()?) }
    }
}

impl<'a> ArgTypeInfo<'a> for &'a mut [u8] {
    type ArgType = BorrowedMutableSliceOf<c_uchar>;
    type StoredType = Self::ArgType;
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        Ok(foreign)
    }
    fn load_from(stored: &'a mut Self::StoredType) -> SignalFfiResult<Self> {
        unsafe { Ok(stored.as_slice_mut()?) }
    }
}

impl<const LEN: usize> SimpleArgTypeInfo for &mut [u8; LEN] {
    type ArgType = *mut [u8; LEN];
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
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
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        match unsafe { foreign.as_ref() } {
            Some(array) => Ok(uuid::Uuid::from_bytes(*array)),
            None => Err(SignalFfiError::NullPointer),
        }
    }
}

impl ResultTypeInfo for uuid::Uuid {
    type ResultType = uuid::Bytes;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(*self.as_bytes())
    }
}

impl SimpleArgTypeInfo for libsignal_protocol::ServiceId {
    type ArgType = *const libsignal_protocol::ServiceIdFixedWidthBinaryBytes;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        match unsafe { foreign.as_ref() } {
            Some(array) => {
                libsignal_protocol::ServiceId::parse_from_service_id_fixed_width_binary(array)
                    .ok_or_else(|| {
                        SignalProtocolError::InvalidArgument(
                            "invalid Service-Id-FixedWidthBinary".to_string(),
                        )
                        .into()
                    })
            }
            None => Err(SignalFfiError::NullPointer),
        }
    }
}

impl ResultTypeInfo for libsignal_protocol::ServiceId {
    type ResultType = libsignal_protocol::ServiceIdFixedWidthBinaryBytes;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self.service_id_fixed_width_binary())
    }
}

impl SimpleArgTypeInfo for libsignal_protocol::Aci {
    type ArgType = <libsignal_protocol::ServiceId as SimpleArgTypeInfo>::ArgType;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        libsignal_protocol::ServiceId::convert_from(foreign)?
            .try_into()
            .map_err(|_| SignalProtocolError::InvalidArgument("not an ACI".to_string()).into())
    }
}

impl ResultTypeInfo for libsignal_protocol::Aci {
    type ResultType = libsignal_protocol::ServiceIdFixedWidthBinaryBytes;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        libsignal_protocol::ServiceId::from(self).convert_into()
    }
}

impl SimpleArgTypeInfo for libsignal_protocol::Pni {
    type ArgType = <libsignal_protocol::ServiceId as SimpleArgTypeInfo>::ArgType;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        libsignal_protocol::ServiceId::convert_from(foreign)?
            .try_into()
            .map_err(|_| SignalProtocolError::InvalidArgument("not a PNI".to_string()).into())
    }
}

impl<const LEN: usize> SimpleArgTypeInfo for &'_ [u8; LEN] {
    type ArgType = *const [u8; LEN];
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(arg: *const [u8; LEN]) -> SignalFfiResult<Self> {
        unsafe { arg.as_ref() }.ok_or(SignalFfiError::NullPointer)
    }
}

impl<const LEN: usize> ResultTypeInfo for [u8; LEN] {
    type ResultType = [u8; LEN];
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self)
    }
}

macro_rules! store {
    ($name:ident) => {
        paste! {
            impl<'a> ArgTypeInfo<'a> for &'a mut dyn $name {
                type ArgType = *const [<Ffi $name Struct>];
                type StoredType = &'a [<Ffi $name Struct>];
                #[allow(clippy::not_unsafe_ptr_arg_deref)]
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
store!(KyberPreKeyStore);
store!(InputStream);

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, SignalProtocolError> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, attest::hsm_enclave::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, attest::sgx_session::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, signal_pin::Error> {
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

#[cfg(feature = "signal-media")]
impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, signal_media::sanitize::Error> {
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

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, zkgroup::ZkGroupVerificationFailure> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, zkgroup::ZkGroupDeserializationFailure> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, usernames::UsernameError> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, usernames::UsernameLinkError> {
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

impl ResultTypeInfo for Vec<u8> {
    type ResultType = OwnedBufferOf<libc::c_uchar>;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(OwnedBufferOf::from(self.into_boxed_slice()))
    }
}

impl ResultTypeInfo for &[u8] {
    type ResultType = OwnedBufferOf<libc::c_uchar>;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        self.to_vec().convert_into()
    }
}

/// `u32::MAX` (`UINT_MAX`, `~0u`) is used to represent `None` here.
impl ResultTypeInfo for Option<u32> {
    type ResultType = u32;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self.unwrap_or(u32::MAX))
    }
}

impl SimpleArgTypeInfo for crate::protocol::Timestamp {
    type ArgType = u64;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        Ok(Self::from_millis(foreign))
    }
}

impl ResultTypeInfo for crate::protocol::Timestamp {
    type ResultType = u64;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self.as_millis())
    }
}

impl SimpleArgTypeInfo for crate::zkgroup::Timestamp {
    type ArgType = u64;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        Ok(Self::from_seconds(foreign))
    }
}

impl ResultTypeInfo for crate::zkgroup::Timestamp {
    type ResultType = u64;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self.as_seconds())
    }
}

/// A marker for Rust objects exposed as opaque pointers.
///
/// When we do this, we hand the lifetime over to the app. Since we don't know how long the object
/// will be kept alive, it can't (safely) have references to anything with a non-static lifetime.
pub trait BridgeHandle: 'static {}

impl<T: BridgeHandle> SimpleArgTypeInfo for &T {
    type ArgType = *const T;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: *const T) -> SignalFfiResult<Self> {
        unsafe { native_handle_cast(foreign) }
    }
}

impl<T: BridgeHandle> SimpleArgTypeInfo for Option<&T> {
    type ArgType = *const T;
    fn convert_from(foreign: *const T) -> SignalFfiResult<Self> {
        if foreign.is_null() {
            Ok(None)
        } else {
            <&T>::convert_from(foreign).map(Some)
        }
    }
}

impl<T: BridgeHandle> SimpleArgTypeInfo for &mut T {
    type ArgType = *mut T;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: *mut T) -> SignalFfiResult<Self> {
        unsafe { native_handle_cast_mut(foreign) }
    }
}

impl<'a, T: BridgeHandle> ArgTypeInfo<'a> for &'a [&'a T] {
    type ArgType = BorrowedSliceOf<*const T>;
    type StoredType = Self::ArgType;
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        Ok(foreign)
    }
    fn load_from(input: &'a mut Self::ArgType) -> SignalFfiResult<Self> {
        let slice_of_pointers = unsafe { input.as_slice() }?;

        if slice_of_pointers.contains(&std::ptr::null()) {
            return Err(SignalFfiError::NullPointer);
        }

        if input.base.is_null() {
            // Early-exit  so that we don't construct a slice with a NULL base later.
            // Note that we already checked that the length is 0 by using slice_of_pointers.
            return Ok(&[]);
        }

        let base_ptr_for_slice_of_refs = input.base as *const &T;

        unsafe {
            Ok(std::slice::from_raw_parts(
                base_ptr_for_slice_of_refs,
                input.length,
            ))
        }
    }
}

impl<T: BridgeHandle> ResultTypeInfo for T {
    type ResultType = *mut T;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(Box::into_raw(Box::new(self)))
    }
}

impl<T: BridgeHandle> ResultTypeInfo for Option<T> {
    type ResultType = *mut T;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        match self {
            Some(obj) => obj.convert_into(),
            None => Ok(std::ptr::null_mut()),
        }
    }
}

impl<T> SimpleArgTypeInfo for Serialized<T>
where
    T: FixedLengthBincodeSerializable + for<'a> serde::Deserialize<'a>,
{
    type ArgType = *const T::Array;

    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let array = unsafe { foreign.as_ref() }.ok_or(SignalFfiError::NullPointer)?;
        let result: T = bincode::deserialize(array.as_ref()).unwrap_or_else(|_| {
            panic!(
                "{} should have been validated on creation",
                std::any::type_name::<T>()
            )
        });
        Ok(Serialized::from(result))
    }
}

impl<T> ResultTypeInfo for Serialized<T>
where
    T: FixedLengthBincodeSerializable + serde::Serialize,
{
    type ResultType = T::Array;

    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let result = bincode::serialize(self.deref()).expect("can always serialize a value");
        Ok(result.as_slice().try_into().expect("wrong serialized size"))
    }
}

/// Implementation of [`bridge_handle`](crate::support::bridge_handle) for FFI.
macro_rules! ffi_bridge_handle {
    ( $typ:ty as false $(, $($_:tt)*)? ) => {};
    ( $typ:ty as $ffi_name:ident, clone = false ) => {
        impl ffi::BridgeHandle for $typ {}
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
                    ffi::write_result_to::<$typ>(new_obj, obj.clone())
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
macro_rules! ffi_arg_type {
    (u8) => (u8);
    (u32) => (u32);
    (u64) => (u64);
    (Option<u32>) => (u32);
    (usize) => (libc::size_t);
    (bool) => (bool);
    (&[u8]) => (ffi::BorrowedSliceOf<libc::c_uchar>);
    (&mut [u8]) => (ffi::BorrowedMutableSliceOf<libc::c_uchar>);
    (String) => (*const libc::c_char);
    (Option<String>) => (*const libc::c_char);
    (Option<&str>) => (*const libc::c_char);
    (Context) => (*mut libc::c_void);
    (Timestamp) => (u64);
    (Uuid) => (*const [u8; 16]);
    (ServiceId) => (*const libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    (Aci) => (*const libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    (Pni) => (*const libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    (&[u8; $len:expr]) => (*const [u8; $len]);
    (&[& $typ:ty]) => (ffi::BorrowedSliceOf<*const $typ>);
    (&mut dyn $typ:ty) => (*const paste!(ffi::[<Ffi $typ Struct>]));
    (& $typ:ty) => (*const $typ);
    (&mut $typ:ty) => (*mut $typ);
    (Option<& $typ:ty>) => (*const $typ);

    // In order to provide a fixed-sized array of the correct length,
    // a serialized type FooBar must have a constant FOO_BAR_LEN that's in scope (and exposed to C).
    (Serialized<$typ:ident>) => (*const [libc::c_uchar; paste!([<$typ:snake:upper _LEN>])]);
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
    (Timestamp) => (u64);
    (Uuid) => ([u8; 16]);
    (ServiceId) => (libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    (Aci) => (libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    (Pni) => (libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    ([u8; $len:expr]) => ([u8; $len]);
    (&[u8]) => (ffi::OwnedBufferOf<libc::c_uchar>);
    (Vec<u8>) => (ffi::OwnedBufferOf<libc::c_uchar>);

    // In order to provide a fixed-sized array of the correct length,
    // a serialized type FooBar must have a constant FOO_BAR_LEN that's in scope (and exposed to C).
    (Serialized<$typ:ident>) => ([libc::c_uchar; paste!([<$typ:snake:upper _LEN>])]);

    ( $typ:ty ) => (*mut $typ);
}
