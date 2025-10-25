//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::CString;

use derive_where::derive_where;
use libsignal_protocol::*;

#[macro_use]
mod convert;
pub use convert::*;

mod chat;
pub use chat::*;

mod error;
pub use error::*;

mod futures;
pub use futures::*;

mod io;
pub use io::*;

mod storage;
pub use storage::*;

use crate::support::describe_panic;

#[derive(Debug)]
pub struct NullPointerError;

#[repr(C)]
pub struct BorrowedSliceOf<T> {
    base: *const T,
    length: usize,
}

impl<T> BorrowedSliceOf<T> {
    pub unsafe fn as_slice(&self) -> Result<&[T], NullPointerError> {
        if self.base.is_null() {
            if self.length != 0 {
                return Err(NullPointerError);
            }
            // We can't just fall through because slice::from_raw_parts still expects a non-null pointer. Reference a dummy buffer instead.
            return Ok(&[]);
        }

        Ok(unsafe { std::slice::from_raw_parts(self.base, self.length) })
    }
}

#[repr(C)]
pub struct BorrowedMutableSliceOf<T> {
    base: *mut T,
    length: usize,
}

impl<T> BorrowedMutableSliceOf<T> {
    pub unsafe fn as_slice_mut(&mut self) -> Result<&mut [T], NullPointerError> {
        if self.base.is_null() {
            if self.length != 0 {
                return Err(NullPointerError);
            }
            // We can't just fall through because slice::from_raw_parts still expects a non-null pointer. Reference a dummy buffer instead.
            return Ok(&mut []);
        }

        Ok(unsafe { std::slice::from_raw_parts_mut(self.base, self.length) })
    }
}

/// A representation of a array allocated on the Rust heap for use in C code.
#[repr(C)]
#[derive_where(Debug)]
pub struct OwnedBufferOf<T> {
    base: *mut T,
    /// The number of elements in the buffer (not necessarily the number of bytes).
    length: usize,
}

impl<T> OwnedBufferOf<T> {
    /// Converts back into a `Box`ed slice.
    ///
    /// Callers of this function must ensure that
    /// - the `OwnedBufferOf` was originally created from `Box` (or `default()`)
    /// - any C code operating on the buffer left all its elements in a valid
    ///   state.
    pub unsafe fn into_box(self) -> Box<[T]> {
        let Self { base, length } = self;
        if base.is_null() {
            return Box::new([]);
        }

        unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(base, length)) }
    }
}

impl<T> Default for OwnedBufferOf<T> {
    fn default() -> Self {
        Self {
            base: std::ptr::null_mut(),
            length: 0,
        }
    }
}

impl<T> From<Box<[T]>> for OwnedBufferOf<T> {
    fn from(value: Box<[T]>) -> Self {
        let raw = unsafe { Box::into_raw(value).as_mut().expect("just created") };
        Self {
            base: raw.as_mut_ptr(),
            length: raw.len(),
        }
    }
}

#[repr(C)]
pub struct BytestringArray {
    bytes: OwnedBufferOf<std::ffi::c_uchar>,
    lengths: OwnedBufferOf<usize>,
}

#[repr(C)]
pub struct BorrowedBytestringArray {
    bytes: BorrowedSliceOf<std::ffi::c_uchar>,
    lengths: BorrowedSliceOf<usize>,
}

pub type StringArray = BytestringArray;

impl BytestringArray {
    /// Converts `self` into owned buffers of contents and string lengths.
    ///
    /// Callers of this function must ensure that
    /// - the `BytestringArray` was originally allocated in Rust, and
    /// - the lengths of the buffers were not modified.
    pub unsafe fn into_boxed_parts(self) -> (Box<[u8]>, Box<[usize]>) {
        let Self { bytes, lengths } = self;

        let bytes = unsafe { bytes.into_box() };
        let lengths = unsafe { lengths.into_box() };
        (bytes, lengths)
    }
}

impl<S: AsRef<[u8]>> FromIterator<S> for BytestringArray {
    fn from_iter<T: IntoIterator<Item = S>>(iter: T) -> Self {
        let it = iter.into_iter();
        let (mut bytes, mut lengths) = (Vec::new(), Vec::with_capacity(it.size_hint().0));
        for s in it {
            let s = s.as_ref();
            bytes.extend_from_slice(s);
            lengths.push(s.len());
        }
        Self {
            bytes: bytes.into_boxed_slice().into(),
            lengths: lengths.into_boxed_slice().into(),
        }
    }
}

impl BorrowedBytestringArray {
    /// Allows iterating over the segments.
    ///
    /// SAFETY: Must be constructed correctly and refer to valid memory.
    unsafe fn iter(&self) -> Result<impl ExactSizeIterator<Item = &[u8]>, NullPointerError> {
        let BorrowedBytestringArray { bytes, lengths } = self;
        let (mut bytes, lengths) = unsafe { (bytes.as_slice()?, lengths.as_slice()?) };

        // Note that this iterator will support DoubleEndedIterator, but we must not expose that to
        // callers, since we have a stateful iteration happening here.
        Ok(lengths.iter().map(move |length| {
            let next;
            (next, bytes) = bytes.split_at(*length);
            next
        }))
    }
}

#[repr(C)]
pub struct OptionalBorrowedSliceOf<T> {
    pub present: bool,
    pub value: BorrowedSliceOf<T>,
}

pub type OptionalUuid = [u8; 17];

#[repr(C)]
pub struct PairOf<A, B> {
    pub first: A,
    pub second: B,
}

#[repr(C)]
#[derive(Default)]
pub struct OptionalPairOf<A, B> {
    pub present: bool,
    pub first: A,
    pub second: B,
}

#[repr(C)]
#[derive(Debug)]
/// cbindgen:field-names=[e164, rawAciUuid, rawPniUuid]
pub struct FfiCdsiLookupResponseEntry {
    /// Telephone number, as an unformatted e164.
    pub e164: u64,
    pub aci: [u8; 16],
    pub pni: [u8; 16],
}

#[repr(C)]
#[derive(Debug)]
pub struct FfiCdsiLookupResponse {
    entries: OwnedBufferOf<FfiCdsiLookupResponseEntry>,
    debug_permits_used: i32,
}

#[repr(C)]
pub struct FfiCheckSvr2CredentialsResponse {
    /// Bridged as a string of bytes, but each entry is a UTF-8 `String` key
    /// concatenated with a byte for the value.
    entries: BytestringArray,
}

/// A type alias to be used with [`OwnedBufferOf`], so that `OwnedBufferOf<c_char>` and
/// `OwnedBufferOf<*const c_char>` get distinct names.
pub type CStringPtr = *const std::ffi::c_char;

#[repr(C)]
#[derive(Debug)]
pub struct FfiChatResponse {
    status: u16,
    message: *const std::ffi::c_char,
    headers: OwnedBufferOf<CStringPtr>,
    body: OwnedBufferOf<std::ffi::c_uchar>,
}

#[repr(C)]
#[derive(Debug)]
pub struct FfiChatServiceDebugInfo {
    raw_ip_type: u8,
    duration_secs: f64,
    connection_info: *const std::ffi::c_char,
}

#[repr(C)]
#[derive(Debug)]
pub struct FfiResponseAndDebugInfo {
    response: FfiChatResponse,
    debug_info: FfiChatServiceDebugInfo,
}

#[repr(C)]
pub struct FfiRegistrationCreateSessionRequest {
    number: *const std::ffi::c_char,
    push_token: *const std::ffi::c_char,
    mcc: *const std::ffi::c_char,
    mnc: *const std::ffi::c_char,
}

#[repr(C)]
pub struct FfiRegisterResponseBadge {
    /// The badge ID.
    pub id: *const std::ffi::c_char,
    /// Whether the badge is currently configured to be visible.
    pub visible: bool,
    /// When the badge expires.
    pub expiration_secs: f64,
}

#[repr(C)]
pub struct FfiSignedPublicPreKey {
    pub key_id: u32,
    pub public_key_type: FfiPublicKeyType,
    pub public_key: *const std::ffi::c_void,
    pub signature: BorrowedSliceOf<std::ffi::c_uchar>,
}

#[repr(u8)]
pub enum FfiPublicKeyType {
    ECC,
    Kyber,
}

#[repr(C)]
pub struct FfiMismatchedDevicesError {
    pub account: ServiceIdFixedWidthBinaryBytes,
    pub missing_devices: OwnedBufferOf<u32>,
    pub extra_devices: OwnedBufferOf<u32>,
    pub stale_devices: OwnedBufferOf<u32>,
}

impl FfiMismatchedDevicesError {
    pub unsafe fn free_buffers(&mut self) {
        _ = unsafe { std::mem::take(&mut self.missing_devices).into_box() };
        _ = unsafe { std::mem::take(&mut self.extra_devices).into_box() };
        _ = unsafe { std::mem::take(&mut self.stale_devices).into_box() };
    }
}

#[cfg_attr(doc, visibility::make(pub))]
struct UnexpectedPanic(Box<dyn std::any::Any + Send>);

impl std::fmt::Debug for UnexpectedPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UnexpectedPanic")
            .field(&describe_panic(&self.0))
            .finish()
    }
}

// Wrapper for a `*mut T` that gets translated by cbindgen into a named struct
// type in the generated C header file. This is useful because the consuming
// Swift code considers all opaque pointers to be the same type, but
// differentiates between the generated named struct types.
#[repr(C)]
#[derive(derive_more::From, zerocopy::FromZeros)]
#[derive_where(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MutPointer<T> {
    raw: *mut T,
}

impl<T> MutPointer<T> {
    pub fn into_inner(self) -> *mut T {
        self.raw
    }

    pub fn null() -> Self {
        Self {
            raw: std::ptr::null_mut(),
        }
    }
}

impl<T> Default for MutPointer<T> {
    fn default() -> Self {
        Self::null()
    }
}

// Wrapped `*const T`. This type exists for the same reason `MutPointer` does.
#[repr(C)]
#[derive_where(Copy, Clone, Debug, PartialEq)]
pub struct ConstPointer<T> {
    raw: *const T,
}

impl<T> From<&T> for ConstPointer<T> {
    fn from(raw: &T) -> Self {
        Self { raw }
    }
}

impl<T> ConstPointer<T> {
    pub fn into_inner(self) -> *const T {
        self.raw
    }
}

#[inline(always)]
pub fn run_ffi_safe<F: FnOnce() -> Result<(), SignalFfiError> + std::panic::UnwindSafe>(
    f: F,
) -> *mut SignalFfiError {
    let result = match std::panic::catch_unwind(f) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(r) => Err(UnexpectedPanic(r).into()),
    };

    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => e.into_raw_box_for_ffi(),
    }
}

/// Like [`std::panic::AssertUnwindSafe`], but FFI-compatible.
#[derive(derive_more::Deref)]
#[repr(transparent)]
pub struct UnwindSafeArg<T>(pub T);

impl<T> std::panic::UnwindSafe for UnwindSafeArg<T> {}
impl<T> std::panic::RefUnwindSafe for UnwindSafeArg<T> {}

pub unsafe fn native_handle_cast<T>(handle: *const T) -> Result<&'static T, SignalFfiError> {
    if handle.is_null() {
        return Err(NullPointerError.into());
    }

    Ok(unsafe { &*(handle) })
}

pub unsafe fn native_handle_cast_mut<T>(handle: *mut T) -> Result<&'static mut T, SignalFfiError> {
    if handle.is_null() {
        return Err(NullPointerError.into());
    }

    Ok(unsafe { &mut *handle })
}

pub unsafe fn write_result_to<T: ResultTypeInfo>(
    ptr: *mut T::ResultType,
    value: T,
) -> SignalFfiResult<()> {
    if ptr.is_null() {
        return Err(NullPointerError.into());
    }
    unsafe {
        *ptr = value.convert_into()?;
    }
    Ok(())
}

/// Used by [`bridge_as_handle`](crate::support::bridge_as_handle).
///
/// Not intended to be invoked directly.
#[macro_export]
macro_rules! ffi_bridge_handle_destroy {
    ( $typ:ty as $ffi_name:ident ) => {
        ::paste::paste! {
            #[cfg(feature = "ffi")]
            #[unsafe(export_name = concat!(
                env!("LIBSIGNAL_BRIDGE_FN_PREFIX_FFI"),
                stringify!($ffi_name),
                "_destroy",
            ))]
            #[allow(non_snake_case)]
            pub unsafe extern "C" fn [<__bridge_handle_ffi_ $ffi_name _destroy>](
                p: $crate::ffi::MutPointer<$typ>
            ) -> *mut ffi::SignalFfiError {
                // The only thing the closure does is drop the value if there is
                // one. Drop shouldn't panic, and if it does and leaves the
                // value in an (internally) inconsistent state, that's fine
                // for the purposes of unwind safety since this is the last
                // reference to the value.
                let p = std::panic::AssertUnwindSafe(p.into_inner());
                ffi::run_ffi_safe(|| {
                    if !p.is_null() {
                        drop(unsafe { Box::from_raw(*p) });
                    }
                    Ok(())
                })
            }
        }
    };
}
