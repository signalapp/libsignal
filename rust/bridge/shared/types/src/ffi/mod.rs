//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::CString;

use derive_where::derive_where;
use libsignal_bridge_macros::c_export;
use libsignal_protocol::*;

use crate::ffi::capi::IsCType;
use crate::support::describe_panic;

#[macro_use]
mod convert;
pub use convert::*;

pub mod capi;

mod chat;
pub use chat::*;

mod error;
pub use error::*;

mod futures;
pub use futures::*;

// TODO: These re-exports are because of the ffi_arg_type macro expecting all bridging structs to be
// under the ffi module; eventually we should be able to remove it.
pub use crate::io::FfiSyncInputStreamStruct;
pub use crate::protocol::storage::{
    FfiIdentityKeyStoreStruct, FfiKyberPreKeyStoreStruct, FfiPreKeyStoreStruct,
    FfiSenderKeyStoreStruct, FfiSessionStoreStruct, FfiSignedPreKeyStoreStruct,
};

#[c_export]
pub type FfiInputStreamStruct = FfiSyncInputStreamStruct;
#[c_export]
type ConstPointerFfiInputStreamStruct = ConstPointer<FfiInputStreamStruct>;

#[derive(Debug)]
pub struct NullPointerError;

#[repr(C)]
#[derive(IsCType)]
#[capi(export_name_override = borrowed_slice_of_name_override)]
pub struct BorrowedSliceOf<T> {
    base: *const T,
    length: usize,
}
#[cfg(feature = "metadata")]
fn borrowed_slice_of_name_override(
    [t]: [std::sync::Arc<crate::metadata::ffi::capi::CType>; 1],
) -> Option<String> {
    use crate::metadata::ffi::capi::RustType;
    if t.rust_type == RustType::of::<u8>() {
        Some("BorrowedBuffer".to_string())
    } else if t.rust_type == RustType::of::<BorrowedSliceOf<u8>>() {
        Some("BorrowedSliceOfBuffers".to_string())
    } else {
        None
    }
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

unsafe impl<T> Send for BorrowedSliceOf<T> where for<'a> &'a [T]: Send {}
unsafe impl<T> Sync for BorrowedSliceOf<T> where for<'a> &'a [T]: Sync {}

#[repr(C)]
#[derive(IsCType)]
#[capi(export_name_override = borrowed_mutable_slice_of_name_override)]
pub struct BorrowedMutableSliceOf<T> {
    base: *mut T,
    length: usize,
}
#[cfg(feature = "metadata")]
fn borrowed_mutable_slice_of_name_override(
    [t]: [std::sync::Arc<crate::metadata::ffi::capi::CType>; 1],
) -> Option<String> {
    use crate::metadata::ffi::capi::RustType;
    if t.rust_type == RustType::of::<u8>() {
        Some("BorrowedMutableBuffer".to_string())
    } else {
        None
    }
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

/// A buffer of `length` elements of type `T`, allocated with the alignment of
/// [`libc::max_align_t`].
///
/// The number of bytes allocated is stored in `size_bytes`.
///
/// `base` should be allocated via Rust's global alloc (i.e. via [`std::alloc::alloc`])
///
/// # Motivation
/// Rust's global allocator takes a size and alignment for _both_ allocation and deallocation. As a
/// result, if we want to have a general "free this buffer" function, that function needs to be
/// able to know the total size of the allocation and its alignment. Having a fixed (constant)
/// alignment means we don't need to store the alignment in this struct (or have a separate free
/// function for each type).
#[repr(C)]
#[derive(IsCType)]
pub struct OwnedBufferOfMaxAligned<T> {
    pub base: *mut T,
    pub length: usize,
    pub size_bytes: usize,
}

impl<T> OwnedBufferOfMaxAligned<T> {
    pub const ALIGNMENT: usize = std::mem::align_of::<libc::max_align_t>();
    pub fn layout_for_count(count: usize) -> std::alloc::Layout {
        std::alloc::Layout::array::<T>(count)
            .expect("valid layout")
            .align_to(Self::ALIGNMENT)
            .expect("valid layout")
    }
    pub fn layout_for_size_bytes(size_bytes: usize) -> std::alloc::Layout {
        std::alloc::Layout::from_size_align(size_bytes, Self::ALIGNMENT).expect("valid layout")
    }
}

/// A representation of a array allocated on the Rust heap for use in C code.
#[repr(C)]
#[derive_where(Debug)]
#[derive(IsCType)]
#[capi(export_name_override = owned_buffer_of_name_override)]
pub struct OwnedBufferOf<T> {
    base: *mut T,
    /// The number of elements in the buffer (not necessarily the number of bytes).
    length: usize,
}
#[cfg(feature = "metadata")]
fn owned_buffer_of_name_override(
    [t]: [std::sync::Arc<crate::metadata::ffi::capi::CType>; 1],
) -> Option<String> {
    use crate::metadata::ffi::capi::RustType;
    if t.rust_type == RustType::of::<u8>() {
        Some("OwnedBuffer".to_string())
    } else if t.rust_type == RustType::of::<FfiCdsiLookupResponseEntry>() {
        Some("OwnedLookupResponseEntryList".to_string())
    } else {
        None
    }
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

/// A helper trait for types that need to be explicitly destroyed, similar to Neon's `Finalize`.
///
/// Meant for use with [`OwnedCallbackStruct`] and the `bridge_callbacks` macro (all
/// `bridge_callbacks` FFI structs implement `FfiDestroyable`).
pub trait FfiDestroyable {
    fn destroy(&mut self);
}

/// A wrapper around a `bridge_callbacks` struct that calls the `destroy` function on Drop.
#[derive(derive_more::Deref, derive_more::DerefMut)]
pub struct OwnedCallbackStruct<T: FfiDestroyable>(pub T);

impl<T: FfiDestroyable> Drop for OwnedCallbackStruct<T> {
    fn drop(&mut self) {
        self.0.destroy();
    }
}

#[repr(C)]
#[derive(IsCType)]
pub struct BytestringArray {
    bytes: OwnedBufferOf<std::ffi::c_uchar>,
    lengths: OwnedBufferOf<usize>,
}

#[repr(C)]
#[derive(IsCType)]
pub struct BorrowedBytestringArray {
    bytes: BorrowedSliceOf<std::ffi::c_uchar>,
    lengths: BorrowedSliceOf<usize>,
}

#[c_export]
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
#[derive(IsCType)]
pub struct OptionalBorrowedSliceOf<T> {
    pub present: bool,
    pub value: BorrowedSliceOf<T>,
}

/// A wrapper type for raw UUIDs, because C treats arrays specially in argument position.
#[repr(C)]
#[derive(IsCType)]
pub struct Uuid {
    pub bytes: [u8; 16],
}

#[derive(Default)]
#[repr(C)]
#[derive(IsCType)]
pub struct OptionalUuid {
    pub present: bool,
    pub bytes: [u8; 16],
}

#[repr(C)]
#[derive(IsCType)]
pub struct PairOf<A, B> {
    pub first: A,
    pub second: B,
}

#[repr(C)]
#[derive(Default, IsCType)]
pub struct OptionalPairOf<A, B> {
    pub present: bool,
    pub first: A,
    pub second: B,
}

#[repr(C)]
#[derive(Debug, IsCType)]
pub struct FfiCdsiLookupResponseEntry {
    /// Telephone number, as an unformatted e164.
    pub e164: u64,
    #[capi(rename = "rawAciUuid")]
    pub aci: [u8; 16],
    #[capi(rename = "rawPniUuid")]
    pub pni: [u8; 16],
}

#[repr(C)]
#[derive(Debug, IsCType)]
pub struct FfiCdsiLookupResponse {
    entries: OwnedBufferOf<FfiCdsiLookupResponseEntry>,
    debug_permits_used: i32,
}

#[repr(C)]
#[derive(IsCType)]
pub struct FfiCheckSvr2CredentialsResponse {
    /// Bridged as a string of bytes, but each entry is a UTF-8 `String` key
    /// concatenated with a byte for the value.
    entries: BytestringArray,
}

/// A type alias to be used with [`OwnedBufferOf`], so that `OwnedBufferOf<c_char>` and
/// `OwnedBufferOf<*const c_char>` get distinct names.
pub type CStringPtr = *const std::ffi::c_char;

#[repr(C)]
#[derive(Debug, IsCType)]
pub struct FfiChatResponse {
    status: u16,
    message: *const std::ffi::c_char,
    headers: OwnedBufferOf<CStringPtr>,
    body: OwnedBufferOf<std::ffi::c_uchar>,
}

#[repr(C)]
#[derive(IsCType, Debug)]
pub struct FfiChatServiceDebugInfo {
    raw_ip_type: u8,
    duration_secs: f64,
    connection_info: *const std::ffi::c_char,
}

#[repr(C)]
#[derive(IsCType, Debug)]
pub struct FfiResponseAndDebugInfo {
    response: FfiChatResponse,
    debug_info: FfiChatServiceDebugInfo,
}

#[repr(C)]
#[derive(IsCType)]
pub struct FfiRegistrationCreateSessionRequest {
    number: *const std::ffi::c_char,
    push_token: *const std::ffi::c_char,
    mcc: *const std::ffi::c_char,
    mnc: *const std::ffi::c_char,
}

#[repr(C)]
#[derive(IsCType)]
pub struct FfiRegisterResponseBadge {
    /// The badge ID.
    pub id: *const std::ffi::c_char,
    /// Whether the badge is currently configured to be visible.
    pub visible: bool,
    /// When the badge expires.
    pub expiration_secs: f64,
}

#[repr(C)]
#[derive(IsCType)]
pub struct FfiSignedPublicPreKey {
    pub key_id: u32,
    pub public_key_type: FfiPublicKeyType,
    pub public_key: *const std::ffi::c_void,
    pub signature: BorrowedSliceOf<std::ffi::c_uchar>,
}

#[repr(u8)]
#[derive(IsCType)]
pub enum FfiPublicKeyType {
    ECC,
    Kyber,
}

#[repr(C)]
#[derive(IsCType)]
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

#[repr(C)]
#[derive(IsCType)]
pub struct FfiPreKeysResponse {
    identity_key: MutPointer<PublicKey>,
    pre_key_bundles: OwnedBufferOf<MutPointer<PreKeyBundle>>,
}

#[repr(C)]
#[derive(IsCType)]
pub struct FfiUploadForm {
    cdn: u32,
    key: CStringPtr,
    header_keys: OwnedBufferOf<CStringPtr>,
    header_values: OwnedBufferOf<CStringPtr>,
    signed_upload_url: CStringPtr,
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
#[derive(derive_more::From, zerocopy::FromZeros, IsCType)]
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
#[derive(IsCType)]
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
            #[$crate::ffi::capi::c_export]
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

mod type_aliases {
    use libsignal_bridge_macros::c_export;
    use static_assertions::const_assert_eq;

    use crate::ffi::capi::IsCType;
    use crate::ffi::{CPromise, FfiCdsiLookupResponseEntry, OptionalPairOf, OwnedBufferOf, PairOf};

    #[c_export]
    type AesKeyBytes = zkgroup::AesKeyBytes;
    #[c_export]
    type GroupMasterKeyBytes = zkgroup::GroupMasterKeyBytes;
    #[c_export]
    type UidBytes = zkgroup::UidBytes;
    #[c_export]
    type ProfileKeyBytes = zkgroup::ProfileKeyBytes;
    #[c_export]
    type RandomnessBytes = zkgroup::RandomnessBytes;
    #[c_export]
    type SignatureBytes = zkgroup::SignatureBytes;
    #[c_export]
    type NotarySignatureBytes = zkgroup::NotarySignatureBytes;
    #[c_export]
    type GroupIdentifierBytes = zkgroup::GroupIdentifierBytes;
    #[c_export]
    type ProfileKeyVersionBytes = zkgroup::ProfileKeyVersionBytes;
    #[c_export]
    type ProfileKeyVersionEncodedBytes = zkgroup::ProfileKeyVersionEncodedBytes;
    #[c_export]
    type ReceiptSerialBytes = zkgroup::ReceiptSerialBytes;
    #[c_export]
    type UnidentifiedAccessKey = [u8; zkgroup::ACCESS_KEY_LEN];
    #[c_export]
    type ServiceIdFixedWidthBinaryBytes = libsignal_core::ServiceIdFixedWidthBinaryBytes;
    #[c_export]
    type IdentityKeyStore = super::FfiIdentityKeyStoreStruct;
    #[c_export]
    type KyberPreKeyStore = super::FfiKyberPreKeyStoreStruct;
    #[c_export]
    type PreKeyStore = super::FfiPreKeyStoreStruct;
    #[c_export]
    type SenderKeyStore = super::FfiSenderKeyStoreStruct;
    #[c_export]
    type SessionStore = super::FfiSessionStoreStruct;
    #[c_export]
    type SignedPreKeyStore = super::FfiSignedPreKeyStoreStruct;
    #[c_export]
    type InputStream = super::FfiInputStreamStruct;
    #[c_export]
    type SyncInputStream = super::FfiSyncInputStreamStruct;

    // Shim exports to support cbindgen's name mangling
    #[c_export]
    type CPromiseOwnedBufferOfServiceIdFixedWidthBinaryBytes =
        CPromise<OwnedBufferOf<ServiceIdFixedWidthBinaryBytes>>;
    #[c_export]
    #[allow(non_camel_case_types)]
    type CPromiseOwnedBufferOfc_uchar = CPromise<OwnedBufferOf<u8>>;
    #[c_export]
    #[allow(non_camel_case_types)]
    type CPromisePairOfOwnedBufferOfc_ucharOwnedBufferOfc_uchar =
        CPromise<PairOf<OwnedBufferOf<u8>, OwnedBufferOf<u8>>>;
    #[c_export]
    type OptionalPairOfCStringPtru832 = OptionalPairOf<*const std::ffi::c_char, [u8; 32]>;
    #[c_export]
    type OwnedBufferOfFfiCdsiLookupResponseEntry = OwnedBufferOf<FfiCdsiLookupResponseEntry>;
    #[c_export]
    #[allow(non_camel_case_types)]
    type PairOfOwnedBufferOfc_ucharOwnedBufferOfc_uchar =
        PairOf<OwnedBufferOf<u8>, OwnedBufferOf<u8>>;
    #[c_export]
    type CPromiseOptionalPairOfCStringPtru832 =
        CPromise<OptionalPairOf<*const std::ffi::c_char, [u8; 32]>>;

    #[repr(C)]
    #[derive(IsCType)]
    #[capi(must_export)]
    enum IdentityChange {
        NewOrUnchanged,
        ReplacedExisting,
    }
    const_assert_eq!(
        IdentityChange::NewOrUnchanged as i128,
        libsignal_protocol::IdentityChange::NewOrUnchanged as i128
    );
    const_assert_eq!(
        IdentityChange::ReplacedExisting as i128,
        libsignal_protocol::IdentityChange::ReplacedExisting as i128
    );

    #[repr(C)]
    #[derive(IsCType)]
    #[capi(must_export)]
    enum ChallengeOption {
        PushChallenge,
        Captcha,
    }
    const_assert_eq!(
        ChallengeOption::PushChallenge as i128,
        libsignal_net_chat::api::ChallengeOption::PushChallenge as i128
    );
    const_assert_eq!(
        ChallengeOption::Captcha as i128,
        libsignal_net_chat::api::ChallengeOption::Captcha as i128
    );

    #[derive(IsCType)]
    #[repr(u8)]
    #[capi(must_export)]
    enum Svr2CredentialsResult {
        Match,
        NoMatch,
        Invalid,
    }
    const_assert_eq!(
        Svr2CredentialsResult::Match as i128,
        libsignal_net_chat::api::registration::Svr2CredentialsResult::Match as i128
    );
    const_assert_eq!(
        Svr2CredentialsResult::NoMatch as i128,
        libsignal_net_chat::api::registration::Svr2CredentialsResult::NoMatch as i128
    );
    const_assert_eq!(
        Svr2CredentialsResult::Invalid as i128,
        libsignal_net_chat::api::registration::Svr2CredentialsResult::Invalid as i128
    );
}
