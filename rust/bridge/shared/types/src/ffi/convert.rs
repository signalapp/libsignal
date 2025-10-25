//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::{CStr, c_char, c_uchar};
use std::fmt::Display;
use std::num::{NonZeroU64, ParseIntError};
use std::ops::Deref;

use itertools::Itertools as _;
use libsignal_account_keys::{AccountEntropyPool, InvalidAccountEntropyPool};
use libsignal_net_chat::api::ChallengeOption;
use libsignal_net_chat::api::registration::PushToken;
use libsignal_protocol::*;
use paste::paste;
use uuid::Uuid;
use zkgroup::ZkGroupDeserializationFailure;

use super::*;
use crate::io::{InputStream, SyncInputStream};
use crate::net::chat::ChatListener;
use crate::net::registration::{
    ConnectChatBridge, RegistrationCreateSessionRequest, RegistrationPushToken,
};
use crate::support::{
    AsType, FixedLengthBincodeSerializable, IllegalArgumentError, Serialized, extend_lifetime,
};

/// Converts arguments from their FFI form to their Rust form.
///
/// `ArgTypeInfo` has two required methods: `borrow` and `load_from`. The use site looks like this:
///
/// ```
/// # use libsignal_bridge_types::ffi::*;
/// # struct Foo;
/// # impl SimpleArgTypeInfo for Foo {
/// #     type ArgType = isize;
/// #     fn convert_from(foreign: isize) -> SignalFfiResult<Self> { Ok(Foo) }
/// # }
/// # fn main() -> SignalFfiResult<()> {
/// #     let ffi_arg = 2;
/// let mut ffi_arg_borrowed = Foo::borrow(ffi_arg)?;
/// let rust_arg = Foo::load_from(&mut ffi_arg_borrowed);
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
    /// The FFI form of the argument (e.g. `std::ffi::c_uchar`).
    type ArgType;
    /// Local storage for the argument (ideally borrowed rather than copied).
    type StoredType: 'storage;
    /// "Borrows" the data in `foreign`, usually to establish a local lifetime or owning type.
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType>;
    /// Loads the Rust value from the data that's been `stored` by [`borrow()`](Self::borrow()).
    fn load_from(stored: &'storage mut Self::StoredType) -> Self;
}

/// A simpler interface for [`ArgTypeInfo`] for when no local storage is needed.
///
/// This trait is easier to use when writing FFI functions manually:
///
/// ```
/// # use libsignal_bridge_types::ffi::*;
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
    /// The FFI form of the argument (e.g. `std::ffi::c_uchar`).
    type ArgType;
    /// Converts the data in `foreign` to the Rust type.
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self>;
}

impl<'a, T> ArgTypeInfo<'a> for T
where
    T: SimpleArgTypeInfo + 'a,
{
    type ArgType = <Self as SimpleArgTypeInfo>::ArgType;
    type StoredType = Option<Self>;
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        Ok(Some(Self::convert_from(foreign)?))
    }
    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        stored.take().expect("only called once")
    }
}

/// Converts result values from their Rust form to their FFI form.
///
/// `ResultTypeInfo` is used to implement the `bridge_fn` macro, but can also be used outside it.
///
/// ```
/// # use libsignal_bridge_types::ffi::*;
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
    /// The FFI form of the result (e.g. `std::ffi::c_uchar`).
    type ResultType;
    /// Converts the data in `self` to the FFI type, similar to `try_into()`.
    fn convert_into(self) -> SignalFfiResult<Self::ResultType>;
}

impl<'a> ArgTypeInfo<'a> for &'a [u8] {
    type ArgType = BorrowedSliceOf<c_uchar>;
    type StoredType = Self::ArgType;
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        // Check preconditions up front.
        unsafe { foreign.as_slice()? };
        Ok(foreign)
    }
    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        unsafe { stored.as_slice().expect("checked earlier") }
    }
}

impl<'a> ArgTypeInfo<'a> for &'a mut [u8] {
    type ArgType = BorrowedMutableSliceOf<c_uchar>;
    type StoredType = Self::ArgType;
    fn borrow(mut foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        // Check preconditions up front.
        unsafe { foreign.as_slice_mut()? };
        Ok(foreign)
    }
    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        unsafe { stored.as_slice_mut().expect("checked earlier") }
    }
}

impl<'a> ArgTypeInfo<'a> for crate::support::ServiceIdSequence<'a> {
    type ArgType = <&'a [u8] as ArgTypeInfo<'a>>::ArgType;
    type StoredType = Self::ArgType;

    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        <&'a [u8]>::borrow(foreign)
    }

    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        let buffer = <&'a [u8]>::load_from(stored);
        Self::parse(buffer)
    }
}

impl<'a> ArgTypeInfo<'a> for Vec<&'a [u8]> {
    type ArgType = BorrowedSliceOf<BorrowedSliceOf<u8>>;
    type StoredType = Vec<&'a [u8]>;

    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let slices = unsafe { foreign.as_slice()? };
        slices
            .iter()
            .map(|next| unsafe {
                let next_slice = next.as_slice()?;
                // The lifetime of `next.as_slice()` is tied to the lifetime of `slices`. However,
                // we expect all of the slices in the argument to outlive this function call. (We
                // could make this safer by following the Java bridge in providing the parameter as
                // a reference rather than a value, at the expense of making the ArgTypeInfo traits
                // more complicated.)
                //
                // We *do* know that 'a won't outlive the function call, because ArgTypeInfo
                // constrains its 'a to the lifetime of the storage. That's why we're not using
                // SimpleArgTypeInfo here, even though we could.
                Ok(extend_lifetime::<'_, 'a, _>(next_slice))
            })
            .collect()
    }

    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        std::mem::take(stored)
    }
}

impl<const LEN: usize> SimpleArgTypeInfo for &mut [u8; LEN] {
    type ArgType = *mut [u8; LEN];
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(input: Self::ArgType) -> SignalFfiResult<Self> {
        unsafe { input.as_mut() }.ok_or_else(|| NullPointerError.into())
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
            return Err(NullPointerError.into());
        }

        match unsafe { CStr::from_ptr(foreign).to_str() } {
            Ok(s) => Ok(s.to_owned()),
            Err(e) => Err(e.into()),
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

impl SimpleArgTypeInfo for uuid::Uuid {
    type ArgType = *const [u8; 16];
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        match unsafe { foreign.as_ref() } {
            Some(array) => Ok(uuid::Uuid::from_bytes(*array)),
            None => Err(NullPointerError.into()),
        }
    }
}

impl ResultTypeInfo for uuid::Uuid {
    type ResultType = uuid::Bytes;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(*self.as_bytes())
    }
}

impl ResultTypeInfo for Option<uuid::Uuid> {
    type ResultType = [u8; 17];
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let mut bytes = [0; 17];
        if let Some(uuid) = self {
            let (present, out) = bytes.split_first_mut().expect("not empty");
            *present = true.into();
            out.copy_from_slice(uuid.as_bytes());
        }
        Ok(bytes)
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
                        IllegalArgumentError::new("invalid Service-Id-FixedWidthBinary").into()
                    })
            }
            None => Err(NullPointerError.into()),
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
            .map_err(|_| IllegalArgumentError::new("not an ACI").into())
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
            .map_err(|_| IllegalArgumentError::new("not a PNI").into())
    }
}

fn parse_e164(s: &str) -> SignalFfiResult<libsignal_core::E164> {
    let parsed = s
        .parse()
        .map_err(|_: ParseIntError| IllegalArgumentError::new(format!("{s} is not an e164")))?;
    Ok(parsed)
}

impl SimpleArgTypeInfo for libsignal_core::E164 {
    type ArgType = <String as SimpleArgTypeInfo>::ArgType;
    fn convert_from(e164: Self::ArgType) -> SignalFfiResult<Self> {
        let e164 = String::convert_from(e164)?;
        parse_e164(&e164)
    }
}

impl SimpleArgTypeInfo for Option<libsignal_core::E164> {
    type ArgType = <Option<String> as SimpleArgTypeInfo>::ArgType;
    fn convert_from(e164: Self::ArgType) -> SignalFfiResult<Self> {
        let e164 = Option::<String>::convert_from(e164)?;
        let parsed = e164.as_deref().map(parse_e164).transpose()?;
        Ok(parsed)
    }
}

impl SimpleArgTypeInfo for AccountEntropyPool {
    type ArgType = <String as SimpleArgTypeInfo>::ArgType;

    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let string = String::convert_from(foreign)?;
        string.parse().map_err(|e: InvalidAccountEntropyPool| {
            IllegalArgumentError::new(format!("bad account entropy pool: {e}")).into()
        })
    }
}

impl SimpleArgTypeInfo for libsignal_net_chat::api::messages::MultiRecipientSendAuthorization {
    type ArgType = BorrowedSliceOf<c_uchar>;

    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let slice = unsafe { foreign.as_slice()? };
        // If we ever have more than two options, we won't be able to just use "empty" for one of
        // them, but for now this is convenient.
        if slice.is_empty() {
            Ok(Self::Story)
        } else {
            let token =
                zkgroup::deserialize(slice).map_err(|_: ZkGroupDeserializationFailure| {
                    IllegalArgumentError::new("bad GroupSendFullToken")
                })?;
            Ok(Self::Group(token))
        }
    }
}

impl SimpleArgTypeInfo for Box<[u8]> {
    type ArgType = BorrowedSliceOf<c_uchar>;

    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let slice = unsafe { foreign.as_slice()? };
        Ok(slice.into())
    }
}

impl<const LEN: usize> SimpleArgTypeInfo for &'_ [u8; LEN] {
    type ArgType = *const [u8; LEN];
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(arg: *const [u8; LEN]) -> SignalFfiResult<Self> {
        unsafe { arg.as_ref() }.ok_or(NullPointerError.into())
    }
}

impl<const LEN: usize> SimpleArgTypeInfo for Option<&'_ [u8; LEN]> {
    type ArgType = *const [u8; LEN];
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(arg: Self::ArgType) -> SignalFfiResult<Self> {
        Ok(unsafe { arg.as_ref() })
    }
}

impl<const LEN: usize> ResultTypeInfo for [u8; LEN] {
    type ResultType = [u8; LEN];
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self)
    }
}

impl SimpleArgTypeInfo for Box<[String]> {
    type ArgType = BorrowedBytestringArray;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        unsafe { foreign.iter()? }
            .map(|bytes| {
                Ok(std::str::from_utf8(bytes)
                    .map_err(|_| IllegalArgumentError::new("invalid UTF-8"))?
                    .to_owned())
            })
            .try_collect()
    }
}

impl SimpleArgTypeInfo for Option<Box<[u8]>> {
    type ArgType = OptionalBorrowedSliceOf<c_uchar>;

    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let OptionalBorrowedSliceOf { present, value } = foreign;
        let slice = present.then(|| unsafe { value.as_slice() }).transpose()?;
        Ok(slice.map(Box::from))
    }
}

impl SimpleArgTypeInfo for libsignal_net::chat::LanguageList {
    type ArgType = <Box<[String]> as SimpleArgTypeInfo>::ArgType;

    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let entries: Vec<&str> = unsafe { foreign.iter()? }
            .map(|bytes| {
                std::str::from_utf8(bytes).map_err(|_| IllegalArgumentError::new("invalid UTF-8"))
            })
            .try_collect()?;
        Ok(libsignal_net::chat::LanguageList::parse(&entries)
            .map_err(|_| IllegalArgumentError::new("invalid language in list"))?)
    }
}

impl SimpleArgTypeInfo for &libsignal_account_keys::BackupKey {
    type ArgType = *const crate::net::svrb::BackupKeyBytes;

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(arg: Self::ArgType) -> SignalFfiResult<Self> {
        unsafe { arg.as_ref() }
            .ok_or(NullPointerError.into())
            .map(Into::into)
    }
}

macro_rules! bridge_trait {
    ($name:ident) => {
        paste! {
            impl<'a> ArgTypeInfo<'a> for &'a mut dyn $name {
                type ArgType = crate::ffi::ConstPointer< [<Ffi $name Struct>] >;
                type StoredType = &'a [<Ffi $name Struct>];
                #[allow(clippy::not_unsafe_ptr_arg_deref)]
                fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
                    match unsafe { foreign.into_inner().as_ref() } {
                        None => Err(NullPointerError.into()),
                        Some(store) => Ok(store),
                    }
                }
                fn load_from(stored: &'a mut Self::StoredType) -> Self {
                    stored
                }
            }

            impl<'a> ArgTypeInfo<'a> for Option<&'a dyn $name> {
                type ArgType = crate::ffi::ConstPointer< [<Ffi $name Struct>] >;
                type StoredType = Option<&'a [<Ffi $name Struct>]>;
                #[allow(clippy::not_unsafe_ptr_arg_deref)]
                fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
                    Ok(unsafe { foreign.into_inner().as_ref() })
                }
                fn load_from(stored: &'a mut Self::StoredType) -> Self {
                    stored.as_ref().map(|x| x as &'a dyn $name)
                }
            }
        }
    };
}

bridge_trait!(IdentityKeyStore);
bridge_trait!(PreKeyStore);
bridge_trait!(SenderKeyStore);
bridge_trait!(SessionStore);
bridge_trait!(SignedPreKeyStore);
bridge_trait!(KyberPreKeyStore);
bridge_trait!(InputStream);
bridge_trait!(SyncInputStream);

impl<'a> ArgTypeInfo<'a> for Box<dyn ChatListener> {
    type ArgType = crate::ffi::ConstPointer<FfiChatListenerStruct>;
    type StoredType = Option<Box<dyn ChatListener>>;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        Ok(Some(unsafe {
            foreign
                .into_inner()
                .as_ref()
                .ok_or(NullPointerError)?
                .make_listener()
        }))
    }
    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        stored.take().expect("not previously taken")
    }
}

impl<'a> ArgTypeInfo<'a> for Option<Box<dyn ChatListener>> {
    type ArgType = crate::ffi::ConstPointer<FfiChatListenerStruct>;
    type StoredType = Option<Box<dyn ChatListener>>;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        Ok(unsafe {
            foreign
                .into_inner()
                .as_ref()
                .map(|f| f.make_listener() as Box<_>)
        })
    }
    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        stored.take().map(|b| b as Box<_>)
    }
}

impl SimpleArgTypeInfo for Box<dyn ConnectChatBridge> {
    type ArgType = ConstPointer<FfiConnectChatBridgeStruct>;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let foreign = unsafe { foreign.into_inner().as_ref() }.ok_or(NullPointerError)?;
        Ok(Box::new(FfiConnectChatBridge::new(foreign)?))
    }
}

impl SimpleArgTypeInfo for RegistrationPushToken {
    type ArgType = *const std::ffi::c_char;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        // FFI is only used from Apple platforms.
        Ok(Self::Apn {
            push_token: String::convert_from(foreign)?,
        })
    }
}

impl SimpleArgTypeInfo for RegistrationCreateSessionRequest {
    type ArgType = FfiRegistrationCreateSessionRequest;

    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let FfiRegistrationCreateSessionRequest {
            number,
            push_token,
            mcc,
            mnc,
        } = foreign;
        let push_token: Option<String> = SimpleArgTypeInfo::convert_from(push_token)?;

        // The FFI bindings are only used for Swift, which is used on Apple platforms.
        let push_token = push_token.map(|push_token| PushToken::Apn { push_token });

        Ok(Self {
            number: String::convert_from(number)?,
            push_token,
            mcc: SimpleArgTypeInfo::convert_from(mcc)?,
            mnc: SimpleArgTypeInfo::convert_from(mnc)?,
        })
    }
}

impl SimpleArgTypeInfo for crate::net::registration::SignedPublicPreKey {
    type ArgType = FfiSignedPublicPreKey;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let FfiSignedPublicPreKey {
            key_id,
            public_key_type,
            public_key,
            signature,
        } = foreign;
        let public_key = match &public_key_type {
            FfiPublicKeyType::ECC => <&PublicKey>::convert_from(ConstPointer {
                raw: public_key.cast(),
            })?
            .serialize(),
            FfiPublicKeyType::Kyber => <&kem::PublicKey>::convert_from(ConstPointer {
                raw: public_key.cast(),
            })?
            .serialize(),
        };
        let signature = unsafe { signature.as_slice()? }.into();
        Ok(Self {
            key_id,
            public_key,
            signature,
        })
    }
}

impl<T: ResultTypeInfo, E> ResultTypeInfo for Result<T, E>
where
    E: IntoFfiError,
{
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

/// Allocates and returns a new Rust-owned C string.
impl ResultTypeInfo for String {
    type ResultType = *const std::ffi::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        self.deref().convert_into()
    }
}

/// Allocates and returns a new Rust-owned C string (or `NULL`).
impl ResultTypeInfo for Option<String> {
    type ResultType = *const std::ffi::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        self.as_deref().convert_into()
    }
}

/// Allocates and returns a new Rust-owned C string.
impl ResultTypeInfo for &str {
    type ResultType = *const std::ffi::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let cstr = CString::new(self).expect("No NULL characters in string being returned to C");
        Ok(cstr.into_raw())
    }
}

/// Allocates and returns a new Rust-owned C string (or `NULL`).
impl ResultTypeInfo for Option<&str> {
    type ResultType = *const std::ffi::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        match self {
            Some(s) => s.convert_into(),
            None => Ok(std::ptr::null()),
        }
    }
}

/// Allocates and returns an array of Rust-owned C strings.
impl ResultTypeInfo for Box<[String]> {
    type ResultType = StringArray;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(StringArray::from_iter(&*self))
    }
}

/// Allocates and returns an array of Rust-owned bytestrings.
impl ResultTypeInfo for Box<[Vec<u8>]> {
    type ResultType = BytestringArray;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(BytestringArray::from_iter(&*self))
    }
}

impl ResultTypeInfo for Vec<u8> {
    type ResultType = OwnedBufferOf<std::ffi::c_uchar>;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(OwnedBufferOf::from(self.into_boxed_slice()))
    }
}

impl ResultTypeInfo for &[u8] {
    type ResultType = OwnedBufferOf<std::ffi::c_uchar>;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        self.to_vec().convert_into()
    }
}

impl ResultTypeInfo for Option<&[u8]> {
    type ResultType = OwnedBufferOf<std::ffi::c_uchar>;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self
            .map(|slice| {
                let owned = OwnedBufferOf::from(Box::from(slice));
                // A boxed slice always has a non-null base pointer, even when
                // the length is zero.
                debug_assert_ne!(owned.base, std::ptr::null_mut());
                owned
            })
            .unwrap_or(OwnedBufferOf {
                base: std::ptr::null_mut(),
                length: 0,
            }))
    }
}

/// `u32::MAX` (`UINT_MAX`, `~0u`) is used to represent `None` here.
impl ResultTypeInfo for Option<u32> {
    type ResultType = u32;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self.unwrap_or(u32::MAX))
    }
}

/// [`u64::MAX`] (`~0u`) is used to represent `None` here.
impl ResultTypeInfo for Option<u64> {
    type ResultType = u64;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self.unwrap_or(u64::MAX))
    }
}

impl SimpleArgTypeInfo for crate::protocol::Timestamp {
    type ArgType = u64;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        Ok(Self::from_epoch_millis(foreign))
    }
}

impl ResultTypeInfo for crate::protocol::Timestamp {
    type ResultType = u64;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self.epoch_millis())
    }
}

impl SimpleArgTypeInfo for crate::zkgroup::Timestamp {
    type ArgType = u64;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        Ok(Self::from_epoch_seconds(foreign))
    }
}

impl ResultTypeInfo for crate::zkgroup::Timestamp {
    type ResultType = u64;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self.epoch_seconds())
    }
}

impl ResultTypeInfo for Box<[ChallengeOption]> {
    type ResultType = <Vec<u8> as ResultTypeInfo>::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        static_assertions::assert_eq_size!(ChallengeOption, u8);
        static_assertions::assert_eq_align!(ChallengeOption, u8);
        // The compiler can optimize this iterated conversion away to nothing.
        Ok(IntoIterator::into_iter(self)
            .map(|r| r as u8)
            .collect::<Box<_>>()
            .into())
    }
}

impl ResultTypeInfo for &[ChallengeOption] {
    type ResultType = <Vec<u8> as ResultTypeInfo>::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Box::<[_]>::from(self).convert_into()
    }
}

impl ResultTypeInfo for Vec<ServiceId> {
    type ResultType = OwnedBufferOf<ServiceIdFixedWidthBinaryBytes>;

    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self
            .into_iter()
            .map(|id| id.service_id_fixed_width_binary())
            .collect::<Box<[_]>>()
            .into())
    }
}

impl ResultTypeInfo for &'_ [libsignal_net_chat::api::messages::MismatchedDeviceError] {
    type ResultType = OwnedBufferOf<FfiMismatchedDevicesError>;

    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self
            .iter()
            .map(|entry| FfiMismatchedDevicesError {
                account: entry.account.service_id_fixed_width_binary(),
                missing_devices: entry
                    .missing_devices
                    .iter()
                    .map(|&id| id.into())
                    .collect::<Box<[_]>>()
                    .into(),
                extra_devices: entry
                    .extra_devices
                    .iter()
                    .map(|&id| id.into())
                    .collect::<Box<[_]>>()
                    .into(),
                stale_devices: entry
                    .stale_devices
                    .iter()
                    .map(|&id| id.into())
                    .collect::<Box<[_]>>()
                    .into(),
            })
            .collect::<Box<[_]>>()
            .into())
    }
}

impl ResultTypeInfo for Box<[libsignal_net_chat::api::registration::RegisterResponseBadge]> {
    type ResultType = OwnedBufferOf<FfiRegisterResponseBadge>;

    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let converted = IntoIterator::into_iter(self)
            .map(ResultTypeInfo::convert_into)
            .try_collect();
        Ok(Box::into(converted?))
    }
}

impl ResultTypeInfo for libsignal_net_chat::api::registration::RegisterResponseBadge {
    type ResultType = FfiRegisterResponseBadge;

    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let Self {
            id,
            visible,
            expiration,
        } = self;
        Ok(FfiRegisterResponseBadge {
            id: id.convert_into()?,
            visible,
            expiration_secs: expiration.as_secs_f64(),
        })
    }
}

/// A marker for Rust objects exposed as opaque pointers.
///
/// When we do this, we hand the lifetime over to the app. Since we don't know how long the object
/// will be kept alive, it can't (safely) have references to anything with a non-static lifetime.
pub trait BridgeHandle: 'static {}

impl<T: BridgeHandle> SimpleArgTypeInfo for &T {
    type ArgType = ConstPointer<T>;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: ConstPointer<T>) -> SignalFfiResult<Self> {
        unsafe { native_handle_cast(foreign.into_inner()) }
    }
}

impl<T: BridgeHandle> SimpleArgTypeInfo for Option<&T> {
    type ArgType = ConstPointer<T>;
    fn convert_from(foreign: ConstPointer<T>) -> SignalFfiResult<Self> {
        if foreign.raw.is_null() {
            Ok(None)
        } else {
            <&T>::convert_from(foreign).map(Some)
        }
    }
}

impl<T: BridgeHandle> SimpleArgTypeInfo for &mut T {
    type ArgType = MutPointer<T>;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: MutPointer<T>) -> SignalFfiResult<Self> {
        unsafe { native_handle_cast_mut(foreign.raw) }
    }
}

impl<'a, T: BridgeHandle> ArgTypeInfo<'a> for &'a [&'a T] {
    type ArgType = BorrowedSliceOf<ConstPointer<T>>;
    type StoredType = Self::ArgType;
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        // Check preconditions up front.
        let slice_of_pointers = unsafe { foreign.as_slice() }?;
        if slice_of_pointers.contains(&ConstPointer {
            raw: std::ptr::null(),
        }) {
            return Err(NullPointerError.into());
        }

        Ok(foreign)
    }
    fn load_from(input: &'a mut Self::ArgType) -> Self {
        if input.base.is_null() {
            // Early-exit so that we don't construct a slice with a NULL base later.
            // Note that we already checked that the length is 0 by using slice_of_pointers above.
            return &[];
        }

        let base_ptr_for_slice_of_refs = input.base as *const &T;

        unsafe { std::slice::from_raw_parts(base_ptr_for_slice_of_refs, input.length) }
    }
}

impl<'a> ArgTypeInfo<'a> for &'a SignalFfiError {
    // This is a lie, we can't *really* guarantee that the contents of an error are unwind-safe. But
    // it's very unlikely we'll encounter one that isn't, especially when we only use them immutably
    // in practice.
    type ArgType = UnwindSafeArg<*const SignalFfiError>;
    type StoredType = *const SignalFfiError;

    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        if foreign.is_null() {
            return Err(NullPointerError.into());
        }
        Ok(foreign.0)
    }

    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        unsafe { stored.as_ref() }.expect("non-null checked above")
    }
}

impl<T: BridgeHandle> ResultTypeInfo for T {
    type ResultType = MutPointer<T>;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(Box::into_raw(Box::new(self)).into())
    }
}

impl<T: BridgeHandle> ResultTypeInfo for Option<T> {
    type ResultType = MutPointer<T>;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        match self {
            Some(obj) => obj.convert_into(),
            None => Ok(MutPointer::from(std::ptr::null_mut())),
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
impl<T> SimpleArgTypeInfo for Serialized<T>
where
    T: FixedLengthBincodeSerializable
        + for<'a> serde::Deserialize<'a>
        + partial_default::PartialDefault,
{
    type ArgType = *const T::Array;

    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let array = unsafe { foreign.as_ref() }.ok_or(NullPointerError)?;
        let result: T = zkgroup::deserialize(array.as_ref()).unwrap_or_else(|_| {
            panic!(
                "{} should have been validated on creation",
                std::any::type_name::<T>()
            )
        });
        Ok(Serialized::from(result))
    }
}

impl<T, P> SimpleArgTypeInfo for AsType<T, P>
where
    P: TryInto<T, Error: Display> + SimpleArgTypeInfo,
{
    type ArgType = P::ArgType;

    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self> {
        let p = P::convert_from(foreign)?;
        p.try_into()
            .map_err(|e| {
                IllegalArgumentError::new(format!("invalid {}: {e}", std::any::type_name::<T>()))
                    .into()
            })
            .map(AsType::from)
    }
}

impl<T> ResultTypeInfo for Serialized<T>
where
    T: FixedLengthBincodeSerializable + serde::Serialize,
{
    type ResultType = T::Array;

    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let result = zkgroup::serialize(self.deref());
        Ok(result.as_slice().try_into().expect("wrong serialized size"))
    }
}

impl ResultTypeInfo for () {
    /// Ideally we wouldn't return *anything,* but C doesn't support that.
    type ResultType = bool;

    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(false)
    }
}

impl<A: ResultTypeInfo, B: ResultTypeInfo> ResultTypeInfo for (A, B) {
    type ResultType = PairOf<A::ResultType, B::ResultType>;

    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(PairOf {
            first: self.0.convert_into()?,
            second: self.1.convert_into()?,
        })
    }
}

impl<A: ResultTypeInfo, B: ResultTypeInfo> ResultTypeInfo for Option<(A, B)>
// We can simplify this when our MSRV is 1.88, when pointers become Default.
// Meanwhile, we'll rely on the fact that every C type is zeroable.
where
    A::ResultType: zerocopy::FromZeros,
    B::ResultType: zerocopy::FromZeros,
{
    type ResultType = OptionalPairOf<A::ResultType, B::ResultType>;

    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let Some(value) = self else {
            return Ok(OptionalPairOf {
                present: false,
                first: zerocopy::FromZeros::new_zeroed(),
                second: zerocopy::FromZeros::new_zeroed(),
            });
        };
        Ok(OptionalPairOf {
            present: true,
            first: value.0.convert_into()?,
            second: value.1.convert_into()?,
        })
    }
}

impl ResultTypeInfo for libsignal_net::cdsi::LookupResponse {
    type ResultType = FfiCdsiLookupResponse;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let Self {
            records,
            debug_permits_used,
        } = self;

        let entries = records
            .into_iter()
            .map(|e| FfiCdsiLookupResponseEntry {
                e164: NonZeroU64::from(e.e164).into(),
                aci: e.aci.map(Uuid::from).unwrap_or(Uuid::nil()).into_bytes(),
                pni: e.pni.map(Uuid::from).unwrap_or(Uuid::nil()).into_bytes(),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice()
            .into();

        Ok(FfiCdsiLookupResponse {
            entries,
            debug_permits_used,
        })
    }
}

impl ResultTypeInfo for libsignal_net::chat::Response {
    type ResultType = FfiChatResponse;

    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let Self {
            status,
            message,
            body,
            headers,
        } = self;

        let header_strings: Vec<*const c_char> = headers
            .iter()
            .map(|(k, v)| {
                // We only support string values for now (see chat_websocket.proto).
                format!(
                    "{}:{}",
                    k,
                    v.to_str().expect("Chat never produces non-string headers")
                )
                .convert_into()
            })
            .collect::<SignalFfiResult<_>>()?;

        Ok(FfiChatResponse {
            status: status.as_u16(),
            message: message.unwrap_or_default().convert_into()?,
            headers: OwnedBufferOf::from(header_strings.into_boxed_slice()),
            body: body.unwrap_or_default().convert_into()?,
        })
    }
}

impl ResultTypeInfo for libsignal_net_chat::api::registration::CheckSvr2CredentialsResponse {
    type ResultType = FfiCheckSvr2CredentialsResponse;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let Self { matches } = self;
        let entries = matches
            .into_iter()
            .map(|(key, value)| {
                let mut bytes = key.into_bytes();
                bytes.push(value as u8);
                bytes
            })
            .collect_vec();
        Ok(FfiCheckSvr2CredentialsResponse {
            entries: entries.into_boxed_slice().convert_into()?,
        })
    }
}

/// Defines an `extern "C"` function for cloning the given type.
#[macro_export]
macro_rules! ffi_bridge_handle_clone {
    ( $typ:ty as $ffi_name:ident ) => {
        ::paste::paste! {
            #[unsafe(export_name = concat!(
                env!("LIBSIGNAL_BRIDGE_FN_PREFIX_FFI"),
                stringify!($ffi_name),
                "_clone",
            ))]
            pub unsafe extern "C" fn [<__bridge_handle_ffi_ $ffi_name _clone>](
                new_obj: *mut ffi::MutPointer<$typ>,
                obj: ffi::ConstPointer<$typ>,
            ) -> *mut $crate::ffi::SignalFfiError {
                $crate::ffi::run_ffi_safe(|| unsafe {
                    let obj = $crate::ffi::native_handle_cast::<$typ>(obj.into_inner())?;
                    $crate::ffi::write_result_to::<$typ>(new_obj, obj.clone())
                })
            }
        }
    };
}

/// Implements `crate::ffi::BridgeHandle` for the given type.
#[macro_export]
macro_rules! ffi_bridge_as_handle {
    ( $typ:ty as false $(, $($_:tt)*)? ) => {};
    ( $typ:ty as $ffi_name:ident ) => {
        impl $crate::ffi::BridgeHandle for $typ {}
    };
    ( $typ:ty ) => {
        ::paste::paste! {
            $crate::ffi_bridge_as_handle!($typ as [<$typ:snake>] );
        }
    };
}

/// Defines boilerplate `extern "C"` functions for the given type.
#[macro_export]
macro_rules! ffi_bridge_handle_fns {
    ( $typ:ty as false $(, $($_:tt)*)? ) => {};
    ( $typ:ty as $ffi_name:ident, clone = false ) => {
        $crate::ffi_bridge_handle_destroy!($typ as $ffi_name);
    };
    ( $typ:ty as $ffi_name:ident ) => {
        $crate::ffi_bridge_handle_fns!($typ as $ffi_name, clone = false);
        $crate::ffi_bridge_handle_clone!($typ as $ffi_name);
    };
    ( $typ:ty $(, clone = $_:tt)? ) => {
        ::paste::paste! {
            $crate::ffi_bridge_handle_fns!($typ as [<$typ:snake>] $(, clone = $_)? );
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
trivial!(u16);
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
#[macro_export]
macro_rules! ffi_arg_type {
    (u8) => (u8);
    (u16) => (u16);
    (i32) => (i32);
    (u32) => (u32);
    (u64) => (u64);
    (Option<u32>) => (u32);
    (usize) => (usize);
    (bool) => (bool);
    (&[u8]) => (ffi::BorrowedSliceOf<std::ffi::c_uchar>);
    (&mut [u8]) => (ffi::BorrowedMutableSliceOf<std::ffi::c_uchar>);
    (ServiceIdSequence<'_>) => (ffi::BorrowedSliceOf<std::ffi::c_uchar>);
    (Vec<&[u8]>) => (ffi::BorrowedSliceOf<ffi_arg_type!(&[u8])>);
    (String) => (*const std::ffi::c_char);
    (Option<String>) => (*const std::ffi::c_char);
    (Option<&str>) => (*const std::ffi::c_char);
    (Timestamp) => (u64);
    (Uuid) => (*const [u8; 16]);
    (ServiceId) => (*const libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    (Aci) => (*const libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    (Pni) => (*const libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    (E164) => (*const std::ffi::c_char);
    (Option<E164>) => (*const std::ffi::c_char);
    (AccountEntropyPool) => (*const std::ffi::c_char);
    (RegistrationCreateSessionRequest) => (ffi::FfiRegistrationCreateSessionRequest);
    (RegistrationPushToken) => (*const std::ffi::c_char);
    (SignedPublicPreKey) => (ffi::FfiSignedPublicPreKey);
    (MultiRecipientSendAuthorization) => (ffi_arg_type!(&[u8]));
    (&SignalFfiError) => (ffi::UnwindSafeArg<*const SignalFfiError>);
    (&[u8; $len:expr]) => (*const [u8; $len]);
    (Option<&[u8; $len:expr]>) => (*const [u8; $len]);
    (&[& $typ:ty]) => (ffi::BorrowedSliceOf<ffi::ConstPointer< $typ >>);
    (&mut dyn $typ:ty) => (ffi::ConstPointer< ::paste::paste!(ffi::[<Ffi $typ Struct>]) >);
    (Option<&dyn $typ:ty>) => (ffi::ConstPointer< ::paste::paste!(ffi::[<Ffi $typ Struct>]) >);
    (&BackupKey) => (*const $crate::net::svrb::BackupKeyBytes);
    (& $typ:ty) => (ffi::ConstPointer< $typ >);
    (&mut $typ:ty) => (ffi::MutPointer< $typ >);
    (Option<& $typ:ty>) => (ffi::ConstPointer< $typ >);
    (Box<[String]>) => (ffi::BorrowedBytestringArray);
    (LanguageList) => (ffi::BorrowedBytestringArray);
    (Box<[u8]>) => (ffi::BorrowedSliceOf<std::ffi::c_uchar>);
    (Box<dyn $typ:ty >) => (ffi::ConstPointer< ::paste::paste!(ffi::[<Ffi $typ Struct>]) >);
    (Option<Box<dyn $typ:ty> >) => (ffi::ConstPointer< ::paste::paste!(ffi::[<Ffi $typ Struct>]) >);
    (Option<Box<[u8]> >) => (ffi::OptionalBorrowedSliceOf<std::ffi::c_uchar>);

    (Ignored<$typ:ty>) => (*const std::ffi::c_void);
    (AsType<$typ:ident, $bridged:ident>) => (ffi_arg_type!($bridged));

    (TestingFutureCancellationGuard) => (ffi_arg_type!(&TestingFutureCancellationCounter));

    // In order to provide a fixed-sized array of the correct length,
    // a serialized type FooBar must have a constant FOO_BAR_LEN that's in scope (and exposed to C).
    (Serialized<$typ:ident>) => (*const [std::ffi::c_uchar; ::paste::paste!([<$typ:snake:upper _LEN>])]);
}

/// Syntactically translates `bridge_fn` result types to FFI types for `cbindgen`.
///
/// This is a syntactic transformation (because that's how Rust macros work), so new result types
/// will need to be added here directly even if they already implement [`ResultTypeInfo`]. The
/// default behavior is to assume we're returning an opaque boxed value `*mut Foo` (`Foo *` in C).
#[macro_export]
macro_rules! ffi_result_type {
    // These rules only match a single token for a Result's success type.
    // We can't use `:ty` because we need the resulting tokens to be matched recursively rather than
    // treated as a single unit, and we can't match multiple tokens because Rust's macros match
    // eagerly. Therefore, if you need to return a more complicated Result type, you'll have to add
    // another rule for its form.
    (std::result::Result<$($rest:tt)+) => (ffi_result_type!(Result<$($rest)+));
    (Result<$typ:tt $(, $_:ty)?>) => (ffi_result_type!($typ));
    (Result<&$typ:tt $(, $_:ty)?>) => (ffi_result_type!(&$typ));
    (Result<Option<&$typ:tt> $(, $_:ty)?>) => (ffi_result_type!(&$typ));
    (Result<$typ:tt<$($args:tt),+> $(, $_:ty)?>) => (ffi_result_type!($typ<$($args)+>));

    (()) => (bool); // Only relevant for Futures.

    // Like Result, we can't use `:ty` here because we need the resulting tokens to be matched
    // recursively. We can at least match several tokens in the second component though.
    (($a:tt, $($b:tt)+)) => (ffi::PairOf<ffi_result_type!($a), ffi_result_type!($($b)+)>);
    (Option<($a:tt, $($b:tt)+)>) => (ffi::OptionalPairOf<ffi_result_type!($a), ffi_result_type!($($b)+)>);

    (u8) => (u8);
    (u16) => (u16);
    (i32) => (i32);
    (u32) => (u32);
    (Option<u32>) => (u32);
    (u64) => (u64);
    (Option<u64>) => (u64);
    (bool) => (bool);
    (&str) => (*const std::ffi::c_char);
    (String) => (*const std::ffi::c_char);
    (Option<String>) => (*const std::ffi::c_char);
    (Option<&str>) => (*const std::ffi::c_char);
    (Timestamp) => (u64);
    (Uuid) => ([u8; 16]);
    (Option<Uuid>) => (ffi::OptionalUuid);
    (ServiceId) => (libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    (Aci) => (libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    (Pni) => (libsignal_protocol::ServiceIdFixedWidthBinaryBytes);
    ([u8; $len:expr]) => ([u8; $len]);
    (&[u8]) => (ffi::OwnedBufferOf<std::ffi::c_uchar>);
    (Option<&[u8]>) => (ffi::OwnedBufferOf<std::ffi::c_uchar>);
    (Vec<u8>) => (ffi::OwnedBufferOf<std::ffi::c_uchar>);
    (Box<[String]>) => (ffi::StringArray);
    (Box<[Vec<u8>]>) => (ffi::BytestringArray);
    (Box<[ChallengeOption]>) => (ffi_result_type!(Vec<u8>));
    (Vec<ServiceId>) => (ffi::OwnedBufferOf<libsignal_protocol::ServiceIdFixedWidthBinaryBytes>);
    (&[MismatchedDeviceError]) => (ffi::OwnedBufferOf<ffi::FfiMismatchedDevicesError>);
    (Option<$typ:ty>) => ($crate::ffi::MutPointer<$typ>);

    (LookupResponse) => (ffi::FfiCdsiLookupResponse);
    (ChatResponse) => (ffi::FfiChatResponse);
    (CheckSvr2CredentialsResponse) => (ffi::FfiCheckSvr2CredentialsResponse);
    (Box<[RegisterResponseBadge]>) => (ffi::OwnedBufferOf<ffi::FfiRegisterResponseBadge>);

    // In order to provide a fixed-sized array of the correct length,
    // a serialized type FooBar must have a constant FOO_BAR_LEN that's in scope (and exposed to C).
    (Serialized<$typ:ident>) => ([std::ffi::c_uchar; ::paste::paste!([<$typ:snake:upper _LEN>])]);

    (Ignored<$typ:ty>) => (*const std::ffi::c_void);

    ( $typ:ty ) => ($crate::ffi::MutPointer<$typ>);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn optional_buffer_convert() {
        {
            let owned_buffer = <Option<&[u8]>>::convert_into(Some(b"abcdef")).expect("can convert");
            assert_ne!(owned_buffer.base, std::ptr::null_mut());
            assert_eq!(owned_buffer.length, 6);
            let _ = unsafe { owned_buffer.into_box() };
        }

        {
            let owned_buffer = <Option<&[u8]>>::convert_into(Some(&[])).expect("can convert");
            assert_ne!(owned_buffer.base, std::ptr::null_mut());
            assert_eq!(owned_buffer.length, 0);
            let _ = unsafe { owned_buffer.into_box() };
        }

        {
            let owned_buffer = <Option<&[u8]>>::convert_into(None).expect("can convert");
            assert_eq!(owned_buffer.base, std::ptr::null_mut());
            assert_eq!(owned_buffer.length, 0);
            let _ = unsafe { owned_buffer.into_box() };
        }
    }
}
