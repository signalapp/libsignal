//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::ParseIntError;
use std::ops::Deref;
use std::sync::Arc;

use itertools::Itertools as _;
use jni::JNIEnv;
use jni::objects::{AutoLocal, JByteBuffer, JIntArray, JMap, JObjectArray};
use jni::sys::{JNI_FALSE, JNI_TRUE, jbyte};
use libsignal_account_keys::{AccountEntropyPool, InvalidAccountEntropyPool};
use libsignal_core::try_scoped;
use libsignal_net::cdsi::LookupResponseEntry;
use libsignal_protocol::*;
use paste::paste;

use super::*;
use crate::io::{InputStream, SyncInputStream};
use crate::message_backup::MessageBackupValidationOutcome;
use crate::net::chat::ChatListener;
use crate::net::registration::{ConnectChatBridge, RegistrationPushToken};
use crate::support::{Array, AsType, FixedLengthBincodeSerializable, Serialized, extend_lifetime};

/// Converts arguments from their JNI form to their Rust form.
///
/// `ArgTypeInfo` has two required methods: `borrow` and `load_from`. The use site looks like this:
///
/// ```no_run
/// # use libsignal_bridge_types::jni::*;
/// # use jni::JNIEnv;
/// # struct Foo;
/// # impl SimpleArgTypeInfo<'_> for Foo {
/// #     type ArgType = isize;
/// #     fn convert_from(env: &mut JNIEnv, foreign: &isize) -> Result<Self, BridgeLayerError> { Ok(Foo) }
/// # }
/// # fn test(env: &mut JNIEnv, jni_arg: isize) -> Result<(), BridgeLayerError> {
/// let mut jni_arg_borrowed = Foo::borrow(env, &jni_arg)?;
/// let rust_arg = Foo::load_from(&mut jni_arg_borrowed);
/// #     Ok(())
/// # }
/// ```
///
/// The `'context` lifetime allows for borrowed values to depend on the current JNI stack frame;
/// that is, they can be assured that referenced objects will not be GC'd out from under them. The
/// `'param` lifetime allows for depending on the current *Rust* stack frame, which is necessary for
/// some `JNIEnv` APIs.
///
/// `ArgTypeInfo` is used to implement the `bridge_fn` macro, but can also be used outside it.
///
/// If the Rust type can be directly loaded from `ArgType` with no local storage needed, implement
/// [`SimpleArgTypeInfo`] instead.
///
/// Implementers should also see the `jni_arg_type` macro in `convert.rs`.
pub trait ArgTypeInfo<'storage, 'param: 'storage, 'context: 'param>: Sized {
    /// The JNI form of the argument (e.g. `jni::jint`).
    type ArgType: 'param;
    /// Local storage for the argument (ideally borrowed rather than copied).
    type StoredType: 'storage;
    /// "Borrows" the data in `foreign`, usually to establish a local lifetime or owning type.
    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError>;
    /// Loads the Rust value from the data that's been `stored` by [`borrow()`](Self::borrow()).
    fn load_from(stored: &'storage mut Self::StoredType) -> Self;
}

/// A simpler interface for [`ArgTypeInfo`] for when no local storage is needed.
///
/// This trait is easier to use when writing JNI functions manually:
///
/// ```no_run
/// # use libsignal_bridge_types::jni::*;
/// # use jni::objects::JObject;
/// # use jni::JNIEnv;
/// # struct Foo;
/// impl<'a> SimpleArgTypeInfo<'a> for Foo {
///     type ArgType = JObject<'a>;
///     fn convert_from(env: &mut JNIEnv, foreign: &JObject<'a>) -> Result<Self, BridgeLayerError> {
///         // ...
///         # Ok(Foo)
///     }
/// }
///
/// # fn test<'a>(env: &mut JNIEnv<'a>, jni_arg: JObject<'a>) -> Result<(), BridgeLayerError> {
/// let rust_arg = Foo::convert_from(env, &jni_arg)?;
/// #     Ok(())
/// # }
/// ```
///
/// However, some types do need the full flexibility of `ArgTypeInfo`.
pub trait SimpleArgTypeInfo<'a>: Sized {
    /// The JNI form of the argument (e.g. `jint`).
    type ArgType: 'a;
    /// Converts the data in `foreign` to the Rust type.
    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError>;
}

impl<'storage, 'param: 'storage, 'context: 'param, T> ArgTypeInfo<'storage, 'param, 'context> for T
where
    T: SimpleArgTypeInfo<'context> + 'storage,
{
    type ArgType = <Self as SimpleArgTypeInfo<'context>>::ArgType;
    type StoredType = Option<Self>;
    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        Ok(Some(Self::convert_from(env, foreign)?))
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        stored.take().expect("only called once")
    }
}

/// Converts result values from their Rust form to their FFI form.
///
/// `ResultTypeInfo` is used to implement the `bridge_fn` macro, but can also be used outside it.
///
/// ```no_run
/// # use libsignal_bridge_types::jni::*;
/// # use jni::JNIEnv;
/// # use jni::objects::JString;
/// # struct Foo;
/// # impl<'a> ResultTypeInfo<'a> for Foo {
/// #     type ResultType = JString<'a>;
/// #     fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<JString<'a>, BridgeLayerError> { todo!() }
/// # }
/// # fn test<'a>(env: &mut JNIEnv<'a>) -> Result<(), BridgeLayerError> {
/// #     let rust_result = Foo;
/// let jni_result = rust_result.convert_into(env)?;
/// #     Ok(())
/// # }
/// ```
///
/// Implementers should also see the `jni_result_type` macro in `convert.rs`.
pub trait ResultTypeInfo<'a>: Sized {
    /// The JNI form of the result (e.g. `jint`).
    type ResultType: Into<JValueOwned<'a>>;
    /// Converts the data in `self` to the JNI type, similar to `try_into()`.
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError>;
}

/// Supports values `0..=Integer.MAX_VALUE`.
///
/// Negative `int` values are *not* reinterpreted as large `u32` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u32`.
impl SimpleArgTypeInfo<'_> for u32 {
    type ArgType = jint;
    fn convert_from(_env: &mut JNIEnv, foreign: &jint) -> Result<Self, BridgeLayerError> {
        if *foreign < 0 {
            return Err(BridgeLayerError::IntegerOverflow(format!(
                "{foreign} to u32"
            )));
        }
        Ok(*foreign as u32)
    }
}

/// Supports values `0..=Integer.MAX_VALUE`. Negative values are considered `None`.
///
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `Option<u32>`.
impl SimpleArgTypeInfo<'_> for Option<u32> {
    type ArgType = jint;
    fn convert_from(env: &mut JNIEnv, foreign: &jint) -> Result<Self, BridgeLayerError> {
        if *foreign < 0 {
            Ok(None)
        } else {
            u32::convert_from(env, foreign).map(Some)
        }
    }
}

/// Reinterprets the bits of the Java `long` as a `u64`.
impl SimpleArgTypeInfo<'_> for u64 {
    type ArgType = jlong;
    fn convert_from(_env: &mut JNIEnv, foreign: &jlong) -> Result<Self, BridgeLayerError> {
        Ok(*foreign as u64)
    }
}

/// Supports values `0..=Long.MAX_VALUE`.
///
/// Negative `long` values are *not* reinterpreted as large `u64` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u64`.
impl SimpleArgTypeInfo<'_> for crate::protocol::Timestamp {
    type ArgType = jlong;
    fn convert_from(_env: &mut JNIEnv, foreign: &jlong) -> Result<Self, BridgeLayerError> {
        if *foreign < 0 {
            return Err(BridgeLayerError::IntegerOverflow(format!(
                "{foreign} to Timestamp (u64)"
            )));
        }
        Ok(Self::from_epoch_millis(*foreign as u64))
    }
}

/// Supports values `0..=Long.MAX_VALUE`.
///
/// Negative `long` values are *not* reinterpreted as large `u64` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u64`.
impl SimpleArgTypeInfo<'_> for crate::zkgroup::Timestamp {
    type ArgType = jlong;
    fn convert_from(_env: &mut JNIEnv, foreign: &jlong) -> Result<Self, BridgeLayerError> {
        if *foreign < 0 {
            return Err(BridgeLayerError::IntegerOverflow(format!(
                "{foreign} to Timestamp (u64)"
            )));
        }
        Ok(Self::from_epoch_seconds(*foreign as u64))
    }
}

/// Supports all valid byte values `0..=255`.
impl SimpleArgTypeInfo<'_> for u8 {
    type ArgType = jint;
    fn convert_from(_env: &mut JNIEnv, foreign: &jint) -> Result<Self, BridgeLayerError> {
        u8::try_from(*foreign)
            .map_err(|_| BridgeLayerError::IntegerOverflow(format!("{foreign} to u8")))
    }
}

/// Supports all valid u16 values `0..=65536`.
impl SimpleArgTypeInfo<'_> for u16 {
    type ArgType = jint;
    fn convert_from(_env: &mut JNIEnv, foreign: &jint) -> Result<Self, BridgeLayerError> {
        u16::try_from(*foreign)
            .map_err(|_| BridgeLayerError::IntegerOverflow(format!("{foreign} to u16")))
    }
}

impl<'a> SimpleArgTypeInfo<'a> for String {
    type ArgType = JString<'a>;
    fn convert_from(env: &mut JNIEnv, foreign: &JString<'a>) -> Result<Self, BridgeLayerError> {
        if foreign.is_null() {
            return Err(BridgeLayerError::NullPointer(Some("java.lang.String")));
        }
        Ok(env
            .get_string(foreign)
            .check_exceptions(env, "String::convert_from")?
            .into())
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Option<String> {
    type ArgType = JString<'a>;
    fn convert_from(env: &mut JNIEnv<'a>, foreign: &JString<'a>) -> Result<Self, BridgeLayerError> {
        if foreign.is_null() {
            Ok(None)
        } else {
            String::convert_from(env, foreign).map(Some)
        }
    }
}

impl<'a> SimpleArgTypeInfo<'a> for uuid::Uuid {
    type ArgType = JObject<'a>;
    fn convert_from(env: &mut JNIEnv, foreign: &JObject<'a>) -> Result<Self, BridgeLayerError> {
        check_jobject_type(env, foreign, ClassName("java.util.UUID"))?;
        let args = jni_args!(() -> long);
        let msb: jlong = call_method_checked(env, foreign, "getMostSignificantBits", args)?;
        let lsb: jlong = call_method_checked(env, foreign, "getLeastSignificantBits", args)?;

        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&msb.to_be_bytes());
        bytes[8..].copy_from_slice(&lsb.to_be_bytes());
        Ok(uuid::Uuid::from_bytes(bytes))
    }
}

impl<'a> SimpleArgTypeInfo<'a> for libsignal_core::E164 {
    type ArgType = <String as SimpleArgTypeInfo<'a>>::ArgType;
    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        let e164 = String::convert_from(env, foreign)?;
        let e164 = e164.parse().map_err(|_: ParseIntError| {
            BridgeLayerError::BadArgument(format!("'{e164}' is not an e164"))
        })?;
        Ok(e164)
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Option<libsignal_core::E164> {
    type ArgType = <String as SimpleArgTypeInfo<'a>>::ArgType;
    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        if foreign.is_null() {
            return Ok(None);
        }
        let res = libsignal_core::E164::convert_from(env, foreign)?;
        Ok(Some(res))
    }
}

impl<'a> SimpleArgTypeInfo<'a> for AccountEntropyPool {
    type ArgType = <String as SimpleArgTypeInfo<'a>>::ArgType;
    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        let pool = String::convert_from(env, foreign)?;
        pool.parse().map_err(|e: InvalidAccountEntropyPool| {
            BridgeLayerError::BadArgument(format!("bad account entropy pool: {e}"))
        })
    }
}

impl<'a> SimpleArgTypeInfo<'a>
    for libsignal_net_chat::api::messages::MultiRecipientSendAuthorization
{
    type ArgType = JByteArray<'a>;
    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        // If we ever have more than two options, we won't be able to just use null for one of them,
        // but for now this is convenient.
        if foreign.is_null() {
            Ok(Self::Story)
        } else {
            let mut elements_guard = <&[u8]>::borrow(env, foreign)?;
            let bytes = <&[u8]>::load_from(&mut elements_guard);
            let token =
                zkgroup::deserialize(bytes).map_err(|_: ZkGroupDeserializationFailure| {
                    BridgeLayerError::BadArgument("bad GroupSendFullToken".into())
                })?;
            Ok(Self::Group(token))
        }
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Box<[u8]> {
    type ArgType = JByteArray<'a>;

    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        let vec = env
            .convert_byte_array(foreign)
            .check_exceptions(env, "Box<[u8]>::convert_from")?;
        Ok(vec.into_boxed_slice())
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Box<[String]> {
    type ArgType = JObjectArray<'a>;

    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        try_scoped(|| {
            let len = env.get_array_length(foreign)?;
            (0..len)
                .map(|i| {
                    let next = AutoLocal::new(
                        JString::from(env.get_object_array_element(foreign, i)?),
                        env,
                    );
                    env.get_string(&next).map(Into::into)
                })
                .try_collect()
        })
        .check_exceptions(env, "Box<[String]>::convert_from")
    }
}

impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
    for &'storage libsignal_account_keys::BackupKey
{
    // This needs to be a `Send`-able value so so that the async task that holds
    // it can be migrated between threads.
    type StoredType = libsignal_account_keys::BackupKey;
    type ArgType = JByteArray<'param>;

    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        use libsignal_account_keys::BACKUP_KEY_LEN;
        let elements = unsafe { env.get_array_elements(foreign, ReleaseMode::NoCopyBack) }
            .check_exceptions(env, "<&[u8; LEN]>::borrow")?;
        if elements.len() != BACKUP_KEY_LEN {
            return Err(BridgeLayerError::IncorrectArrayLength {
                expected: BACKUP_KEY_LEN,
                actual: elements.len(),
            });
        }
        Ok(libsignal_account_keys::BackupKey(
            zerocopy::IntoBytes::as_bytes(&*elements)
                .try_into()
                .expect("checked in construction"),
        ))
    }

    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        stored
    }
}

impl<'a> SimpleArgTypeInfo<'a> for libsignal_net::chat::LanguageList {
    type ArgType = JObjectArray<'a>;

    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        let entries = Box::<[String]>::convert_from(env, foreign)?;
        libsignal_net::chat::LanguageList::parse(&entries)
            .map_err(|_| BridgeLayerError::BadArgument("invalid language in list".to_owned()))
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Option<Box<[u8]>> {
    type ArgType = JByteArray<'a>;

    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        if foreign.is_null() {
            return Ok(None);
        }
        let res = Box::<[u8]>::convert_from(env, foreign)?;
        Ok(Some(res))
    }
}

impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
    for &'storage [u8]
{
    type ArgType = JByteArray<'context>;
    type StoredType = AutoElements<'context, 'context, 'param, jbyte>;
    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        unsafe { env.get_array_elements(foreign, ReleaseMode::NoCopyBack) }
            .check_exceptions(env, "<&[u8]>::borrow")
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> &'storage [u8] {
        // Deref `stored` to the contained slice of [jbyte] ([i8]), then cast that to [u8].
        zerocopy::IntoBytes::as_bytes(&**stored)
    }
}

impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
    for Option<&'storage [u8]>
{
    type ArgType = JByteArray<'context>;
    type StoredType = Option<AutoElements<'context, 'context, 'param, jbyte>>;
    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        if foreign.is_null() {
            Ok(None)
        } else {
            <&'storage [u8]>::borrow(env, foreign).map(Some)
        }
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> Option<&'storage [u8]> {
        stored.as_mut().map(ArgTypeInfo::load_from)
    }
}

impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
    for &'storage mut [u8]
{
    type ArgType = JByteArray<'context>;
    type StoredType = AutoElements<'context, 'context, 'param, jbyte>;
    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        unsafe { env.get_array_elements(foreign, ReleaseMode::CopyBack) }
            .check_exceptions(env, "<&mut [u8]>::borrow")
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> &'storage mut [u8] {
        // Deref `stored` to the contained slice of [jbyte] ([i8]), then cast that to [u8].
        zerocopy::IntoBytes::as_mut_bytes(&mut **stored)
    }
}

impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
    for crate::support::ServiceIdSequence<'storage>
{
    type ArgType = JByteArray<'context>;
    type StoredType = AutoElements<'context, 'context, 'param, jbyte>;

    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        <&'storage [u8]>::borrow(env, foreign)
    }

    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        let buffer = <&'storage [u8]>::load_from(stored);
        Self::parse(buffer)
    }
}

/// Represents a sequence of byte arrays as `ByteBuffer[]`.
///
/// We use a ByteBuffer instead of a `byte[]` because ByteBuffer can expose its storage without
/// having to "release" it afterwards; as long as the object is live, the storage is valid. By
/// contrast, `byte[][]` can't have all of its elements borrowed at once, because the `jni` crate is
/// strict about the lifetimes for that.
impl<'a> SimpleArgTypeInfo<'a> for Vec<&'a [u8]> {
    type ArgType = JObjectArray<'a>;

    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        #[derive(derive_more::From)]
        enum JniErrorOrNull {
            Jni(#[from] jni::errors::Error),
            Null(&'static str),
        }
        try_scoped(|| {
            let len = env.get_array_length(foreign)?;
            (0..len)
                .map(|i| {
                    let next = AutoLocal::new(
                        JByteBuffer::from(env.get_object_array_element(foreign, i)?),
                        env,
                    );
                    let len = env.get_direct_buffer_capacity(&next)?;
                    let addr = env.get_direct_buffer_address(&next)?;
                    if !addr.is_null() {
                        Ok(unsafe { std::slice::from_raw_parts(addr, len) })
                    } else {
                        if len != 0 {
                            return Err(JniErrorOrNull::Null("ByteBuffer direct address"));
                        }
                        Ok([].as_slice())
                    }
                })
                .collect()
        })
        .or_else(|e| match e {
            JniErrorOrNull::Jni(jni_error) => {
                Err(jni_error).check_exceptions(env, "Vec<&[u8]>::convert_from")
            }
            JniErrorOrNull::Null(message) => Err(BridgeLayerError::NullPointer(Some(message))),
        })
    }
}

macro_rules! bridge_trait {
    ($name:ident) => {
        paste! {
            impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
                for &'storage mut dyn $name
            {
                type ArgType = JObject<'context>;
                type StoredType = [<Jni $name>]<'storage>;
                fn borrow(
                    env: &mut JNIEnv<'context>,
                    store: &'param Self::ArgType,
                ) -> Result<Self::StoredType, BridgeLayerError> {
                    Self::StoredType::new(env, store)
                }
                fn load_from(
                    stored: &'storage mut Self::StoredType,
                ) -> Self {
                    stored
                }
            }

            impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
                for Option<&'storage dyn $name>
            {
                type ArgType = JObject<'context>;
                type StoredType = Option<[<Jni $name>]<'storage>>;
                fn borrow(
                    env: &mut JNIEnv<'context>,
                    store: &'param Self::ArgType,
                ) -> Result<Self::StoredType, BridgeLayerError> {
                    if store.is_null() {
                        Ok(None)
                    } else {
                        Ok(Some([<Jni $name>]::new(env, store)?))
                    }
                }
                fn load_from(
                    stored: &'storage mut Self::StoredType,
                ) -> Self {
                    stored.as_ref().map(|x| x as &'storage dyn $name)
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

impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
    for Option<Box<dyn ChatListener>>
{
    type ArgType = JObject<'context>;
    type StoredType = Option<JniBridgeChatListener>;
    fn borrow(
        env: &mut JNIEnv<'context>,
        store: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        if store.is_null() {
            Ok(None)
        } else {
            Ok(Some(JniBridgeChatListener::new(env, store)?))
        }
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        stored.take().map(|j| j.into_listener())
    }
}

impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
    for Box<dyn ChatListener>
{
    type ArgType = JObject<'context>;
    type StoredType = Option<JniBridgeChatListener>;
    fn borrow(
        env: &mut JNIEnv<'context>,
        store: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        if store.is_null() {
            return Err(BridgeLayerError::NullPointer(Some("BridgeChatListener")));
        }
        Ok(Some(JniBridgeChatListener::new(env, store)?))
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        stored.take().expect("not previously taken").into_listener()
    }
}

impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
    for Box<dyn ConnectChatBridge>
{
    type ArgType = JObject<'context>;
    type StoredType = Option<JniConnectChatBridge>;
    fn borrow(
        env: &mut JNIEnv<'context>,
        store: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        JniConnectChatBridge::new(env, store).map(Some)
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        Box::new(stored.take().expect("not previously taken"))
    }
}

/// A translation from a Java interface where the implementing class wraps the Rust handle.
impl<'a> SimpleArgTypeInfo<'a> for CiphertextMessageRef<'a> {
    type ArgType = JavaCiphertextMessage<'a>;
    fn convert_from(env: &mut JNIEnv, foreign: &Self::ArgType) -> Result<Self, BridgeLayerError> {
        if foreign.is_null() {
            return Err(BridgeLayerError::NullPointer(Some("CipherTextMessageRef")));
        }

        None.or_else(|| {
            map_native_handle_if_matching_jobject(
                env,
                foreign,
                ClassName("org.signal.libsignal.protocol.message.SignalMessage"),
                Self::SignalMessage,
            )
            .transpose()
        })
        .or_else(|| {
            map_native_handle_if_matching_jobject(
                env,
                foreign,
                ClassName("org.signal.libsignal.protocol.message.PreKeySignalMessage"),
                Self::PreKeySignalMessage,
            )
            .transpose()
        })
        .or_else(|| {
            map_native_handle_if_matching_jobject(
                env,
                foreign,
                ClassName("org.signal.libsignal.protocol.message.SenderKeyMessage"),
                Self::SenderKeyMessage,
            )
            .transpose()
        })
        .or_else(|| {
            map_native_handle_if_matching_jobject(
                env,
                foreign,
                ClassName("org.signal.libsignal.protocol.message.PlaintextContent"),
                Self::PlaintextContent,
            )
            .transpose()
        })
        .unwrap_or(Err(BridgeLayerError::BadArgument(
            "unknown CiphertextMessage subclass".to_string(),
        )))
    }
}

#[cfg(not(target_os = "android"))]
impl<'a> ResultTypeInfo<'a> for crate::cds2::Cds2Metrics {
    type ResultType = JObject<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let jobj = new_instance(env, ClassName("java.util.HashMap"), jni_args!(() -> void))?;
        let jmap = JMap::from_env(env, &jobj).check_exceptions(env, "Cds2Metrics::convert_into")?;

        const LONG_CLASS_NAME: ClassName<'_> = ClassName("java.lang.Long");
        let long_class = find_class(env, LONG_CLASS_NAME).expect_no_exceptions()?;
        for (k, v) in self.0 {
            let k = k.convert_into(env)?;
            let v = new_object(env, &long_class, jni_args!((v => long) -> void))
                .check_exceptions(env, LONG_CLASS_NAME.0)?;
            jmap.put(env, &k, &v).check_exceptions(env, "put")?;
        }
        Ok(jobj)
    }
}

impl ResultTypeInfo<'_> for bool {
    type ResultType = jboolean;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        Ok(if self { JNI_TRUE } else { JNI_FALSE })
    }
}

/// Supports all valid byte values `0..=255`.
impl ResultTypeInfo<'_> for u8 {
    type ResultType = jint;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        Ok(self as jint)
    }
}

/// Supports all valid byte values `0..=65536`.
impl ResultTypeInfo<'_> for u16 {
    type ResultType = jint;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        Ok(self as jint)
    }
}

/// Reinterprets the bits of the `u32` as a Java `int`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `u32`.
impl ResultTypeInfo<'_> for u32 {
    type ResultType = jint;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        // Note that we don't check bounds here.
        Ok(self as jint)
    }
}

/// Reinterprets the bits of the `u32` as a Java `int`. Returns `-1` for `None`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `Option<u32>`.
impl ResultTypeInfo<'_> for Option<u32> {
    type ResultType = jint;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        // Note that we don't check bounds here.
        Ok(self.unwrap_or(u32::MAX) as jint)
    }
}

/// Reinterprets the bits of the `u64` as a Java `long`.
impl ResultTypeInfo<'_> for u64 {
    type ResultType = jlong;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        // Note that we don't check bounds here.
        Ok(self as jlong)
    }
}

/// Reinterprets the bits of the timestamp's `u64` as a Java `long`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `Timestamp`.
impl ResultTypeInfo<'_> for crate::protocol::Timestamp {
    type ResultType = jlong;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        // Note that we don't check bounds here.
        Ok(self.epoch_millis() as jlong)
    }
}

/// Reinterprets the bits of the `u64` as a Java `long`. Returns `-1` for `None`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `Option<u64>`.
impl ResultTypeInfo<'_> for Option<u64> {
    type ResultType = jlong;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        // Note that we don't check bounds here.
        Ok(self.unwrap_or(u64::MAX) as jlong)
    }
}

/// Reinterprets the bits of the timestamp's `u64` as a Java `long`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `Timestamp`.
impl ResultTypeInfo<'_> for crate::zkgroup::Timestamp {
    type ResultType = jlong;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        // Note that we don't check bounds here.
        Ok(self.epoch_seconds() as jlong)
    }
}

impl<'a> ResultTypeInfo<'a> for String {
    type ResultType = JString<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        self.deref().convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for Option<String> {
    type ResultType = JString<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        self.as_deref().convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for &str {
    type ResultType = JString<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        env.new_string(self)
            .check_exceptions(env, "<&str>::convert_into")
    }
}

impl<'a> ResultTypeInfo<'a> for Option<&str> {
    type ResultType = JString<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        match self {
            Some(s) => s.convert_into(env),
            None => Ok(JString::default()),
        }
    }
}

impl<'a> ResultTypeInfo<'a> for &[u8] {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        env.byte_array_from_slice(self)
            .check_exceptions(env, "<&[u8]>::convert_into")
    }
}

impl<'a> ResultTypeInfo<'a> for Option<&[u8]> {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        match self {
            Some(s) => s.convert_into(env),
            None => Ok(JByteArray::default()),
        }
    }
}

impl<'a> ResultTypeInfo<'a> for Vec<u8> {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        self.deref().convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for Option<Vec<u8>> {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        self.as_deref().convert_into(env)
    }
}

impl<'storage, 'param: 'storage, 'context: 'param, const LEN: usize>
    ArgTypeInfo<'storage, 'param, 'context> for &'storage [u8; LEN]
{
    type ArgType = JByteArray<'context>;
    type StoredType = AutoElements<'context, 'context, 'param, jbyte>;
    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        let elements = unsafe { env.get_array_elements(foreign, ReleaseMode::NoCopyBack) }
            .check_exceptions(env, "<&[u8; LEN]>::borrow")?;
        if elements.len() != LEN {
            return Err(BridgeLayerError::IncorrectArrayLength {
                expected: LEN,
                actual: elements.len(),
            });
        }
        Ok(elements)
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> &'storage [u8; LEN] {
        // Deref `stored` to the contained slice of [jbyte] ([i8]), then cast that to [u8],
        // then convert the fixed-sized array [u8; LEN]
        zerocopy::IntoBytes::as_bytes(&**stored)
            .try_into()
            .expect("checked in construction")
    }
}

impl<'storage, 'param: 'storage, 'context: 'param, const LEN: usize>
    ArgTypeInfo<'storage, 'param, 'context> for Option<&'storage [u8; LEN]>
{
    type ArgType = JByteArray<'context>;
    type StoredType = Option<AutoElements<'context, 'context, 'param, jbyte>>;
    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        if foreign.is_null() {
            Ok(None)
        } else {
            <&'storage [u8; LEN]>::borrow(env, foreign).map(Some)
        }
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        stored.as_mut().map(ArgTypeInfo::load_from)
    }
}

impl<'a, const LEN: usize> ResultTypeInfo<'a> for [u8; LEN] {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        self.as_ref().convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for uuid::Uuid {
    type ResultType = JObject<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let uuid_bytes: [u8; 16] = *self.as_bytes();
        let (msb, lsb) = uuid_bytes.split_at(8);
        new_instance(
            env,
            ClassName("java.util.UUID"),
            jni_args!((
                jlong::from_be_bytes(msb.try_into().expect("correct length")) => long,
                jlong::from_be_bytes(lsb.try_into().expect("correct length")) => long,
            ) -> void),
        )
    }
}

impl<'a> ResultTypeInfo<'a> for Option<uuid::Uuid> {
    type ResultType = JObject<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        self.map(|uuid| uuid.convert_into(env))
            .unwrap_or(Ok(JObject::null()))
    }
}

/// A translation to a Java interface where the implementing class wraps the Rust handle.
impl<'a> ResultTypeInfo<'a> for CiphertextMessage {
    type ResultType = JavaCiphertextMessage<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        match self {
            CiphertextMessage::SignalMessage(m) => {
                let message = m.convert_into(env)?;
                jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.message.SignalMessage"),
                    message,
                )
            }
            CiphertextMessage::PreKeySignalMessage(m) => {
                let message = m.convert_into(env)?;
                jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.message.PreKeySignalMessage"),
                    message,
                )
            }
            CiphertextMessage::SenderKeyMessage(m) => {
                let message = m.convert_into(env)?;
                jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.message.SenderKeyMessage"),
                    message,
                )
            }
            CiphertextMessage::PlaintextContent(m) => {
                let message = m.convert_into(env)?;
                jobject_from_native_handle(
                    env,
                    ClassName("org.signal.libsignal.protocol.message.PlaintextContent"),
                    message,
                )
            }
        }
    }
}

impl<'a> ResultTypeInfo<'a> for Option<JObject<'a>> {
    type ResultType = JObject<'a>;
    fn convert_into(self, _env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        Ok(self.unwrap_or_default())
    }
}

/// The offset, in bits, to store an 8-bit type tag in a pointer.
///
/// The top 8 bits of (64-bit) pointers get used for OS-based pointer integrity checks on some
/// devices. The bottom 48 are the extent of a "normal" address space on both x86_64 and aarch64.
/// That leaves 8 bits in the middle for us to store our own type tag. As long as we don't deploy to
/// a server with a memory space bigger than a terabyte, we should be good.
const TYPE_TAG_POINTER_OFFSET: usize = 48;

/// A marker for Rust objects exposed as opaque handles (pointers converted to `jlong`).
///
/// When we do this, we hand the lifetime over to the app. Since we don't know how long the object
/// will be kept alive, it can't (safely) have references to anything with a non-static lifetime.
pub trait BridgeHandle: Sized + 'static {
    const TYPE_TAG: u8;

    /// Casts the given handle as a `NonNull<T>`.
    ///
    /// Does some rudimentary checks that the handle probably does represent a real object, but
    /// cannot guarantee it.
    unsafe fn native_handle_cast(handle: ObjectHandle) -> Result<NonNull<Self>, BridgeLayerError> {
        if handle == 0 {
            return Err(BridgeLayerError::NullPointer(None));
        }

        let addr = if cfg!(feature = "jni-type-tagging") {
            if ((handle >> TYPE_TAG_POINTER_OFFSET) & 0xFF) as u8 != Self::TYPE_TAG {
                return Err(BridgeLayerError::BadJniParameter(
                    std::any::type_name::<Self>(),
                ));
            }
            handle & !(0xFF << TYPE_TAG_POINTER_OFFSET)
        } else {
            handle
        };

        // We could add additional validity checks here (alignment, "not a very low address", etc)
        // but the type tag is already a good check that we haven't been handed garbage.

        // SAFETY: For this to fail, we would have needed to be passed a handle that has a correct
        // type tag but no actual address. However, NonNull does require a *mut* pointer, and with
        // shared access that may or may not be safe. It's up to call sites to get this right.
        Ok(unsafe { NonNull::new_unchecked(addr as *mut Self) })
    }

    /// Converts from a raw pointer decoded by `native_handle_cast` into an owned reference.
    ///
    /// SAFETY: `raw` must have actually come from `encode_as_handle` followed by
    /// `native_handle_cast`.
    unsafe fn from_raw_without_consuming(raw: NonNull<Self>) -> Arc<Self> {
        let ptr = raw.as_ptr().cast_const();
        unsafe {
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
    }

    /// Converts `boxed_value` to a raw pointer and then encodes it as a handle.
    fn encode_as_handle(boxed_value: Arc<Self>) -> ObjectHandle {
        let mut addr = Arc::into_raw(boxed_value) as ObjectHandle;
        if cfg!(feature = "jni-type-tagging") {
            assert!(
                (addr >> TYPE_TAG_POINTER_OFFSET) & 0xFF == 0,
                "type-tag bits already in use"
            );
            addr |= (Self::TYPE_TAG as ObjectHandle) << TYPE_TAG_POINTER_OFFSET;
        }
        addr
    }
}

impl<'storage, 'param: 'storage, 'context: 'param, T: BridgeHandle>
    ArgTypeInfo<'storage, 'param, 'context> for Option<&'storage T>
where
    &'storage T:
        ArgTypeInfo<'storage, 'param, 'context, ArgType = ObjectHandle, StoredType = Arc<T>>,
{
    type ArgType = ObjectHandle;
    type StoredType = Option<Arc<T>>;

    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        if *foreign == 0 {
            Ok(None)
        } else {
            <&T>::borrow(env, foreign).map(Some)
        }
    }

    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        stored.as_deref()
    }
}

impl<'storage, 'param: 'storage, 'context: 'param, T> ArgTypeInfo<'storage, 'param, 'context>
    for &'storage [&'storage T]
where
    &'storage T:
        ArgTypeInfo<'storage, 'param, 'context, ArgType = ObjectHandle, StoredType = Arc<T>>,
{
    type ArgType = JLongArray<'context>;
    // Stored in this order so the references get dropped before the owners.
    type StoredType = (Vec<&'storage T>, Vec<Arc<T>>);
    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        let array = unsafe { env.get_array_elements(foreign, ReleaseMode::NoCopyBack) }
            .check_exceptions(env, "<&[&T]>::borrow")?;
        let mut result_arcs = Vec::with_capacity(array.len());
        let mut result_refs = Vec::with_capacity(array.len());
        for raw_handle in array.iter() {
            // SAFETY: ArgTypeInfo for BridgeHandles doesn't actually care about the lifetime of the
            // parameter used to pass the handle address around.
            let arc = <&T>::borrow(env, unsafe { extend_lifetime(raw_handle) })?;
            // SAFETY: This address is kept alive as long as any of the Arcs are kept alive, which
            // they will be.
            result_refs.push(unsafe { extend_lifetime(&*arc) });
            result_arcs.push(arc);
        }
        Ok((result_refs, result_arcs))
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> &'storage [&'storage T] {
        &stored.0
    }
}

impl<T: BridgeHandle> ResultTypeInfo<'_> for T {
    type ResultType = ObjectHandle;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        Ok(T::encode_as_handle(Arc::new(self)))
    }
}

impl<T: BridgeHandle> ResultTypeInfo<'_> for Option<T> {
    type ResultType = ObjectHandle;
    fn convert_into(self, env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        match self {
            Some(obj) => obj.convert_into(env),
            None => Ok(0),
        }
    }
}

impl<'a, A: ResultTypeInfo<'a>, B: ResultTypeInfo<'a>> ResultTypeInfo<'a> for (A, B) {
    type ResultType = JavaPair<'a, A::ResultType, B::ResultType>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let a = self.0.convert_into(env)?;
        let a = box_primitive_if_needed(env, a.into())?;
        let b = self.1.convert_into(env)?;
        let b = box_primitive_if_needed(env, b.into())?;
        Ok(new_instance(
            env,
            ClassName("kotlin.Pair"),
            jni_args!((a => java.lang.Object, b => java.lang.Object) -> void),
        )?
        .into())
    }
}

impl<'a, A: ResultTypeInfo<'a>, B: ResultTypeInfo<'a>> ResultTypeInfo<'a> for Option<(A, B)> {
    type ResultType = JavaPair<'a, A::ResultType, B::ResultType>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let Some(value) = self else {
            return Ok(JObject::null().into());
        };
        value.convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for ServiceId {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        env.byte_array_from_slice(&self.service_id_fixed_width_binary())
            .check_exceptions(env, "ServiceId::convert_into")
    }
}

impl<'a> ResultTypeInfo<'a> for Aci {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        ServiceId::from(self).convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for Pni {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        ServiceId::from(self).convert_into(env)
    }
}

macro_rules! impl_result_type_info_for_option {
    ($typ:ty) => {
        impl<'a> ResultTypeInfo<'a> for Option<$typ> {
            type ResultType = <$typ as ResultTypeInfo<'a>>::ResultType;
            fn convert_into(
                self,
                env: &mut JNIEnv<'a>,
            ) -> Result<Self::ResultType, BridgeLayerError> {
                match self {
                    None => Ok(Self::ResultType::default()),
                    Some(inner) => inner.convert_into(env),
                }
            }
        }
    };
}

impl_result_type_info_for_option!(Aci);
impl_result_type_info_for_option!(Pni);

impl<'a, T> SimpleArgTypeInfo<'a> for Serialized<T>
where
    T: FixedLengthBincodeSerializable
        + for<'x> serde::Deserialize<'x>
        + partial_default::PartialDefault,
{
    type ArgType = JByteArray<'a>;

    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        // Ideally we would deserialize directly to &T::Array. However, trying to require that
        // T::Array: ArgTypeInfo is pretty much impossible with the lifetimes SimpleArgTypeInfo
        // provides; we'd have to drop back to ArgTypeInfo for Serialized<T>.
        let mut borrowed_array = <&[u8]>::borrow(env, foreign)?;
        let bytes = <&[u8]>::load_from(&mut borrowed_array);
        assert_eq!(
            bytes.len(),
            T::Array::LEN,
            "{} should have been validated on creation",
            std::any::type_name::<T>()
        );
        let result: T = zkgroup::deserialize(bytes).unwrap_or_else(|_| {
            panic!(
                "{} should have been validated on creation",
                std::any::type_name::<T>()
            )
        });
        Ok(Serialized::from(result))
    }
}

impl<'a, T, P> SimpleArgTypeInfo<'a> for AsType<T, P>
where
    P: SimpleArgTypeInfo<'a> + TryInto<T, Error: Display>,
{
    type ArgType = P::ArgType;

    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        let p = P::convert_from(env, foreign)?;
        p.try_into()
            .map_err(|e| {
                BridgeLayerError::BadArgument(format!(
                    "invalid {}: {e}",
                    std::any::type_name::<T>()
                ))
            })
            .map(AsType::from)
    }
}

impl<'a> SimpleArgTypeInfo<'a> for ServiceId {
    type ArgType = JByteArray<'a>;
    fn convert_from(env: &mut JNIEnv, foreign: &Self::ArgType) -> Result<Self, BridgeLayerError> {
        env.convert_byte_array(foreign)
            .ok()
            .and_then(|vec| vec.try_into().ok())
            .as_ref()
            .and_then(Self::parse_from_service_id_fixed_width_binary)
            .ok_or_else(|| {
                BridgeLayerError::BadArgument("invalid Service-Id-FixedWidthBinary".to_string())
            })
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Aci {
    type ArgType = JByteArray<'a>;
    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        ServiceId::convert_from(env, foreign)?
            .try_into()
            .map_err(|_| BridgeLayerError::BadArgument("not an ACI".to_string()))
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Pni {
    type ArgType = JByteArray<'a>;
    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        ServiceId::convert_from(env, foreign)?
            .try_into()
            .map_err(|_| BridgeLayerError::BadArgument("not a PNI".to_string()))
    }
}

impl<'a> SimpleArgTypeInfo<'a> for bool {
    type ArgType = jboolean;
    fn convert_from(_: &mut JNIEnv<'a>, foreign: &Self::ArgType) -> Result<Self, BridgeLayerError> {
        Ok(*foreign != 0)
    }
}

impl<'a> SimpleArgTypeInfo<'a> for libsignal_net_chat::api::registration::CreateSession {
    type ArgType = JObject<'a>;

    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            foreign,
            ClassName("org.signal.libsignal.net.RegistrationService$CreateSession"),
        )?;

        let fields = try_scoped(|| {
            let number = AutoLocal::new(
                env.get_field(foreign, "number", jni_signature!(java.lang.String))?
                    .l()?,
                env,
            );
            let push_token = AutoLocal::new(
                env.get_field(foreign, "fcmPushToken", jni_signature!(java.lang.String))?
                    .l()?,
                env,
            );
            let mcc = AutoLocal::new(
                env.get_field(foreign, "mcc", jni_signature!(java.lang.String))?
                    .l()?,
                env,
            );
            let mnc = AutoLocal::new(
                env.get_field(foreign, "mnc", jni_signature!(java.lang.String))?
                    .l()?,
                env,
            );
            let number = env.get_string((&*number).into())?.into();

            let mut from_nullable_string = |obj: AutoLocal<'_, JObject<'_>>| {
                (!obj.is_null())
                    .then(|| env.get_string((&*obj).into()).map(Into::into))
                    .transpose()
            };
            Ok((
                number,
                push_token,
                from_nullable_string(mcc)?,
                from_nullable_string(mnc)?,
            ))
        })
        .check_exceptions(env, "CreateSession::convert_from")?;
        let (number, push_token, mcc, mnc) = fields;

        let push_token = SimpleArgTypeInfo::convert_from(env, (&*push_token).into())?;

        Ok(Self {
            number,
            push_token,
            mcc,
            mnc,
        })
    }
}

impl<'a> SimpleArgTypeInfo<'a> for RegistrationPushToken {
    type ArgType = JString<'a>;
    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        // Java push tokens are always FCM.
        Ok(Self::Fcm {
            push_token: String::convert_from(env, foreign)?,
        })
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Option<RegistrationPushToken> {
    type ArgType = JString<'a>;
    fn convert_from(
        env: &mut JNIEnv<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        if foreign.is_null() {
            Ok(None)
        } else {
            RegistrationPushToken::convert_from(env, foreign).map(Some)
        }
    }
}

impl<'a> SimpleArgTypeInfo<'a> for crate::net::registration::SignedPublicPreKey {
    type ArgType = JObject<'a>;
    fn convert_from(env: &mut JNIEnv<'a>, obj: &Self::ArgType) -> Result<Self, BridgeLayerError> {
        check_jobject_type(
            env,
            obj,
            ClassName("org.signal.libsignal.protocol.SignedPublicPreKey"),
        )?;

        let values = try_scoped(|| {
            let key_id = env.get_field(obj, "id", jni_signature!(int))?.i()?;

            let public_key = env
                .get_field(
                    obj,
                    "publicKey",
                    jni_signature!(org.signal.libsignal.protocol.SerializablePublicKey),
                )?
                .l()?;

            let signature = env
                .get_field(obj, "signature", jni_signature!([byte]))?
                .l()?;

            Ok((key_id, public_key, signature.into()))
        })
        .check_exceptions(env, "SignedPreKeyBody::convert_from")?;

        let (key_id, public_key, signature) = values;

        let key_id = key_id.try_into().map_err(|_| {
            BridgeLayerError::IntegerOverflow("id field is out of bounds".to_owned())
        })?;

        let public_key = {
            None.or_else(|| {
                map_native_handle_if_matching_jobject(
                    env,
                    &public_key,
                    ClassName("org.signal.libsignal.protocol.ecc.ECPublicKey"),
                    PublicKey::serialize,
                )
                .transpose()
            })
            .or_else(|| {
                map_native_handle_if_matching_jobject(
                    env,
                    &public_key,
                    ClassName("org.signal.libsignal.protocol.kem.KEMPublicKey"),
                    kem::PublicKey::serialize,
                )
                .transpose()
            })
            .unwrap_or_else(|| {
                Err(BridgeLayerError::BadArgument(
                    "publicKey type is not supported".to_owned(),
                ))
            })?
        };
        let signature = <Box<[u8]>>::convert_from(env, &signature)?;

        Ok(Self {
            key_id,
            public_key,
            signature,
        })
    }
}

/// For testing purposes
impl<'a> SimpleArgTypeInfo<'a> for ::jni::JavaVM {
    type ArgType = JObject<'a>;

    fn convert_from(
        env: &mut jni::JNIEnv<'a>,
        _placeholder_parameter: &Self::ArgType,
    ) -> Result<Self, BridgeLayerError> {
        env.get_java_vm()
            .check_exceptions(env, "JavaVM::convert_from")
    }
}

impl<'a, T> ResultTypeInfo<'a> for Serialized<T>
where
    T: FixedLengthBincodeSerializable + serde::Serialize,
{
    type ResultType = JByteArray<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let result = zkgroup::serialize(self.deref());
        result.convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for libsignal_net::cdsi::LookupResponse {
    type ResultType = JObject<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let Self {
            records,
            debug_permits_used,
        } = self;

        let entries_hashmap =
            new_instance(env, ClassName("java.util.HashMap"), jni_args!(() -> void))?;
        let entries_jmap = JMap::from_env(env, &entries_hashmap)
            .check_exceptions(env, "LookupResponse::convert_into")?;

        const ENTRY_CLASS: ClassName =
            ClassName("org.signal.libsignal.net.CdsiLookupResponse$Entry");
        let entry_class =
            find_class(env, ENTRY_CLASS).check_exceptions(env, "LookupResponse::convert_into")?;

        for entry in records {
            let LookupResponseEntry { aci, e164, pni } = entry;
            let aci = AutoLocal::new(
                aci.map(|aci| aci.convert_into(env))
                    .transpose()?
                    .unwrap_or_default(),
                env,
            );
            let pni = AutoLocal::new(
                pni.map(|pni| pni.convert_into(env))
                    .transpose()?
                    .unwrap_or_default(),
                env,
            );
            let e164 = AutoLocal::new(
                JObject::from(
                    env.new_string(e164.to_string())
                        .check_exceptions(env, "LookupResponse::convert_into")?,
                ),
                env,
            );

            let entry = AutoLocal::new(
                new_object(
                    env,
                    &entry_class,
                    jni_args!( (aci => [byte], pni => [byte]) -> void),
                )
                .check_exceptions(env, "LookupResponse::convert_into")?,
                env,
            );

            entries_jmap
                .put(env, &e164, &entry)
                .check_exceptions(env, "put")?;
        }

        new_instance(
            env,
            ClassName("org.signal.libsignal.net.CdsiLookupResponse"),
            jni_args!((entries_hashmap => java.util.Map, debug_permits_used => int) -> void),
        )
    }
}

impl<'a> ResultTypeInfo<'a> for libsignal_net::chat::Response {
    type ResultType = JObject<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let Self {
            status,
            message,
            body,
            headers,
        } = self;

        // body
        let body = body.as_deref().unwrap_or(&[]);
        let body_arr = env
            .byte_array_from_slice(body)
            .check_exceptions(env, "Response::convert_into")?;

        // message
        let message_local = env
            .new_string(message.as_deref().unwrap_or(""))
            .check_exceptions(env, "Response::convert_into")?;

        // headers
        let headers_map = new_instance(env, ClassName("java.util.HashMap"), jni_args!(() -> void))?;
        let headers_jmap =
            JMap::from_env(env, &headers_map).check_exceptions(env, "Response::convert_into")?;
        for (name, value) in headers.iter() {
            let name_str = env
                .new_string(name.as_str())
                .check_exceptions(env, "Response::convert_into")?;
            let value_str = env
                .new_string(value.to_str().expect("valid header value"))
                .check_exceptions(env, "Response::convert_into")?;
            headers_jmap
                .put(env, &name_str, &value_str)
                .check_exceptions(env, "put")?;
        }

        new_instance(
            env,
            ClassName("org.signal.libsignal.net.ChatConnection$Response"),
            jni_args!((
                status.as_u16().into() => int,
                message_local => java.lang.String,
                headers_jmap => java.util.Map,
                body_arr => [byte]
            ) -> void),
        )
    }
}

impl<'a> ResultTypeInfo<'a> for libsignal_net_chat::api::ChallengeOption {
    type ResultType = JObject<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        try_scoped(|| {
            let class = find_class(env, ClassName("org.signal.libsignal.net.ChallengeOption"))?;

            let field_name = match self {
                Self::PushChallenge => "PUSH_CHALLENGE",
                Self::Captcha => "CAPTCHA",
            };
            env.get_static_field(
                class,
                field_name,
                jni_signature!(org.signal.libsignal.net.ChallengeOption),
            )?
            .l()
        })
        .check_exceptions(env, "ChallengeOption::convert_into")
    }
}

impl<'a> ResultTypeInfo<'a> for &'_ [libsignal_net_chat::api::ChallengeOption] {
    type ResultType = JObjectArray<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let element_class = find_class(env, ClassName("org.signal.libsignal.net.ChallengeOption"))
            .check_exceptions(env, "ChallengeOption::convert_into")?;
        make_object_array(env, element_class, self.iter().copied())
    }
}

impl<'a> ResultTypeInfo<'a> for Box<[libsignal_net_chat::api::ChallengeOption]> {
    type ResultType = JObjectArray<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        (&*self).convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for Vec<ServiceId> {
    type ResultType = JObjectArray<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let element_class = find_primitive_array_class(env, jni_signature!([byte]))
            .check_exceptions(env, "Vec<ServiceId>::convert_into")?;
        make_object_array(env, element_class, self)
    }
}

impl<'a> ResultTypeInfo<'a> for &'_ libsignal_net_chat::api::messages::MismatchedDeviceError {
    type ResultType = JObject<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let libsignal_net_chat::api::messages::MismatchedDeviceError {
            account,
            missing_devices,
            extra_devices,
            stale_devices,
        } = self;

        fn convert_device_list<'a>(
            env: &mut JNIEnv<'a>,
            input: &[DeviceId],
        ) -> Result<JIntArray<'a>, BridgeLayerError> {
            let len = input.len().try_into().map_err(|_| {
                // This is not *really* the correct error, it will produce an
                // IllegalArgumentException even though we're making a result. But also we shouldn't
                // in practice try to return arrays of 2 billion IDs.
                BridgeLayerError::IntegerOverflow(format!("{}_usize to i32", input.len()))
            })?;
            let array = env
                .new_int_array(len)
                .check_exceptions(env, "MismatchedDeviceError::convert_into")?;
            let mut elems = unsafe { env.get_array_elements(&array, ReleaseMode::CopyBack) }
                .check_exceptions(env, "MismatchedDeviceError::convert_into")?;

            for (elem, id) in elems.iter_mut().zip(input) {
                *elem = u8::from(*id).into();
            }

            // `elems` borrows from `array`, so we have to drop it before we return.
            drop(elems);
            Ok(array)
        }

        let account_bytes = account.convert_into(env)?;
        let missing_devices = convert_device_list(env, missing_devices)?;
        let extra_devices = convert_device_list(env, extra_devices)?;
        let stale_devices = convert_device_list(env, stale_devices)?;

        new_instance(
            env,
            ClassName("org.signal.libsignal.net.MismatchedDeviceException$Entry"),
            jni_args!((
                account_bytes => [byte],
                missing_devices => [int],
                extra_devices => [int],
                stale_devices => [int]
            ) -> void),
        )
    }
}

impl<'a> ResultTypeInfo<'a> for &'_ [libsignal_net_chat::api::messages::MismatchedDeviceError] {
    type ResultType = JObjectArray<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let element_class = find_class(
            env,
            ClassName("org.signal.libsignal.net.MismatchedDeviceException$Entry"),
        )
        .check_exceptions(env, "MismatchedDeviceError::convert_into")?;
        make_object_array(env, element_class, self)
    }
}

impl<'a> ResultTypeInfo<'a> for libsignal_net_chat::api::registration::RegisterResponseBadge {
    type ResultType = JObject<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        const CLASS_NAME: ClassName<'_> =
            ClassName("org.signal.libsignal.net.RegisterAccountResponse$BadgeEntitlement");
        let class = find_class(env, CLASS_NAME)
            .check_exceptions(env, "RegisterResponseBadge::convert_into")?;

        let Self {
            id,
            visible,
            expiration,
        } = self;

        let expiration_seconds = expiration.as_secs().convert_into(env)?;
        try_scoped(|| {
            let id = env.new_string(id)?;

            new_object(
                env,
                class,
                jni_args!((
                    id => java.lang.String,
                    visible => boolean,
                    expiration_seconds => long
                ) -> void),
            )
        })
        .check_exceptions(env, "RegisterResponseBadge::convert_into")
    }
}

impl<'a> ResultTypeInfo<'a>
    for Box<[libsignal_net_chat::api::registration::RegisterResponseBadge]>
{
    type ResultType = JObjectArray<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let element_class = find_class(
            env,
            ClassName("org.signal.libsignal.net.RegisterAccountResponse$BadgeEntitlement"),
        )
        .check_exceptions(env, "RegisterResponseBadge::convert_into")?;
        make_object_array(env, element_class, self)
    }
}

impl<'a> ResultTypeInfo<'a>
    for libsignal_net_chat::api::registration::CheckSvr2CredentialsResponse
{
    type ResultType = JObject<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        const RESULT_CLASS_NAME: &str =
            "org.signal.libsignal.net.RegistrationService$Svr2CredentialsResult";
        let jobj = new_instance(env, ClassName("java.util.HashMap"), jni_args!(() -> void))?;
        let (jmap, response_class) = try_scoped(|| {
            Ok((
                JMap::from_env(env, &jobj)?,
                find_class(env, ClassName(RESULT_CLASS_NAME))?,
            ))
        })
        .check_exceptions(env, "CheckSvr2CredentialsResponse::convert_into")?;

        let Self { matches } = self;
        for (k, v) in matches {
            let k = k.convert_into(env)?;
            let name = match v {
                libsignal_net_chat::api::registration::Svr2CredentialsResult::Match => "MATCH",
                libsignal_net_chat::api::registration::Svr2CredentialsResult::NoMatch => "NO_MATCH",
                libsignal_net_chat::api::registration::Svr2CredentialsResult::Invalid => "INVALID",
            };
            let v = env.get_static_field(&response_class, name, jni_signature!(org.signal.libsignal.net.RegistrationService::Svr2CredentialsResult))
            .and_then(|v| v.l())
                .check_exceptions(env, "Svr2CredentialsResult")?;
            jmap.put(env, &k, &v).check_exceptions(env, "put")?;
        }
        Ok(jobj)
    }
}

/// Converts each element of `it` to a Java object, storing the result in an array.
fn make_object_array<'a, It>(
    env: &mut JNIEnv<'a>,
    element_type: JClass<'a>,
    it: It,
) -> Result<JObjectArray<'a>, BridgeLayerError>
where
    It: IntoIterator<
            Item: ResultTypeInfo<'a, ResultType: Into<JObject<'a>>>,
            IntoIter: ExactSizeIterator,
        >,
{
    let it = it.into_iter();
    let len = it.len();
    let array = env
        .new_object_array(
            len.try_into().map_err(|_| {
                // This is not *really* the correct error, it will produce an
                // IllegalArgumentException even though we're making a result. But also we shouldn't
                // in practice try to return arrays of 2 billion objects.
                BridgeLayerError::IntegerOverflow(format!("{len}_usize to i32"))
            })?,
            element_type,
            JavaObject::null(),
        )
        .check_exceptions(env, "make_object_array")?;

    for (index, next) in it.enumerate() {
        let value = AutoLocal::new(next.convert_into(env)?.into(), env);
        env.set_object_array_element(
            &array,
            index.try_into().expect("max size validated above"),
            value,
        )
        .check_exceptions(env, "make_object_array")?
    }

    Ok(array)
}

impl<'a> ResultTypeInfo<'a> for Box<[String]> {
    type ResultType = JObjectArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let element_class = find_class(env, ClassName("java.lang.String"))
            .check_exceptions(env, "Box<[String]>::convert_into")?;
        make_object_array(env, element_class, self)
    }
}

impl<'a> ResultTypeInfo<'a> for Box<[Vec<u8>]> {
    type ResultType = JObjectArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let element_class = find_primitive_array_class(env, jni_signature!([byte]))
            .check_exceptions(env, "Box<[Vec<u8>]>::convert_into")?;
        make_object_array(env, element_class, self)
    }
}

impl<'a> ResultTypeInfo<'a> for MessageBackupValidationOutcome {
    type ResultType = JObject<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let Self {
            error_message,
            found_unknown_fields,
        } = self;

        let element_class = find_class(env, ClassName("java.lang.String"))
            .check_exceptions(env, "MessageBackupValidationOutcome::convert_into")?;
        let unknown_fields = make_object_array(
            env,
            element_class,
            found_unknown_fields.into_iter().map(|f| f.to_string()),
        )?;
        let error_message = error_message.convert_into(env)?;

        new_instance(
            env,
            ClassName("kotlin.Pair"),
            jni_args!((error_message => java.lang.Object, unknown_fields => java.lang.Object) -> void),
        )
    }
}

/// Implementation of [`bridge_as_handle`](crate::support::bridge_as_handle) for JNI.
#[macro_export]
macro_rules! jni_bridge_as_handle {
    ( $typ:ty as false $(, $($_:tt)*)? ) => {};
    ( $typ:ty as $jni_name:ident ) => {
        impl $crate::jni::BridgeHandle for $typ {
            const TYPE_TAG: u8 = $crate::jni::hash_location_for_type_tag(file!(), line!());
        }

        // Unfortunately we have to implement these explicitly because
        // `impl ArgTypeInfo for &T where T: BridgeHandle`
        // conflicts (theoretically) with
        // `impl ArgTypeInfo for T where T: SimpleArgTypeInfo`
        impl<'storage, 'param: 'storage, 'context: 'param>
            $crate::jni::ArgTypeInfo<'storage, 'param, 'context> for &'storage $typ
        {
            type ArgType = $crate::jni::ObjectHandle;
            type StoredType = ::std::sync::Arc<$typ>;

            fn borrow(
                _env: &mut $crate::jni::JNIEnv<'context>,
                foreign: &'param Self::ArgType,
            ) -> ::std::result::Result<Self::StoredType, $crate::jni::BridgeLayerError> {
                let addr =
                    unsafe { <$typ as $crate::jni::BridgeHandle>::native_handle_cast(*foreign)? };
                let owned = unsafe {
                    <$typ as $crate::jni::BridgeHandle>::from_raw_without_consuming(addr)
                };
                Ok(owned)
            }

            fn load_from(stored: &'storage mut Self::StoredType) -> Self {
                &*stored
            }
        }

        impl<'storage, 'param: 'storage, 'context: 'param>
            $crate::jni::ArgTypeInfo<'storage, 'param, 'context> for &'storage mut $typ
        {
            type ArgType = $crate::jni::ObjectHandle;
            type StoredType = ::std::sync::Arc<$typ>;

            fn borrow(
                _env: &mut $crate::jni::JNIEnv<'context>,
                foreign: &'param Self::ArgType,
            ) -> ::std::result::Result<Self::StoredType, $crate::jni::BridgeLayerError> {
                let addr =
                    unsafe { <$typ as $crate::jni::BridgeHandle>::native_handle_cast(*foreign)? };
                let owned = unsafe {
                    <$typ as $crate::jni::BridgeHandle>::from_raw_without_consuming(addr)
                };
                // This isn't perfect; the way we have things set up won't catch *later* uses of
                // this object from Java while the modification is in progress. We'd have to use a
                // proper Mutex/RwLock for that. But it's better than the nothing we had before.
                assert_eq!(
                    Self::StoredType::strong_count(&owned),
                    2, // one covered by `owned`, one outstanding from `encode_as_handle`
                    "modifying a {} while in use elsewhere",
                    ::std::any::type_name::<$typ>()
                );
                Ok(owned)
            }

            fn load_from(stored: &'storage mut Self::StoredType) -> Self {
                // This is a manual version of the unstable Arc::get_mut_unchecked.
                // https://github.com/rust-lang/rust/issues/63292
                // We can't use get_mut because we *have* cloned a second Arc.
                unsafe {
                    Self::StoredType::as_ptr(stored)
                        .cast_mut()
                        .as_mut()
                        .expect("cannot be null")
                }
            }
        }
    };
    ( $typ:ty ) => {
        // `paste!` turns the type back into an identifier.
        // We can't specify an identifier here because the main `bridge_as_handle!` accepts any type
        // and just passes it down.
        ::paste::paste! {
            $crate::jni_bridge_as_handle!($typ as $typ);
        }
    };
}

#[macro_export]
macro_rules! jni_bridge_handle_fns {
    ( $typ:ty as false $(, $($_:tt)*)? ) => {};
    ( $typ:ty as $jni_name:ident ) => {
        $crate::jni_bridge_handle_destroy!($typ as $jni_name);
    };
    ( $typ:ty ) => {
        // `paste!` turns the type back into an identifier.
        // We can't specify an identifier here because the main `bridge_handle_fns!` accepts any type
        // and just passes it down.
        ::paste::paste! {
            $crate::jni_bridge_handle_fns!($typ as $typ);
        }
    };
}

macro_rules! trivial {
    ($typ:ty) => {
        impl SimpleArgTypeInfo<'_> for $typ {
            type ArgType = Self;
            fn convert_from(_env: &mut JNIEnv, foreign: &Self) -> Result<Self, BridgeLayerError> {
                Ok(*foreign)
            }
        }
        impl ResultTypeInfo<'_> for $typ {
            type ResultType = Self;
            fn convert_into(self, _env: &mut JNIEnv) -> Result<Self, BridgeLayerError> {
                Ok(self)
            }
        }
    };
}

trivial!(i32);
trivial!(());

/// Syntactically translates `bridge_fn` argument types to JNI types for `cbindgen` and
/// `gen_java_decl.py`.
///
/// This is a syntactic transformation (because that's how Rust macros work), so new argument types
/// will need to be added here directly even if they already implement [`ArgTypeInfo`]. The default
/// behavior for references is to assume they're opaque handles to Rust values; the default
/// behavior for `&mut dyn Foo` is to assume there's a type called `jni::JavaFoo`.
///
/// The `'local` lifetime represents the lifetime of the JNI context.
#[macro_export]
macro_rules! jni_arg_type {
    (u8) => {
        // Note: not a jbyte. It's better to preserve the signedness here.
        ::jni::sys::jint
    };
    (u16) => {
        ::jni::sys::jint
    };
    (i32) => {
        ::jni::sys::jint
    };
    (u32) => {
        ::jni::sys::jint
    };
    (Option<u32>) => {
        ::jni::sys::jint
    };
    (u64) => {
        ::jni::sys::jlong
    };
    (bool) => {
        ::jni::sys::jboolean
    };
    (String) => {
        ::jni::objects::JString<'local>
    };
    (Option<String>) => {
        $crate::jni::Nullable<::jni::objects::JString<'local>>
    };
    (&[u8]) => {
        ::jni::objects::JByteArray<'local>
    };
    (Option<&[u8]>) => {
        $crate::jni::Nullable<::jni::objects::JByteArray<'local>>
    };
    (Option<Box<dyn ChatListener> >) =>{
        $crate::jni::Nullable<jni::JavaBridgeChatListener<'local>>
    };
    (Box<dyn ChatListener >) =>{
        jni::JavaBridgeChatListener<'local>
    };
    (Box<dyn ConnectChatBridge >) =>{
        $crate::jni::JavaConnectChatBridge<'local>
    };
    (RegistrationCreateSessionRequest) => {
        ::jni::objects::JObject<'local>
    };
    (RegistrationPushToken) => {
        ::jni::objects::JString<'local>
    };
    (SignedPublicPreKey) => {
        jni::JavaSignedPublicPreKey<'local>
    };
    (&mut [u8]) => {
        ::jni::objects::JByteArray<'local>
    };
    (&[u8; $len:expr]) => {
        ::jni::objects::JByteArray<'local>
    };
    (Box<[u8]>) => {
        ::jni::objects::JByteArray<'local>
    };
    (Box<[String]>) => {
        ::jni::objects::JObjectArray<'local>
    };
    (LanguageList) => {
        ::jni::objects::JObjectArray<'local>
    };
    (&BackupKey) => {
        ::jni::objects::JByteArray<'local>
    };
    (Option<Box<[u8]> >) => {
        $crate::jni::Nullable<::jni::objects::JByteArray<'local>>
    };
    (Option<&[u8; $len:expr] >) => {
        $crate::jni::Nullable<::jni::objects::JByteArray<'local>>
    };
    (ServiceId) => {
        ::jni::objects::JByteArray<'local>
    };
    (Aci) => {
        ::jni::objects::JByteArray<'local>
    };
    (Pni) => {
        ::jni::objects::JByteArray<'local>
    };
    (AccountEntropyPool) => {
        ::jni::objects::JString<'local>
    };
    (MultiRecipientSendAuthorization) => {
        $crate::jni::Nullable<::jni::objects::JByteArray<'local>>
    };
    (ServiceIdSequence<'_>) => {
        ::jni::objects::JByteArray<'local>
    };
    (Vec<&[u8]>) => {
        jni::JavaByteBufferArray<'local>
    };
    (Timestamp) => {
        ::jni::sys::jlong
    };
    (Uuid) => {
        $crate::jni::JavaUUID<'local>
    };
    (E164) => {
        ::jni::objects::JString<'local>
    };
    (Option<E164>) => {
        $crate::jni::Nullable<::jni::objects::JString<'local>>
    };
    (jni::CiphertextMessageRef) => {
        $crate::jni::JavaCiphertextMessage<'local>
    };
    (& [& $typ:ty]) => {
        ::jni::objects::JLongArray<'local>
    };
    (&mut dyn $typ:ty) => {
        ::paste::paste!(jni::[<Java $typ>]<'local>)
    };
    (Option<&dyn $typ:ty>) => {
        ::paste::paste!($crate::jni::Nullable<jni::[<Java $typ>]<'local>>)
    };
    (& $typ:ty) => {
        $crate::jni::ObjectHandle
    };
    (&mut $typ:ty) => {
        $crate::jni::ObjectHandle
    };
    (Option<& $typ:ty>) => {
        $crate::jni::ObjectHandle
    };
    (Serialized<$typ:ident>) => {
        ::jni::objects::JByteArray<'local>
    };
    (AsType<$typ:ident, $bridged:ident>) => {
        $crate::jni_arg_type!($bridged)
    };
    (CreateSession) => {
        $crate::jni::JObject<'local>
    };
    (TestingFutureCancellationGuard) => { ::jni::sys::jlong };

    (Ignored<$typ:ty>) => (::jni::objects::JObject<'local>);
}

/// Syntactically translates `bridge_fn` result types to JNI types for `cbindgen` and
/// `gen_java_decl.py`.
///
/// This is a syntactic transformation (because that's how Rust macros work), so new result types
/// will need to be added here directly even if they already implement [`ResultTypeInfo`]. The
/// default behavior is to assume we're returning an opaque handle to a Rust value.
///
/// The `'local` lifetime represents the lifetime of the JNI context.
#[macro_export]
macro_rules! jni_result_type {
    // These rules only match a single token for a Result's success type, or
    // Option's inner type.  We can't use `:ty` because we need the resulting
    // tokens to be matched recursively rather than treated as a single unit,
    // and we can't match multiple tokens because Rust's macros match eagerly.
    // Therefore, if you need to return a more complicated Result or Option
    // type, you'll have to add another rule for its form.
    (std::result::Result<$($rest:tt)+) => {
        jni_result_type!(Result<$($rest)+)
    };
    (Result<$typ:tt $(, $_:ty)?>) => {
        $crate::jni::Throwing<jni_result_type!($typ)>
    };
    (Result<&$typ:tt $(, $_:ty)?>) => {
        $crate::jni::Throwing<jni_result_type!(&$typ)>
    };
    (Result<Option<&$typ:tt> $(, $_:ty)?>) => {
        $crate::jni::Throwing<jni_result_type!(Option<&$typ>)>
    };
    (Result<Option<$typ:tt<$($args:tt),+> > $(, $_:ty)?>) => {
        $crate::jni::Throwing<jni_result_type!(Option<$typ<$($args),+> >)>
    };
    (Result<$typ:tt<$($args:tt),+> $(, $_:ty)?>) => {
        $crate::jni::Throwing<jni_result_type!($typ<$($args),+>)>
    };
    (Option<u32>) => {
        ::jni::sys::jint
    };
    (Option<u64>) => {
        ::jni::sys::jlong
    };
    (Option<$typ:tt>) => {
        $crate::jni::Nullable<$crate::jni_result_type!($typ)>
    };
    (Option<&$typ:tt>) => {
        $crate::jni::Nullable<$crate::jni_result_type!(&$typ)>
    };
    (Option<$typ:tt<$($args:tt),+> >) => {
        $crate::jni::Nullable<$crate::jni_result_type!($typ<$($args),+>)>
    };
    (()) => {
        ()
    };
    (($a:tt, $b:tt)) => {
        $crate::jni::JavaPair<'local, $crate::jni_result_type!($a), $crate::jni_result_type!($b)>
    };
    (bool) => {
        ::jni::sys::jboolean
    };
    (u8) => {
        // Note: not a jbyte. It's better to preserve the signedness here.
        ::jni::sys::jint
    };
    (u16) => {
        // Note: not a jshort. It's better to preserve the signedness here.
        ::jni::sys::jint
    };
    (i32) => {
        ::jni::sys::jint
    };
    (u32) => {
        ::jni::sys::jint
    };
    (u64) => {
        ::jni::sys::jlong
    };
    (&str) => {
        ::jni::objects::JString<'local>
    };
    (String) => {
        ::jni::objects::JString<'local>
    };
    (Uuid) => {
        $crate::jni::JavaUUID<'local>
    };
    (Timestamp) => {
        ::jni::sys::jlong
    };
    (&[u8]) => {
        ::jni::objects::JByteArray<'local>
    };
    (Vec<u8>) => {
        ::jni::objects::JByteArray<'local>
    };
    (&[String]) => {
        ::jni::objects::JObjectArray<'local>
    };
    (Box<[String]>) => {
        ::jni::objects::JObjectArray<'local>
    };
    (Box<[Vec<u8>]>) => {
        $crate::jni::JavaArrayOfByteArray<'local>
    };
    (Cds2Metrics) => {
        $crate::jni::JavaMap<'local>
    };
    ([u8; $len:expr]) => {
        ::jni::objects::JByteArray<'local>
    };
    (ServiceId) => {
        ::jni::objects::JByteArray<'local>
    };
    (Aci) => {
        ::jni::objects::JByteArray<'local>
    };
    (Pni) => {
        ::jni::objects::JByteArray<'local>
    };
    (MessageBackupValidationOutcome) => {
        ::jni::objects::JObject<'local>
    };
    (MessageBackupReadOutcome) => {
        ::jni::objects::JObject<'local>
    };
    (LookupResponse) => {
        ::jni::objects::JObject<'local>
    };
    (ChatResponse) => {
        ::jni::objects::JObject<'local>
    };
    (CiphertextMessage) => {
        jni::JavaCiphertextMessage<'local>
    };
    (Vec<ServiceId>) => {
        ::jni::objects::JObjectArray<'local>
    };
    (Box<[ChallengeOption] >) => {
        ::jni::objects::JObjectArray<'local>
    };
    (Box<[RegisterResponseBadge] >) => {
        ::jni::objects::JObjectArray<'local>
    };
    (CheckSvr2CredentialsResponse) => {
        ::jni::objects::JObject<'local>
    };
    (Serialized<$typ:ident>) => {
        ::jni::objects::JByteArray<'local>
    };
    (Ignored<$typ:ty>) => {
        ::jni::objects::JObject<'local>
    };
    ( $handle:ty ) => {
        $crate::jni::ObjectHandle
    };
}
