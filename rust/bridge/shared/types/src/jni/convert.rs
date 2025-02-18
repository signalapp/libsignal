//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::ParseIntError;
use std::ops::Deref;

use jni::objects::{AutoLocal, JByteBuffer, JMap, JObjectArray};
use jni::sys::{jbyte, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use libsignal_account_keys::{AccountEntropyPool, InvalidAccountEntropyPool};
use libsignal_net::cdsi::LookupResponseEntry;
use libsignal_protocol::*;
use paste::paste;

use super::*;
use crate::io::{InputStream, SyncInputStream};
use crate::message_backup::MessageBackupValidationOutcome;
use crate::net::chat::ChatListener;
use crate::support::{Array, AsType, FixedLengthBincodeSerializable, Serialized};

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
                "{} to u32",
                foreign
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
                "{} to Timestamp (u64)",
                foreign
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
                "{} to Timestamp (u64)",
                foreign
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
            .map_err(|_| BridgeLayerError::IntegerOverflow(format!("{} to u8", foreign)))
    }
}

/// Supports all valid u16 values `0..=65536`.
impl SimpleArgTypeInfo<'_> for u16 {
    type ArgType = jint;
    fn convert_from(_env: &mut JNIEnv, foreign: &jint) -> Result<Self, BridgeLayerError> {
        u16::try_from(*foreign)
            .map_err(|_| BridgeLayerError::IntegerOverflow(format!("{} to u16", foreign)))
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
        zerocopy::AsBytes::as_bytes(&**stored)
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
        zerocopy::AsBytes::as_bytes_mut(&mut **stored)
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
        let len = env
            .get_array_length(foreign)
            .check_exceptions(env, "Vec<&[u8]>::convert_from")?;
        let slices: Vec<&[u8]> = (0..len)
            .map(|i| {
                let next = AutoLocal::new(
                    JByteBuffer::from(
                        env.get_object_array_element(foreign, i)
                            .check_exceptions(env, "Vec<&[u8]>::convert_from")?,
                    ),
                    env,
                );
                let len = env
                    .get_direct_buffer_capacity(&next)
                    .check_exceptions(env, "Vec<&[u8]>::convert_from")?;
                let addr = env
                    .get_direct_buffer_address(&next)
                    .check_exceptions(env, "Vec<&[u8]>::convert_from")?;
                if !addr.is_null() {
                    Ok(unsafe { std::slice::from_raw_parts(addr, len) })
                } else {
                    if len != 0 {
                        return Err(BridgeLayerError::NullPointer(Some(
                            "ByteBuffer direct address",
                        )));
                    }
                    Ok([].as_slice())
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(slices)
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

/// A translation from a Java interface where the implementing class wraps the Rust handle.
impl<'a> SimpleArgTypeInfo<'a> for CiphertextMessageRef<'a> {
    type ArgType = JavaCiphertextMessage<'a>;
    fn convert_from(env: &mut JNIEnv, foreign: &Self::ArgType) -> Result<Self, BridgeLayerError> {
        fn native_handle_from_message<'a, T: 'static>(
            env: &mut JNIEnv,
            foreign: &JavaCiphertextMessage<'a>,
            class_name: &'static str,
            make_result: fn(&'a T) -> CiphertextMessageRef<'a>,
        ) -> Result<Option<CiphertextMessageRef<'a>>, BridgeLayerError> {
            if env
                .is_instance_of(foreign, class_name)
                .check_exceptions(env, "CiphertextMessageRef::convert_from")?
            {
                let handle: jlong = env
                    .get_field(foreign, "unsafeHandle", jni_signature!(long))
                    .check_exceptions(env, "CiphertextMessageRef::convert_from")?
                    .try_into()
                    .expect_no_exceptions()?;
                Ok(Some(make_result(unsafe { native_handle_cast(handle)? })))
            } else {
                Ok(None)
            }
        }

        if foreign.is_null() {
            return Err(BridgeLayerError::NullPointer(Some("CipherTextMessageRef")));
        }

        None.or_else(|| {
            native_handle_from_message(
                env,
                foreign,
                jni_class_name!(org.signal.libsignal.protocol.message.SignalMessage),
                Self::SignalMessage,
            )
            .transpose()
        })
        .or_else(|| {
            native_handle_from_message(
                env,
                foreign,
                jni_class_name!(org.signal.libsignal.protocol.message.PreKeySignalMessage),
                Self::PreKeySignalMessage,
            )
            .transpose()
        })
        .or_else(|| {
            native_handle_from_message(
                env,
                foreign,
                jni_class_name!(org.signal.libsignal.protocol.message.SenderKeyMessage),
                Self::SenderKeyMessage,
            )
            .transpose()
        })
        .or_else(|| {
            native_handle_from_message(
                env,
                foreign,
                jni_class_name!(org.signal.libsignal.protocol.message.PlaintextContent),
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

        let long_class = find_class(env, ClassName("java.lang.Long"))?;
        for (k, v) in self.0 {
            let k = k.convert_into(env)?;
            let v = new_object(env, &long_class, jni_args!((v => long) -> void))
                .check_exceptions(env, "java.lang.Long")?;
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
        zerocopy::AsBytes::as_bytes(&**stored)
            .try_into()
            .expect("checked in construction")
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

/// A marker for Rust objects exposed as opaque handles (pointers converted to `jlong`).
///
/// When we do this, we hand the lifetime over to the app. Since we don't know how long the object
/// will be kept alive, it can't (safely) have references to anything with a non-static lifetime.
pub trait BridgeHandle: 'static {}

impl<T: BridgeHandle> SimpleArgTypeInfo<'_> for &T {
    type ArgType = ObjectHandle;
    fn convert_from(_env: &mut JNIEnv, foreign: &Self::ArgType) -> Result<Self, BridgeLayerError> {
        Ok(unsafe { native_handle_cast(*foreign) }?)
    }
}

impl<T: BridgeHandle> SimpleArgTypeInfo<'_> for Option<&T> {
    type ArgType = ObjectHandle;
    fn convert_from(env: &mut JNIEnv, foreign: &Self::ArgType) -> Result<Self, BridgeLayerError> {
        if *foreign == 0 {
            Ok(None)
        } else {
            <&T>::convert_from(env, foreign).map(Some)
        }
    }
}

impl<T: BridgeHandle> SimpleArgTypeInfo<'_> for &mut T {
    type ArgType = ObjectHandle;
    fn convert_from(_env: &mut JNIEnv, foreign: &Self::ArgType) -> Result<Self, BridgeLayerError> {
        unsafe { native_handle_cast(*foreign) }
    }
}

impl<'storage, 'param: 'storage, 'context: 'param, T: BridgeHandle>
    ArgTypeInfo<'storage, 'param, 'context> for &'storage [&'storage T]
{
    type ArgType = JLongArray<'context>;
    type StoredType = Vec<&'storage T>;
    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, BridgeLayerError> {
        let array = unsafe { env.get_array_elements(foreign, ReleaseMode::NoCopyBack) }
            .check_exceptions(env, "<&[&T]>::borrow")?;
        array
            .iter()
            .map(|&raw_handle| unsafe {
                (raw_handle as *const T)
                    .as_ref()
                    .ok_or(BridgeLayerError::NullPointer(None))
            })
            .collect()
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> &'storage [&'storage T] {
        &*stored
    }
}

impl<T: BridgeHandle> ResultTypeInfo<'_> for T {
    type ResultType = ObjectHandle;
    fn convert_into(self, _env: &mut JNIEnv) -> Result<Self::ResultType, BridgeLayerError> {
        Ok(Box::into_raw(Box::new(self)) as ObjectHandle)
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

impl<'a> ResultTypeInfo<'a> for (Vec<u8>, Vec<u8>) {
    type ResultType = JObjectArray<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let key = env
            .byte_array_from_slice(&self.0)
            .check_exceptions(env, "search key to jByteArray")?;
        let value = env
            .byte_array_from_slice(&self.1)
            .check_exceptions(env, "monitoring data to jByteArray")?;
        let pair = env
            .new_object_array(2, jni_signature!([byte]), JavaObject::null())
            .check_exceptions(env, "new_object_array")?;

        env.set_object_array_element(&pair, 0, key)
            .check_exceptions(env, "set key")?;
        env.set_object_array_element(&pair, 1, value)
            .check_exceptions(env, "set value")?;
        Ok(pair)
    }
}

type PairOfByteVecs = (Vec<u8>, Vec<u8>);
impl_result_type_info_for_option!(PairOfByteVecs);

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
        let entry_class = find_class(env, ENTRY_CLASS)?;

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
                .check_exceptions(env, ENTRY_CLASS.0)?,
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

/// Converts each element of `it` to a Java object, storing the result in an array.
///
/// `element_type_signature` should use [`jni_class_name`] if it's a plain class and
/// [`jni_signature`] if it's an array (according to the official docs for the JNI [FindClass][]
/// operation).
///
/// [FindClass]: https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#FindClass
fn make_object_array<'a, It>(
    env: &mut JNIEnv<'a>,
    element_type_signature: &str,
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
            element_type_signature,
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
        make_object_array(env, jni_class_name!(java.lang.String), self.into_vec())
    }
}

impl<'a> ResultTypeInfo<'a> for Box<[Vec<u8>]> {
    type ResultType = JObjectArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        make_object_array(env, jni_signature!([byte]), self.into_vec())
    }
}

impl<'a> ResultTypeInfo<'a> for MessageBackupValidationOutcome {
    type ResultType = JObject<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> Result<Self::ResultType, BridgeLayerError> {
        let Self {
            error_message,
            found_unknown_fields,
        } = self;

        let unknown_fields = make_object_array(
            env,
            jni_class_name!(java.lang.String),
            found_unknown_fields.into_iter().map(|f| f.to_string()),
        )?;
        let error_message = error_message.convert_into(env)?;

        new_instance(
            env,
            ClassName("org.signal.libsignal.protocol.util.Pair"),
            jni_args!((error_message => java.lang.Object, unknown_fields => java.lang.Object) -> void),
        )
    }
}

/// Implementation of [`bridge_as_handle`](crate::support::bridge_as_handle) for JNI.
#[macro_export]
macro_rules! jni_bridge_as_handle {
    ( $typ:ty as false $(, $($_:tt)*)? ) => {};
    ( $typ:ty as $jni_name:ident ) => {
        impl $crate::jni::BridgeHandle for $typ {}
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
        ::jni::objects::JString<'local>
    };
    (&[u8]) => {
        ::jni::objects::JByteArray<'local>
    };
    (Option<&[u8]>) => {
        ::jni::objects::JByteArray<'local>
    };
    (Option<Box<dyn ChatListener> >) =>{
        jni::JavaBridgeChatListener<'local>
    };
    (Box<dyn ChatListener >) =>{
        jni::JavaBridgeChatListener<'local>
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
    (Option<Box<[u8]> >) => {
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
    (AccountEntropyPool) => {
        ::jni::objects::JString<'local>
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
        ::jni::objects::JString<'local>
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
        ::paste::paste!(jni::[<Java $typ>]<'local>)
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
    (Result<$typ:tt $(, $_:ty)?>) => {
        $crate::jni::Throwing<jni_result_type!($typ)>
    };
    (Result<&$typ:tt $(, $_:ty)?>) => {
        $crate::jni::Throwing<jni_result_type!(&$typ)>
    };
    (Result<Option<&$typ:tt> $(, $_:ty)?>) => {
        $crate::jni::Throwing<jni_result_type!(&$typ)>
    };
    (Result<Option<$typ:tt<$($args:tt),+> > $(, $_:ty)?>) => {
        $crate::jni::Throwing<jni_result_type!($typ<$($args),+>)>
    };
    (Result<$typ:tt<$($args:tt),+> $(, $_:ty)?>) => {
        $crate::jni::Throwing<jni_result_type!($typ<$($args),+>)>
    };
    (Option<$typ:tt>) => {
        $crate::jni_result_type!($typ)
    };
    (Option<&$typ:tt>) => {
        $crate::jni_result_type!(&$typ)
    };
    (Option<$typ:tt<$($args:tt),+> >) => {
        $crate::jni_result_type!($typ<$($args),+>)
    };
    (()) => {
        ()
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
    (Option<u32>) => {
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
    ((Vec<u8>, Vec<u8>)) => {
        ::jni::objects::JObjectArray<'local>
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
