//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{AutoLocal, JMap};
use jni::sys::{jbyte, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use libsignal_net::cdsi::LookupResponseEntry;
use libsignal_protocol::*;

use paste::paste;

use std::num::ParseIntError;
use std::ops::Deref;

use crate::io::{InputStream, SyncInputStream};
use crate::support::{Array, FixedLengthBincodeSerializable, Serialized};

use super::*;

/// Converts arguments from their JNI form to their Rust form.
///
/// `ArgTypeInfo` has two required methods: `borrow` and `load_from`. The use site looks like this:
///
/// ```no_run
/// # use libsignal_bridge::jni::*;
/// # use jni::JNIEnv;
/// # struct Foo;
/// # impl SimpleArgTypeInfo<'_> for Foo {
/// #     type ArgType = isize;
/// #     fn convert_from(env: &mut JNIEnv, foreign: &isize) -> SignalJniResult<Self> { Ok(Foo) }
/// # }
/// # fn test(env: &mut JNIEnv, jni_arg: isize) -> SignalJniResult<()> {
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
    ) -> SignalJniResult<Self::StoredType>;
    /// Loads the Rust value from the data that's been `stored` by [`borrow()`](Self::borrow()).
    fn load_from(stored: &'storage mut Self::StoredType) -> Self;
}

/// A simpler interface for [`ArgTypeInfo`] for when no local storage is needed.
///
/// This trait is easier to use when writing JNI functions manually:
///
/// ```no_run
/// # use libsignal_bridge::jni::*;
/// # use jni::objects::JObject;
/// # use jni::JNIEnv;
/// # struct Foo;
/// impl<'a> SimpleArgTypeInfo<'a> for Foo {
///     type ArgType = JObject<'a>;
///     fn convert_from(env: &mut JNIEnv, foreign: &JObject<'a>) -> SignalJniResult<Self> {
///         // ...
///         # Ok(Foo)
///     }
/// }
///
/// # fn test<'a>(env: &mut JNIEnv<'a>, jni_arg: JObject<'a>) -> SignalJniResult<()> {
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
    fn convert_from(env: &mut JNIEnv<'a>, foreign: &Self::ArgType) -> SignalJniResult<Self>;
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
    ) -> SignalJniResult<Self::StoredType> {
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
/// # use libsignal_bridge::jni::*;
/// # use jni::JNIEnv;
/// # use jni::objects::JString;
/// # struct Foo;
/// # impl<'a> ResultTypeInfo<'a> for Foo {
/// #     type ResultType = JString<'a>;
/// #     fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<JString<'a>> { todo!() }
/// # }
/// # fn test<'a>(env: &mut JNIEnv<'a>) -> SignalJniResult<()> {
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
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType>;
}

/// Supports values `0..=Integer.MAX_VALUE`.
///
/// Negative `int` values are *not* reinterpreted as large `u32` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u32`.
impl SimpleArgTypeInfo<'_> for u32 {
    type ArgType = jint;
    fn convert_from(_env: &mut JNIEnv, foreign: &jint) -> SignalJniResult<Self> {
        if *foreign < 0 {
            return Err(SignalJniError::IntegerOverflow(format!(
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
    fn convert_from(env: &mut JNIEnv, foreign: &jint) -> SignalJniResult<Self> {
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
    fn convert_from(_env: &mut JNIEnv, foreign: &jlong) -> SignalJniResult<Self> {
        Ok(*foreign as u64)
    }
}

/// Supports values `0..=Long.MAX_VALUE`.
///
/// Negative `long` values are *not* reinterpreted as large `u64` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u64`.
impl SimpleArgTypeInfo<'_> for crate::protocol::Timestamp {
    type ArgType = jlong;
    fn convert_from(_env: &mut JNIEnv, foreign: &jlong) -> SignalJniResult<Self> {
        if *foreign < 0 {
            return Err(SignalJniError::IntegerOverflow(format!(
                "{} to Timestamp (u64)",
                foreign
            )));
        }
        Ok(Self::from_millis(*foreign as u64))
    }
}

/// Supports values `0..=Long.MAX_VALUE`.
///
/// Negative `long` values are *not* reinterpreted as large `u64` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u64`.
impl SimpleArgTypeInfo<'_> for crate::zkgroup::Timestamp {
    type ArgType = jlong;
    fn convert_from(_env: &mut JNIEnv, foreign: &jlong) -> SignalJniResult<Self> {
        if *foreign < 0 {
            return Err(SignalJniError::IntegerOverflow(format!(
                "{} to Timestamp (u64)",
                foreign
            )));
        }
        Ok(Self::from_seconds(*foreign as u64))
    }
}

/// Supports all valid byte values `0..=255`.
impl SimpleArgTypeInfo<'_> for u8 {
    type ArgType = jint;
    fn convert_from(_env: &mut JNIEnv, foreign: &jint) -> SignalJniResult<Self> {
        match u8::try_from(*foreign) {
            Err(_) => Err(SignalJniError::IntegerOverflow(format!(
                "{} to u8",
                foreign
            ))),
            Ok(v) => Ok(v),
        }
    }
}

impl<'a> SimpleArgTypeInfo<'a> for String {
    type ArgType = JString<'a>;
    fn convert_from(env: &mut JNIEnv, foreign: &JString<'a>) -> SignalJniResult<Self> {
        Ok(env.get_string(foreign)?.into())
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Option<String> {
    type ArgType = JString<'a>;
    fn convert_from(env: &mut JNIEnv<'a>, foreign: &JString<'a>) -> SignalJniResult<Self> {
        if foreign.is_null() {
            Ok(None)
        } else {
            String::convert_from(env, foreign).map(Some)
        }
    }
}

impl<'a> SimpleArgTypeInfo<'a> for uuid::Uuid {
    type ArgType = JObject<'a>;
    fn convert_from(env: &mut JNIEnv, foreign: &JObject<'a>) -> SignalJniResult<Self> {
        check_jobject_type(env, foreign, jni_class_name!(java.util.UUID))?;
        let args = jni_args!(() -> long);
        let msb: jlong = call_method_checked(env, foreign, "getMostSignificantBits", args)?;
        let lsb: jlong = call_method_checked(env, foreign, "getLeastSignificantBits", args)?;

        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&msb.to_be_bytes());
        bytes[8..].copy_from_slice(&lsb.to_be_bytes());
        Ok(uuid::Uuid::from_bytes(bytes))
    }
}

impl<'a> SimpleArgTypeInfo<'a> for libsignal_net::cdsi::E164 {
    type ArgType = <String as SimpleArgTypeInfo<'a>>::ArgType;
    fn convert_from(env: &mut JNIEnv<'a>, foreign: &Self::ArgType) -> SignalJniResult<Self> {
        let e164 = String::convert_from(env, foreign)?;
        let e164 = e164.parse().map_err(|_: ParseIntError| {
            SignalProtocolError::InvalidArgument(format!("{e164} is not an e164"))
        })?;
        Ok(e164)
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
    ) -> SignalJniResult<Self::StoredType> {
        Ok(unsafe { env.get_array_elements(foreign, ReleaseMode::NoCopyBack)? })
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> &'storage [u8] {
        // Deref `stored` to the contained slice of [jbyte] ([i8]), then cast that to [u8].
        bytemuck::cast_slice(stored)
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
    ) -> SignalJniResult<Self::StoredType> {
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
    ) -> SignalJniResult<Self::StoredType> {
        Ok(unsafe { env.get_array_elements(foreign, ReleaseMode::CopyBack)? })
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> &'storage mut [u8] {
        // Deref `stored` to the contained slice of [jbyte] ([i8]), then cast that to [u8].
        bytemuck::cast_slice_mut(stored)
    }
}

impl<'storage, 'param: 'storage, 'context: 'param> ArgTypeInfo<'storage, 'param, 'context>
    for crate::protocol::ServiceIdSequence<'storage>
{
    type ArgType = JByteArray<'context>;
    type StoredType = AutoElements<'context, 'context, 'param, jbyte>;

    fn borrow(
        env: &mut JNIEnv<'context>,
        foreign: &'param Self::ArgType,
    ) -> SignalJniResult<Self::StoredType> {
        <&'storage [u8]>::borrow(env, foreign)
    }

    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        let buffer = <&'storage [u8]>::load_from(stored);
        Self::parse(buffer)
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
                ) -> SignalJniResult<Self::StoredType> {
                    Self::StoredType::new(env, store)
                }
                fn load_from(
                    stored: &'storage mut Self::StoredType,
                ) -> Self {
                    stored
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

/// A translation from a Java interface where the implementing class wraps the Rust handle.
impl<'a> SimpleArgTypeInfo<'a> for CiphertextMessageRef<'a> {
    type ArgType = JavaCiphertextMessage<'a>;
    fn convert_from(env: &mut JNIEnv, foreign: &Self::ArgType) -> SignalJniResult<Self> {
        fn native_handle_from_message<'a, T: 'static>(
            env: &mut JNIEnv,
            foreign: &JavaCiphertextMessage<'a>,
            class_name: &'static str,
            make_result: fn(&'a T) -> CiphertextMessageRef<'a>,
        ) -> SignalJniResult<Option<CiphertextMessageRef<'a>>> {
            if env.is_instance_of(foreign, class_name)? {
                let handle: jlong = env
                    .get_field(foreign, "unsafeHandle", jni_signature!(long))?
                    .try_into()?;
                Ok(Some(make_result(unsafe { native_handle_cast(handle)? })))
            } else {
                Ok(None)
            }
        }

        if foreign.is_null() {
            return Err(SignalJniError::NullHandle);
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
        .unwrap_or(Err(SignalJniError::BadJniParameter("CiphertextMessage")))
    }
}

#[cfg(not(target_os = "android"))]
impl<'a> ResultTypeInfo<'a> for crate::cds2::Cds2Metrics {
    type ResultType = JObject<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        let jobj = new_object(
            env,
            jni_class_name!(java.util.HashMap),
            jni_args!(() -> void),
        )?;
        let jmap = JMap::from_env(env, &jobj)?;

        let long_class = env.find_class(jni_class_name!(java.lang.Long))?;
        for (k, v) in self.0 {
            let k = k.convert_into(env)?;
            let v = new_object(env, &long_class, jni_args!((v => long) -> void))?;
            jmap.put(env, &k, &v)?;
        }
        Ok(jobj)
    }
}

impl ResultTypeInfo<'_> for bool {
    type ResultType = jboolean;
    fn convert_into(self, _env: &mut JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(if self { JNI_TRUE } else { JNI_FALSE })
    }
}

/// Supports all valid byte values `0..=255`.
impl ResultTypeInfo<'_> for u8 {
    type ResultType = jint;
    fn convert_into(self, _env: &mut JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(self as jint)
    }
}

/// Reinterprets the bits of the `u32` as a Java `int`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `u32`.
impl ResultTypeInfo<'_> for u32 {
    type ResultType = jint;
    fn convert_into(self, _env: &mut JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self as jint)
    }
}

/// Reinterprets the bits of the `u32` as a Java `int`. Returns `-1` for `None`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `Option<u32>`.
impl ResultTypeInfo<'_> for Option<u32> {
    type ResultType = jint;
    fn convert_into(self, _env: &mut JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self.unwrap_or(u32::MAX) as jint)
    }
}

/// Reinterprets the bits of the `u64` as a Java `long`.
impl ResultTypeInfo<'_> for u64 {
    type ResultType = jlong;
    fn convert_into(self, _env: &mut JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self as jlong)
    }
}

/// Reinterprets the bits of the timestamp's `u64` as a Java `long`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `Timestamp`.
impl ResultTypeInfo<'_> for crate::protocol::Timestamp {
    type ResultType = jlong;
    fn convert_into(self, _env: &mut JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self.as_millis() as jlong)
    }
}

/// Reinterprets the bits of the timestamp's `u64` as a Java `long`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `Timestamp`.
impl ResultTypeInfo<'_> for crate::zkgroup::Timestamp {
    type ResultType = jlong;
    fn convert_into(self, _env: &mut JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self.as_seconds() as jlong)
    }
}

impl<'a> ResultTypeInfo<'a> for String {
    type ResultType = JString<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        self.deref().convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for Option<String> {
    type ResultType = JString<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        self.as_deref().convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for &str {
    type ResultType = JString<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        Ok(env.new_string(self)?)
    }
}

impl<'a> ResultTypeInfo<'a> for Option<&str> {
    type ResultType = JString<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        match self {
            Some(s) => s.convert_into(env),
            None => Ok(JString::default()),
        }
    }
}

impl<'a> ResultTypeInfo<'a> for &[u8] {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        Ok(env.byte_array_from_slice(self)?)
    }
}

impl<'a> ResultTypeInfo<'a> for Option<&[u8]> {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        match self {
            Some(s) => s.convert_into(env),
            None => Ok(JByteArray::default()),
        }
    }
}

impl<'a> ResultTypeInfo<'a> for Vec<u8> {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        self.deref().convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for Option<Vec<u8>> {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
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
    ) -> SignalJniResult<Self::StoredType> {
        let elements = unsafe { env.get_array_elements(foreign, ReleaseMode::NoCopyBack)? };
        if elements.len() != LEN {
            return Err(SignalJniError::IncorrectArrayLength {
                expected: LEN,
                actual: elements.len(),
            });
        }
        Ok(elements)
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> &'storage [u8; LEN] {
        // Deref `stored` to the contained slice of [jbyte] ([i8]), then cast that to [u8],
        // then convert the fixed-sized array [u8; LEN]
        bytemuck::cast_slice(stored)
            .try_into()
            .expect("checked in construction")
    }
}

impl<'a, const LEN: usize> ResultTypeInfo<'a> for [u8; LEN] {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        self.as_ref().convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for uuid::Uuid {
    type ResultType = JObject<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        let uuid_bytes: [u8; 16] = *self.as_bytes();
        let (msb, lsb) = uuid_bytes.split_at(8);
        Ok(new_object(
            env,
            jni_class_name!(java.util.UUID),
            jni_args!((
                jlong::from_be_bytes(msb.try_into().expect("correct length")) => long,
                jlong::from_be_bytes(lsb.try_into().expect("correct length")) => long,
            ) -> void),
        )?)
    }
}

/// A translation to a Java interface where the implementing class wraps the Rust handle.
impl<'a> ResultTypeInfo<'a> for CiphertextMessage {
    type ResultType = JavaCiphertextMessage<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        match self {
            CiphertextMessage::SignalMessage(m) => {
                let message = m.convert_into(env)?;
                jobject_from_native_handle(
                    env,
                    jni_class_name!(org.signal.libsignal.protocol.message.SignalMessage),
                    message,
                )
            }
            CiphertextMessage::PreKeySignalMessage(m) => {
                let message = m.convert_into(env)?;
                jobject_from_native_handle(
                    env,
                    jni_class_name!(org.signal.libsignal.protocol.message.PreKeySignalMessage),
                    message,
                )
            }
            CiphertextMessage::SenderKeyMessage(m) => {
                let message = m.convert_into(env)?;
                jobject_from_native_handle(
                    env,
                    jni_class_name!(org.signal.libsignal.protocol.message.SenderKeyMessage),
                    message,
                )
            }
            CiphertextMessage::PlaintextContent(m) => {
                let message = m.convert_into(env)?;
                jobject_from_native_handle(
                    env,
                    jni_class_name!(org.signal.libsignal.protocol.message.PlaintextContent),
                    message,
                )
            }
        }
    }
}

impl<'a, T: ResultTypeInfo<'a>, E> ResultTypeInfo<'a> for Result<T, E>
where
    SignalJniError: From<E>,
{
    type ResultType = T::ResultType;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
}

/// Used when returning an optional buffer, since the conversion to a Java array might also fail.
impl<'a> ResultTypeInfo<'a> for Option<SignalJniResult<JByteArray<'a>>> {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, _env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        Ok(self.transpose()?.unwrap_or_default())
    }
}

impl<'a> ResultTypeInfo<'a> for Option<JObject<'a>> {
    type ResultType = JObject<'a>;
    fn convert_into(self, _env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
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
    fn convert_from(_env: &mut JNIEnv, foreign: &Self::ArgType) -> SignalJniResult<Self> {
        Ok(unsafe { native_handle_cast(*foreign) }?)
    }
}

impl<T: BridgeHandle> SimpleArgTypeInfo<'_> for Option<&T> {
    type ArgType = ObjectHandle;
    fn convert_from(env: &mut JNIEnv, foreign: &Self::ArgType) -> SignalJniResult<Self> {
        if *foreign == 0 {
            Ok(None)
        } else {
            <&T>::convert_from(env, foreign).map(Some)
        }
    }
}

impl<T: BridgeHandle> SimpleArgTypeInfo<'_> for &mut T {
    type ArgType = ObjectHandle;
    fn convert_from(_env: &mut JNIEnv, foreign: &Self::ArgType) -> SignalJniResult<Self> {
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
    ) -> SignalJniResult<Self::StoredType> {
        let array = unsafe { env.get_array_elements(foreign, ReleaseMode::NoCopyBack)? };
        array
            .iter()
            .map(|&raw_handle| unsafe {
                (raw_handle as *const T)
                    .as_ref()
                    .ok_or(SignalJniError::NullHandle)
            })
            .collect()
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> &'storage [&'storage T] {
        &*stored
    }
}

impl<T: BridgeHandle> ResultTypeInfo<'_> for T {
    type ResultType = ObjectHandle;
    fn convert_into(self, _env: &mut JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(Box::into_raw(Box::new(self)) as ObjectHandle)
    }
}

impl<T: BridgeHandle> ResultTypeInfo<'_> for Option<T> {
    type ResultType = ObjectHandle;
    fn convert_into(self, env: &mut JNIEnv) -> SignalJniResult<Self::ResultType> {
        match self {
            Some(obj) => obj.convert_into(env),
            None => Ok(0),
        }
    }
}

impl<'a> ResultTypeInfo<'a> for ServiceId {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        Ok(env.byte_array_from_slice(&self.service_id_fixed_width_binary())?)
    }
}

impl<'a> ResultTypeInfo<'a> for Aci {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        ServiceId::from(self).convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for Pni {
    type ResultType = JByteArray<'a>;
    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        ServiceId::from(self).convert_into(env)
    }
}

impl<'a, T> SimpleArgTypeInfo<'a> for Serialized<T>
where
    T: FixedLengthBincodeSerializable
        + for<'x> serde::Deserialize<'x>
        + partial_default::PartialDefault,
{
    type ArgType = JByteArray<'a>;

    fn convert_from(env: &mut JNIEnv<'a>, foreign: &Self::ArgType) -> SignalJniResult<Self> {
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

impl<'a> SimpleArgTypeInfo<'a> for ServiceId {
    type ArgType = JByteArray<'a>;
    fn convert_from(env: &mut JNIEnv, foreign: &Self::ArgType) -> SignalJniResult<Self> {
        env.convert_byte_array(foreign)
            .ok()
            .and_then(|vec| vec.try_into().ok())
            .as_ref()
            .and_then(Self::parse_from_service_id_fixed_width_binary)
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument(
                    "invalid Service-Id-FixedWidthBinary".to_string(),
                )
                .into()
            })
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Aci {
    type ArgType = JByteArray<'a>;
    fn convert_from(env: &mut JNIEnv<'a>, foreign: &Self::ArgType) -> SignalJniResult<Self> {
        ServiceId::convert_from(env, foreign)?
            .try_into()
            .map_err(|_| SignalProtocolError::InvalidArgument("not an ACI".to_string()).into())
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Pni {
    type ArgType = JByteArray<'a>;
    fn convert_from(env: &mut JNIEnv<'a>, foreign: &Self::ArgType) -> SignalJniResult<Self> {
        ServiceId::convert_from(env, foreign)?
            .try_into()
            .map_err(|_| SignalProtocolError::InvalidArgument("not a PNI".to_string()).into())
    }
}

impl<'a> SimpleArgTypeInfo<'a> for bool {
    type ArgType = jboolean;
    fn convert_from(_: &mut JNIEnv<'a>, foreign: &Self::ArgType) -> SignalJniResult<Self> {
        Ok(*foreign != 0)
    }
}

impl<'a, T> ResultTypeInfo<'a> for Serialized<T>
where
    T: FixedLengthBincodeSerializable + serde::Serialize,
{
    type ResultType = JByteArray<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        let result = zkgroup::serialize(self.deref());
        result.convert_into(env)
    }
}

impl<'a> ResultTypeInfo<'a> for libsignal_net::cdsi::LookupResponse {
    type ResultType = JObject<'a>;

    fn convert_into(self, env: &mut JNIEnv<'a>) -> SignalJniResult<Self::ResultType> {
        let output_hashmap = new_object(
            env,
            jni_class_name!(java.util.HashMap),
            jni_args!(() -> void),
        )?;
        let output_jmap = JMap::from_env(env, &output_hashmap)?;

        let entry_class =
            env.find_class(jni_class_name!(org.signal.libsignal.net.CdsiLookupResponse::Entry))?;

        for entry in self.records {
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
            let e164 = AutoLocal::new(JObject::from(env.new_string(e164.to_string())?), env);

            let entry = AutoLocal::new(
                new_object(
                    env,
                    &entry_class,
                    jni_args!( (aci => [byte], pni => [byte]) -> void),
                )?,
                env,
            );

            output_jmap.put(env, &e164, &entry)?;
        }

        Ok(output_hashmap)
    }
}

/// Implementation of [`bridge_handle`](crate::support::bridge_handle) for JNI.
macro_rules! jni_bridge_handle {
    ( $typ:ty as false $(, $($_:tt)*)? ) => {};
    ( $typ:ty as $jni_name:ident ) => {
        impl jni::BridgeHandle for $typ {}
        jni_bridge_destroy!($typ as $jni_name);
    };
    ( $typ:ty ) => {
        // `paste!` turns the type back into an identifier.
        // We can't specify an identifier here because the main `bridge_handle!` accepts any type
        // and just passes it down.
        paste! {
            jni_bridge_handle!($typ as $typ);
        }
    };
}

macro_rules! trivial {
    ($typ:ty) => {
        impl SimpleArgTypeInfo<'_> for $typ {
            type ArgType = Self;
            fn convert_from(_env: &mut JNIEnv, foreign: &Self) -> SignalJniResult<Self> {
                Ok(*foreign)
            }
        }
        impl ResultTypeInfo<'_> for $typ {
            type ResultType = Self;
            fn convert_into(self, _env: &mut JNIEnv) -> SignalJniResult<Self> {
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
macro_rules! jni_arg_type {
    (u8) => {
        // Note: not a jbyte. It's better to preserve the signedness here.
        jni::jint
    };
    (u32) => {
        jni::jint
    };
    (Option<u32>) => {
        jni::jint
    };
    (u64) => {
        jni::jlong
    };
    (bool) => {
        jni::jboolean
    };
    (String) => {
        jni::JString<'local>
    };
    (Option<String>) => {
        jni::JString<'local>
    };
    (&[u8]) => {
        jni::JByteArray<'local>
    };
    (Option<&[u8]>) => {
        jni::JByteArray<'local>
    };
    (&mut [u8]) => {
        jni::JByteArray<'local>
    };
    (&[u8; $len:expr]) => {
        jni::JByteArray<'local>
    };
    (ServiceId) => {
        jni::JByteArray<'local>
    };
    (Aci) => {
        jni::JByteArray<'local>
    };
    (Pni) => {
        jni::JByteArray<'local>
    };
    (ServiceIdSequence<'_>) => {
        jni::JByteArray<'local>
    };
    (Timestamp) => {
        jni::jlong
    };
    (Uuid) => {
        jni::JavaUUID<'local>
    };
    (E164) => {
        jni::JString<'local>
    };
    (jni::CiphertextMessageRef) => {
        jni::JavaCiphertextMessage<'local>
    };
    (& [& $typ:ty]) => {
        jni::JLongArray<'local>
    };
    (&mut dyn $typ:ty) => {
        paste!(jni::[<Java $typ>]<'local>)
    };
    (& $typ:ty) => {
        jni::ObjectHandle
    };
    (&mut $typ:ty) => {
        jni::ObjectHandle
    };
    (Option<& $typ:ty>) => {
        jni::ObjectHandle
    };
    (Serialized<$typ:ident>) => {
        jni::JByteArray<'local>
    };

    (Ignored<$typ:ty>) => (jni::JObject<'local>);
}

/// Syntactically translates `bridge_fn` result types to JNI types for `cbindgen` and
/// `gen_java_decl.py`.
///
/// This is a syntactic transformation (because that's how Rust macros work), so new result types
/// will need to be added here directly even if they already implement [`ResultTypeInfo`]. The
/// default behavior is to assume we're returning an opaque handle to a Rust value.
///
/// The `'local` lifetime represents the lifetime of the JNI context.
macro_rules! jni_result_type {
    // These rules only match a single token for a Result's success type.
    // We can't use `:ty` because we need the resulting tokens to be matched recursively rather than
    // treated as a single unit, and we can't match multiple tokens because Rust's macros match
    // eagerly. Therefore, if you need to return a more complicated Result type, you'll have to add
    // another rule for its form.
    (Result<$typ:tt $(, $_:ty)?>) => {
        jni_result_type!($typ)
    };
    (Result<&$typ:tt $(, $_:ty)?>) => {
        jni_result_type!(&$typ)
    };
    (Result<Option<&$typ:tt> $(, $_:ty)?>) => {
        jni_result_type!(&$typ)
    };
    (Result<Option<$typ:tt<$($args:tt),+> > $(, $_:ty)?>) => {
        jni_result_type!($typ<$($args),+>)
    };
    (Result<$typ:tt<$($args:tt),+> $(, $_:ty)?>) => {
        jni_result_type!($typ<$($args),+>)
    };
    (()) => {
        ()
    };
    (bool) => {
        jni::jboolean
    };
    (u8) => {
        // Note: not a jbyte. It's better to preserve the signedness here.
        jni::jint
    };
    (i32) => {
        jni::jint
    };
    (u32) => {
        jni::jint
    };
    (Option<u32>) => {
        jni::jint
    };
    (u64) => {
        jni::jlong
    };
    (&str) => {
        jni::JString<'local>
    };
    (String) => {
        jni::JString<'local>
    };
    (Uuid) => {
        jni::JavaUUID<'local>
    };
    (Timestamp) => {
        jni::jlong
    };
    (&[u8]) => {
        jni::JByteArray<'local>
    };
    (Vec<u8>) => {
        jni::JByteArray<'local>
    };
    (Cds2Metrics) => {
        jni::JavaMap<'local>
    };
    ([u8; $len:expr]) => {
        jni::JByteArray<'local>
    };
    (ServiceId) => {
        jni::JByteArray<'local>
    };
    (Aci) => {
        jni::JByteArray<'local>
    };
    (Pni) => {
        jni::JByteArray<'local>
    };
    (LookupResponse) => {
        jni::JavaMap<'local>
    };
    (Option<$typ:tt>) => {
        jni_result_type!($typ)
    };
    (Option<$typ:tt<$($args:tt),+> >) => {
        jni_result_type!($typ<$($args),+>)
    };
    (CiphertextMessage) => {
        jni::JavaCiphertextMessage<'local>
    };
    (Serialized<$typ:ident>) => {
        jni::JByteArray<'local>
    };
    (Ignored<$typ:ty>) => {
        jni::JObject<'local>
    };
    ( $handle:ty ) => {
        jni::ObjectHandle
    };
}
