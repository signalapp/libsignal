//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::{JObject, JString};
use jni::sys::{jbyte, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use libsignal_protocol::*;
use paste::paste;
use std::convert::TryInto;
use std::ops::Deref;

use crate::io::InputStream;
use crate::support::{Array, FixedLengthBincodeSerializable, Serialized};

use super::*;

/// Converts arguments from their JNI form to their Rust form.
///
/// `ArgTypeInfo` has two required methods: `borrow` and `load_from`. The use site looks like this:
///
/// ```no_run
/// # use libsignal_bridge::jni::*;
/// # use jni_crate::JNIEnv;
/// # struct Foo;
/// # impl SimpleArgTypeInfo<'_> for Foo {
/// #     type ArgType = isize;
/// #     fn convert_from(env: &JNIEnv, foreign: isize) -> SignalJniResult<Self> { Ok(Foo) }
/// # }
/// # fn test(env: &JNIEnv, jni_arg: isize) -> SignalJniResult<()> {
/// let mut jni_arg_borrowed = Foo::borrow(env, jni_arg)?;
/// let rust_arg = Foo::load_from(env, &mut jni_arg_borrowed)?;
/// #     Ok(())
/// # }
/// ```
///
/// The `'context` lifetime allows for borrowed values to depend on the current JNI stack frame;
/// that is, they can be assured that referenced objects will not be GC'd out from under them.
///
/// `ArgTypeInfo` is used to implement the `bridge_fn` macro, but can also be used outside it.
///
/// If the Rust type can be directly loaded from `ArgType` with no local storage needed,
/// implement [`SimpleArgTypeInfo`] instead.
///
/// Implementers should also see the `jni_arg_type` macro in `convert.rs`.
pub trait ArgTypeInfo<'storage, 'context: 'storage>: Sized {
    /// The JNI form of the argument (e.g. `jni::jint`).
    type ArgType;
    /// Local storage for the argument (ideally borrowed rather than copied).
    type StoredType: 'storage;
    /// "Borrows" the data in `foreign`, usually to establish a local lifetime or owning type.
    fn borrow(env: &'context JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self::StoredType>;
    /// Loads the Rust value from the data that's been `stored` by [`borrow()`](Self::borrow()).
    fn load_from(env: &JNIEnv, stored: &'storage mut Self::StoredType) -> SignalJniResult<Self>;
}

/// A simpler interface for [`ArgTypeInfo`] for when no local storage is needed.
///
/// This trait is easier to use when writing JNI functions manually:
///
/// ```no_run
/// # use libsignal_bridge::jni::*;
/// # use jni_crate::objects::JObject;
/// # use jni_crate::JNIEnv;
/// # struct Foo;
/// impl<'a> SimpleArgTypeInfo<'a> for Foo {
///     type ArgType = JObject<'a>;
///     fn convert_from(env: &JNIEnv, foreign: JObject<'a>) -> SignalJniResult<Self> {
///         // ...
///         # Ok(Foo)
///     }
/// }
///
/// # fn test<'a>(env: &JNIEnv<'a>, jni_arg: JObject<'a>) -> SignalJniResult<()> {
/// let rust_arg = Foo::convert_from(env, jni_arg)?;
/// #     Ok(())
/// # }
/// ```
///
/// However, some types do need the full flexibility of `ArgTypeInfo`.
pub trait SimpleArgTypeInfo<'a>: Sized {
    /// The JNI form of the argument (e.g. `jint`).
    ///
    /// Must be [`Copy`] to help the compiler optimize out local storage.
    type ArgType: Copy + 'a;
    /// Converts the data in `foreign` to the Rust type.
    fn convert_from(env: &JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self>;
}

impl<'a, T> ArgTypeInfo<'a, 'a> for T
where
    T: SimpleArgTypeInfo<'a>,
{
    type ArgType = <Self as SimpleArgTypeInfo<'a>>::ArgType;
    type StoredType = Self::ArgType;
    fn borrow(_env: &'a JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self::StoredType> {
        Ok(foreign)
    }
    fn load_from(env: &JNIEnv, stored: &'a mut Self::StoredType) -> SignalJniResult<Self> {
        Self::convert_from(env, *stored)
    }
}

/// Converts result values from their Rust form to their FFI form.
///
/// `ResultTypeInfo` is used to implement the `bridge_fn` macro, but can also be used outside it.
///
/// ```no_run
/// # use libsignal_bridge::jni::*;
/// # use jni_crate::JNIEnv;
/// # use jni_crate::objects::JObject;
/// # struct Foo;
/// # impl ResultTypeInfo for Foo {
/// #     type ResultType = isize;
/// #     fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<isize> { Ok(1) }
/// #     fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject { JObject::null() }
/// # }
/// # fn test<'a>(env: &JNIEnv<'a>) -> SignalJniResult<()> {
/// #     let rust_result = Foo;
/// #     let jni_result = rust_result.convert_into(env)?;
/// #     Ok(())
/// # }
/// ```
///
/// Implementers should also see the `jni_result_type` macro in `convert.rs`.
pub trait ResultTypeInfo: Sized {
    /// The JNI form of the result (e.g. `jint`).
    type ResultType;
    /// Converts the data in `self` to the JNI type, similar to `try_into()`.
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType>;
    /// Converts the data in `self` into a JObject type for preserving while popping the local
    /// frame.
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject;
}

/// Supports values `0..=Integer.MAX_VALUE`.
///
/// Negative `int` values are *not* reinterpreted as large `u32` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u32`.
impl<'a> SimpleArgTypeInfo<'a> for u32 {
    type ArgType = jint;
    fn convert_from(_env: &JNIEnv, foreign: jint) -> SignalJniResult<Self> {
        if foreign < 0 {
            return Err(SignalJniError::IntegerOverflow(format!(
                "{} to u32",
                foreign
            )));
        }
        Ok(foreign as u32)
    }
}

/// Supports values `0..=Integer.MAX_VALUE`. Negative values are considered `None`.
///
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `Option<u32>`.
impl<'a> SimpleArgTypeInfo<'a> for Option<u32> {
    type ArgType = jint;
    fn convert_from(env: &JNIEnv, foreign: jint) -> SignalJniResult<Self> {
        if foreign < 0 {
            Ok(None)
        } else {
            u32::convert_from(env, foreign).map(Some)
        }
    }
}

/// Reinterprets the bits of the Java `long` as a `u64`.
impl<'a> SimpleArgTypeInfo<'a> for u64 {
    type ArgType = jlong;
    fn convert_from(_env: &JNIEnv, foreign: jlong) -> SignalJniResult<Self> {
        Ok(foreign as u64)
    }
}

/// Supports values `0..=Long.MAX_VALUE`.
///
/// Negative `long` values are *not* reinterpreted as large `u64` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u64`.
impl<'a> SimpleArgTypeInfo<'a> for crate::protocol::Timestamp {
    type ArgType = jlong;
    fn convert_from(_env: &JNIEnv, foreign: jlong) -> SignalJniResult<Self> {
        if foreign < 0 {
            return Err(SignalJniError::IntegerOverflow(format!(
                "{} to Timestamp (u64)",
                foreign
            )));
        }
        Ok(Self::from_millis(foreign as u64))
    }
}

/// Supports values `0..=Long.MAX_VALUE`.
///
/// Negative `long` values are *not* reinterpreted as large `u64` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u64`.
impl<'a> SimpleArgTypeInfo<'a> for crate::zkgroup::Timestamp {
    type ArgType = jlong;
    fn convert_from(_env: &JNIEnv, foreign: jlong) -> SignalJniResult<Self> {
        if foreign < 0 {
            return Err(SignalJniError::IntegerOverflow(format!(
                "{} to Timestamp (u64)",
                foreign
            )));
        }
        Ok(Self::from_seconds(foreign as u64))
    }
}

/// Supports all valid byte values `0..=255`.
impl<'a> SimpleArgTypeInfo<'a> for u8 {
    type ArgType = jint;
    fn convert_from(_env: &JNIEnv, foreign: jint) -> SignalJniResult<Self> {
        match u8::try_from(foreign) {
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
    fn convert_from(env: &JNIEnv, foreign: JString<'a>) -> SignalJniResult<Self> {
        Ok(env.get_string(foreign)?.into())
    }
}

impl<'a> SimpleArgTypeInfo<'a> for Option<String> {
    type ArgType = JString<'a>;
    fn convert_from(env: &JNIEnv, foreign: JString<'a>) -> SignalJniResult<Self> {
        if foreign.is_null() {
            Ok(None)
        } else {
            String::convert_from(env, foreign).map(Some)
        }
    }
}

impl<'a> SimpleArgTypeInfo<'a> for uuid::Uuid {
    type ArgType = JObject<'a>;
    fn convert_from(env: &JNIEnv, foreign: JObject<'a>) -> SignalJniResult<Self> {
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

impl<'storage, 'context: 'storage> ArgTypeInfo<'storage, 'context> for &'storage [u8] {
    type ArgType = jbyteArray;
    type StoredType = AutoArray<'context, 'context, jbyte>;
    fn borrow(env: &'context JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self::StoredType> {
        Ok(env.get_byte_array_elements(foreign, ReleaseMode::NoCopyBack)?)
    }
    fn load_from(
        _env: &JNIEnv,
        stored: &'storage mut Self::StoredType,
    ) -> SignalJniResult<&'storage [u8]> {
        Ok(unsafe {
            std::slice::from_raw_parts(stored.as_ptr() as *const u8, stored.size()? as usize)
        })
    }
}

impl<'storage, 'context: 'storage> ArgTypeInfo<'storage, 'context> for Option<&'storage [u8]> {
    type ArgType = jbyteArray;
    type StoredType = Option<AutoArray<'context, 'context, jbyte>>;
    fn borrow(env: &'context JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self::StoredType> {
        if foreign.is_null() {
            Ok(None)
        } else {
            <&'storage [u8]>::borrow(env, foreign).map(Some)
        }
    }
    fn load_from(
        env: &JNIEnv,
        stored: &'storage mut Self::StoredType,
    ) -> SignalJniResult<Option<&'storage [u8]>> {
        stored
            .as_mut()
            .map(|s| <&'storage [u8]>::load_from(env, s))
            .transpose()
    }
}

impl<'storage, 'context: 'storage> ArgTypeInfo<'storage, 'context> for &'storage mut [u8] {
    type ArgType = jbyteArray;
    type StoredType = AutoArray<'context, 'context, jbyte>;
    fn borrow(env: &'context JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self::StoredType> {
        Ok(env.get_byte_array_elements(foreign, ReleaseMode::CopyBack)?)
    }
    fn load_from(
        _env: &JNIEnv,
        stored: &'storage mut Self::StoredType,
    ) -> SignalJniResult<&'storage mut [u8]> {
        Ok(unsafe {
            std::slice::from_raw_parts_mut(stored.as_ptr() as *mut u8, stored.size()? as usize)
        })
    }
}

macro_rules! store {
    ($name:ident) => {
        paste! {
            impl<'storage, 'context: 'storage> ArgTypeInfo<'storage, 'context>
                for &'storage mut dyn $name
            {
                type ArgType = JObject<'context>;
                type StoredType = [<Jni $name>]<'context>;
                fn borrow(
                    env: &'context JNIEnv,
                    store: Self::ArgType,
                ) -> SignalJniResult<Self::StoredType> {
                    Self::StoredType::new(env, store)
                }
                fn load_from(
                    _env: &JNIEnv,
                    stored: &'storage mut Self::StoredType,
                ) -> SignalJniResult<Self> {
                    Ok(stored)
                }
            }
        }
    };
}

impl<'a> SimpleArgTypeInfo<'a> for Context {
    type ArgType = JObject<'a>;
    fn convert_from(_env: &JNIEnv, foreign: JObject<'a>) -> SignalJniResult<Self> {
        if foreign.is_null() {
            Ok(None)
        } else {
            Err(SignalJniError::BadJniParameter(
                "<context> (only 'null' contexts are supported)",
            ))
        }
    }
}

store!(IdentityKeyStore);
store!(PreKeyStore);
store!(SenderKeyStore);
store!(SessionStore);
store!(SignedPreKeyStore);
store!(KyberPreKeyStore);
store!(InputStream);

/// A translation from a Java interface where the implementing class wraps the Rust handle.
impl<'a> SimpleArgTypeInfo<'a> for CiphertextMessageRef<'a> {
    type ArgType = JavaCiphertextMessage<'a>;
    fn convert_from(env: &JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self> {
        fn native_handle_from_message<'a, T: 'static>(
            env: &JNIEnv,
            foreign: JavaCiphertextMessage<'a>,
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
impl ResultTypeInfo for crate::cds2::Cds2Metrics {
    type ResultType = jobject;

    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        let map_args = jni_args!(() -> void);
        let jobj = env.new_object(
            env.find_class(jni_class_name!(java.util.HashMap))?,
            map_args.sig,
            &map_args.args,
        )?;
        // Fully-qualified so that we don't need to conditionalize the `use`.
        let jmap = jni::objects::JMap::from_env(env, jobj)?;

        let long_class = env.find_class(jni_class_name!(java.lang.Long))?;
        for (k, v) in self.0 {
            let args = jni_args!((v => long) -> void);
            jmap.put(
                String::convert_into_jobject(&k.convert_into(env)),
                env.new_object(long_class, args.sig, &args.args)?,
            )?;
        }
        Ok(jmap.into_inner())
    }

    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl ResultTypeInfo for bool {
    type ResultType = jboolean;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(if self { JNI_TRUE } else { JNI_FALSE })
    }
    fn convert_into_jobject(_signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        JObject::null()
    }
}

/// Supports all valid byte values `0..=255`.
impl ResultTypeInfo for u8 {
    type ResultType = jint;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(self as jint)
    }
    fn convert_into_jobject(_signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        JObject::null()
    }
}

/// Reinterprets the bits of the `u32` as a Java `int`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `u32`.
impl ResultTypeInfo for u32 {
    type ResultType = jint;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self as jint)
    }
    fn convert_into_jobject(_signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        JObject::null()
    }
}

/// Reinterprets the bits of the `u32` as a Java `int`. Returns `-1` for `None`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `Option<u32>`.
impl ResultTypeInfo for Option<u32> {
    type ResultType = jint;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self.unwrap_or(u32::MAX) as jint)
    }
    fn convert_into_jobject(_signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        JObject::null()
    }
}

/// Reinterprets the bits of the `u64` as a Java `long`.
impl ResultTypeInfo for u64 {
    type ResultType = jlong;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self as jlong)
    }
    fn convert_into_jobject(_signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        JObject::null()
    }
}

/// Reinterprets the bits of the timestamp's `u64` as a Java `long`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `Timestamp`.
impl ResultTypeInfo for crate::protocol::Timestamp {
    type ResultType = jlong;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self.as_millis() as jlong)
    }
    fn convert_into_jobject(_signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        JObject::null()
    }
}

/// Reinterprets the bits of the timestamp's `u64` as a Java `long`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `Timestamp`.
impl ResultTypeInfo for crate::zkgroup::Timestamp {
    type ResultType = jlong;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self.as_seconds() as jlong)
    }
    fn convert_into_jobject(_signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        JObject::null()
    }
}

impl ResultTypeInfo for String {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        self.deref().convert_into(env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl ResultTypeInfo for Option<String> {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        self.as_deref().convert_into(env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl ResultTypeInfo for &str {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(env.new_string(self)?.into_inner())
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl ResultTypeInfo for Option<&str> {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        match self {
            Some(s) => s.convert_into(env),
            None => Ok(std::ptr::null_mut()),
        }
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl ResultTypeInfo for &[u8] {
    type ResultType = jbyteArray;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(env.byte_array_from_slice(self)?)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl ResultTypeInfo for Option<&[u8]> {
    type ResultType = jbyteArray;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        match self {
            Some(s) => s.convert_into(env),
            None => Ok(std::ptr::null_mut()),
        }
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl ResultTypeInfo for Vec<u8> {
    type ResultType = jbyteArray;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        self.deref().convert_into(env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl ResultTypeInfo for Option<Vec<u8>> {
    type ResultType = jbyteArray;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        self.as_deref().convert_into(env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl<'storage, 'context: 'storage, const LEN: usize> ArgTypeInfo<'storage, 'context>
    for &'storage [u8; LEN]
{
    type ArgType = jbyteArray;
    type StoredType = AutoArray<'context, 'context, jbyte>;
    fn borrow(env: &'context JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self::StoredType> {
        Ok(env.get_byte_array_elements(foreign, ReleaseMode::NoCopyBack)?)
    }
    fn load_from(
        _env: &JNIEnv,
        stored: &'storage mut Self::StoredType,
    ) -> SignalJniResult<&'storage [u8; LEN]> {
        let slice = unsafe {
            std::slice::from_raw_parts(stored.as_ptr() as *const u8, stored.size()? as usize)
        };
        slice
            .try_into()
            .map_err(|_| SignalJniError::IncorrectArrayLength {
                expected: LEN,
                actual: slice.len(),
            })
    }
}

impl<const LEN: usize> ResultTypeInfo for [u8; LEN] {
    type ResultType = jbyteArray;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        self.as_ref().convert_into(env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl ResultTypeInfo for uuid::Uuid {
    type ResultType = jobject;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        let uuid_class = env.find_class(jni_class_name!(java.util.UUID))?;
        let uuid_bytes: [u8; 16] = *self.as_bytes();
        let (msb, lsb) = uuid_bytes.split_at(8);
        let args = jni_args!((
            jlong::from_be_bytes(msb.try_into().expect("correct length")) => long,
            jlong::from_be_bytes(lsb.try_into().expect("correct length")) => long,
        ) -> void);
        Ok(*env.new_object(uuid_class, args.sig, &args.args)?)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

/// A translation to a Java interface where the implementing class wraps the Rust handle.
impl ResultTypeInfo for CiphertextMessage {
    type ResultType = JavaReturnCiphertextMessage;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        let obj = match self {
            CiphertextMessage::SignalMessage(m) => jobject_from_native_handle(
                env,
                jni_class_name!(org.signal.libsignal.protocol.message.SignalMessage),
                m.convert_into(env)?,
            ),
            CiphertextMessage::PreKeySignalMessage(m) => jobject_from_native_handle(
                env,
                jni_class_name!(org.signal.libsignal.protocol.message.PreKeySignalMessage),
                m.convert_into(env)?,
            ),
            CiphertextMessage::SenderKeyMessage(m) => jobject_from_native_handle(
                env,
                jni_class_name!(org.signal.libsignal.protocol.message.SenderKeyMessage),
                m.convert_into(env)?,
            ),
            CiphertextMessage::PlaintextContent(m) => jobject_from_native_handle(
                env,
                jni_class_name!(org.signal.libsignal.protocol.message.PlaintextContent),
                m.convert_into(env)?,
            ),
        };

        Ok(obj?.into_inner())
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, SignalProtocolError> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, device_transfer::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, attest::hsm_enclave::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, attest::sgx_session::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, signal_pin::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

#[cfg(feature = "signal-media")]
impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, signal_media::sanitize::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, signal_crypto::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, zkgroup::ZkGroupVerificationFailure> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, zkgroup::ZkGroupDeserializationFailure> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, usernames::UsernameError> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, usernames::UsernameLinkError> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for SignalJniResult<T> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <T as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

/// Used when returning an optional buffer, since the conversion to a Java array might also fail.
impl ResultTypeInfo for Option<SignalJniResult<jbyteArray>> {
    type ResultType = <Option<jbyteArray> as ResultTypeInfo>::ResultType;
    fn convert_into(self, env: &jni::JNIEnv) -> SignalJniResult<Self::ResultType> {
        self.transpose()?.convert_into(env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        <Option<jbyteArray> as ResultTypeInfo>::convert_into_jobject(signal_jni_result)
    }
}

impl ResultTypeInfo for Option<jobject> {
    type ResultType = jobject;
    fn convert_into(self, _env: &jni::JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(self.unwrap_or(std::ptr::null_mut()))
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

/// A marker for Rust objects exposed as opaque handles (pointers converted to `jlong`).
///
/// When we do this, we hand the lifetime over to the app. Since we don't know how long the object
/// will be kept alive, it can't (safely) have references to anything with a non-static lifetime.
pub trait BridgeHandle: 'static {}

impl<'a, T: BridgeHandle> SimpleArgTypeInfo<'a> for &T {
    type ArgType = ObjectHandle;
    fn convert_from(_env: &JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self> {
        Ok(unsafe { native_handle_cast(foreign) }?)
    }
}

impl<'a, T: BridgeHandle> SimpleArgTypeInfo<'a> for Option<&T> {
    type ArgType = ObjectHandle;
    fn convert_from(env: &JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self> {
        if foreign == 0 {
            Ok(None)
        } else {
            <&T>::convert_from(env, foreign).map(Some)
        }
    }
}

impl<'a, T: BridgeHandle> SimpleArgTypeInfo<'a> for &mut T {
    type ArgType = ObjectHandle;
    fn convert_from(_env: &JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self> {
        unsafe { native_handle_cast(foreign) }
    }
}

impl<'storage, 'context: 'storage, T: BridgeHandle> ArgTypeInfo<'storage, 'context>
    for &'storage [&'storage T]
{
    type ArgType = jlongArray;
    type StoredType = Vec<&'storage T>;
    fn borrow(env: &'context JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self::StoredType> {
        let array = env.get_long_array_elements(foreign, ReleaseMode::NoCopyBack)?;
        let len = array.size()? as usize;
        let slice = unsafe { std::slice::from_raw_parts(array.as_ptr(), len) };
        slice
            .iter()
            .map(|&raw_handle| unsafe {
                (raw_handle as *const T)
                    .as_ref()
                    .ok_or(SignalJniError::NullHandle)
            })
            .collect()
    }
    fn load_from(
        _env: &JNIEnv,
        stored: &'storage mut Self::StoredType,
    ) -> SignalJniResult<&'storage [&'storage T]> {
        Ok(&*stored)
    }
}

impl<T: BridgeHandle> ResultTypeInfo for T {
    type ResultType = ObjectHandle;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(Box::into_raw(Box::new(self)) as ObjectHandle)
    }
    fn convert_into_jobject(_signal_jni_result: &SignalJniResult<Self::ResultType>) -> JavaObject {
        JavaObject::null()
    }
}

impl<T: BridgeHandle> ResultTypeInfo for Option<T> {
    type ResultType = ObjectHandle;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        match self {
            Some(obj) => obj.convert_into(env),
            None => Ok(0),
        }
    }
    fn convert_into_jobject(_signal_jni_result: &SignalJniResult<Self::ResultType>) -> JavaObject {
        JavaObject::null()
    }
}

impl ResultTypeInfo for ServiceId {
    type ResultType = jbyteArray;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(env.byte_array_from_slice(&self.service_id_fixed_width_binary())?)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl ResultTypeInfo for Aci {
    type ResultType = jbyteArray;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        ServiceId::from(self).convert_into(env)
    }
    fn convert_into_jobject(signal_jni_result: &SignalJniResult<Self::ResultType>) -> JObject {
        signal_jni_result
            .as_ref()
            .map_or(JObject::null(), |&jobj| JObject::from(jobj))
    }
}

impl<T> SimpleArgTypeInfo<'_> for Serialized<T>
where
    T: FixedLengthBincodeSerializable + for<'a> serde::Deserialize<'a>,
{
    type ArgType = jbyteArray;

    fn convert_from(env: &jni_crate::JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self> {
        let borrowed_array = env.get_byte_array_elements(foreign, ReleaseMode::NoCopyBack)?;
        let len = borrowed_array.size()? as usize;
        assert!(
            len == T::Array::LEN,
            "{} should have been validated on creation",
            std::any::type_name::<T>()
        );
        // Convert from i8 to u8.
        let bytes =
            unsafe { std::slice::from_raw_parts(borrowed_array.as_ptr() as *const u8, len) };
        let result: T = bincode::deserialize(bytes).unwrap_or_else(|_| {
            panic!(
                "{} should have been validated on creation",
                std::any::type_name::<T>()
            )
        });
        Ok(Serialized::from(result))
    }
}

impl SimpleArgTypeInfo<'_> for ServiceId {
    type ArgType = jbyteArray;
    fn convert_from(env: &JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self> {
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

impl SimpleArgTypeInfo<'_> for Aci {
    type ArgType = jbyteArray;
    fn convert_from(env: &JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self> {
        ServiceId::convert_from(env, foreign)?
            .try_into()
            .map_err(|_| SignalProtocolError::InvalidArgument("not an ACI".to_string()).into())
    }
}

impl SimpleArgTypeInfo<'_> for Pni {
    type ArgType = jbyteArray;
    fn convert_from(env: &JNIEnv, foreign: Self::ArgType) -> SignalJniResult<Self> {
        ServiceId::convert_from(env, foreign)?
            .try_into()
            .map_err(|_| SignalProtocolError::InvalidArgument("not a PNI".to_string()).into())
    }
}

impl<T> ResultTypeInfo for Serialized<T>
where
    T: FixedLengthBincodeSerializable + serde::Serialize,
{
    type ResultType = jbyteArray;

    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        let result = bincode::serialize(self.deref()).expect("can always serialize a value");
        result.convert_into(env)
    }

    fn convert_into_jobject(
        signal_jni_result: &SignalJniResult<Self::ResultType>,
    ) -> jni_crate::objects::JObject {
        Vec::<u8>::convert_into_jobject(signal_jni_result)
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
        impl<'a> SimpleArgTypeInfo<'a> for $typ {
            type ArgType = Self;
            fn convert_from(_env: &JNIEnv, foreign: Self) -> SignalJniResult<Self> {
                Ok(foreign)
            }
        }
        impl ResultTypeInfo for $typ {
            type ResultType = Self;
            fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self> {
                Ok(self)
            }
            fn convert_into_jobject(
                _signal_jni_result: &SignalJniResult<Self::ResultType>,
            ) -> JObject {
                JObject::null()
            }
        }
    };
}

macro_rules! trivial_jobject {
    ($typ:ty) => {
        impl<'a> SimpleArgTypeInfo<'a> for $typ {
            type ArgType = Self;
            fn convert_from(_env: &JNIEnv, foreign: Self) -> SignalJniResult<Self> {
                Ok(foreign)
            }
        }
        impl ResultTypeInfo for $typ {
            type ResultType = Self;
            fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self> {
                Ok(self)
            }
            fn convert_into_jobject(
                signal_jni_result: &SignalJniResult<Self::ResultType>,
            ) -> JObject {
                signal_jni_result
                    .as_ref()
                    .map_or(JObject::null(), |&jobj| JObject::from(jobj))
            }
        }
    };
}

trivial!(i32);
trivial_jobject!(jbyteArray);
trivial!(());

/// Syntactically translates `bridge_fn` argument types to JNI types for `cbindgen` and
/// `gen_java_decl.py`.
///
/// This is a syntactic transformation (because that's how Rust macros work), so new argument types
/// will need to be added here directly even if they already implement [`ArgTypeInfo`]. The default
/// behavior for references is to assume they're opaque handles to Rust values; the default
/// behavior for `&mut dyn Foo` is to assume there's a type called `jni::JavaFoo`.
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
    (String) => {
        jni::JString
    };
    (Option<String>) => {
        jni::JString
    };
    (&[u8]) => {
        jni::jbyteArray
    };
    (Option<&[u8]>) => {
        jni::jbyteArray
    };
    (&mut [u8]) => {
        jni::jbyteArray
    };
    (&[u8; $len:expr]) => {
        jni::jbyteArray
    };
    (ServiceId) => {
        jni::jbyteArray
    };
    (Aci) => {
        jni::jbyteArray
    };
    (Pni) => {
        jni::jbyteArray
    };
    (Context) => {
        jni::JObject
    };
    (Timestamp) => {
        jni::jlong
    };
    (Uuid) => {
        jni::JavaUUID
    };
    (jni::CiphertextMessageRef) => {
        jni::JavaCiphertextMessage
    };
    (& [& $typ:ty]) => {
        jni::jlongArray
    };
    (&mut dyn $typ:ty) => {
        paste!(jni::[<Java $typ>])
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
        jni::jbyteArray
    };
}

/// Syntactically translates `bridge_fn` result types to JNI types for `cbindgen` and
/// `gen_java_decl.py`.
///
/// This is a syntactic transformation (because that's how Rust macros work), so new result types
/// will need to be added here directly even if they already implement [`ResultTypeInfo`]. The
/// default behavior is to assume we're returning an opaque handle to a Rust value.
macro_rules! jni_result_type {
    // These rules only match a single token for a Result's success type.
    // We can't use `:ty` because we need the resulting tokens to be matched recursively rather than
    // treated as a single unit, and we can't match multiple tokens because Rust's macros match
    // eagerly. Therefore, if you need to return a more complicated Result type, you'll have to add // another rule for its form.
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
        jni::jstring
    };
    (String) => {
        jni::jstring
    };
    (Uuid) => {
        jni::JavaReturnUUID
    };
    (Timestamp) => {
        jni::jlong
    };
    (&[u8]) => {
        jni::jbyteArray
    };
    (Vec<u8>) => {
        jni::jbyteArray
    };
    (Cds2Metrics) => {
        jni::JavaReturnMap
    };
    ([u8; $len:expr]) => {
        jni::jbyteArray
    };
    (ServiceId) => {
        jni::jbyteArray
    };
    (Aci) => {
        jni::jbyteArray
    };
    (Pni) => {
        jni::jbyteArray
    };
    (Option<$typ:tt>) => {
        jni_result_type!($typ)
    };
    (Option<$typ:tt<$($args:tt),+> >) => {
        jni_result_type!($typ<$($args),+>)
    };
    (CiphertextMessage) => {
        jni::JavaReturnCiphertextMessage
    };
    (Serialized<$typ:ident>) => {
        jni::jbyteArray
    };
    ( $handle:ty ) => {
        jni::ObjectHandle
    };
}
