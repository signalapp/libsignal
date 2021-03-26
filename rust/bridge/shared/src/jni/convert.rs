//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use jni::objects::JString;
use jni::sys::{jbyte, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use libsignal_protocol::*;
use paste::paste;
use std::borrow::Cow;
use std::convert::TryInto;
use std::ops::Deref;

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
/// # struct Foo;
/// # impl ResultTypeInfo for Foo {
/// #     type ResultType = isize;
/// #     fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<isize> { Ok(1) }
/// # }
/// # fn test<'a>(env: &JNIEnv<'a>) -> SignalJniResult<()> {
/// #     let rust_result = Foo;
/// let jni_result = rust_result.convert_into(env)?;
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
}

/// Supports values `0..=Integer.MAX_VALUE`.
///
/// Negative `int` values are *not* reinterpreted as large `u32` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u32`.
impl<'a> SimpleArgTypeInfo<'a> for u32 {
    type ArgType = jint;
    fn convert_from(_env: &JNIEnv, foreign: jint) -> SignalJniResult<Self> {
        jint_to_u32(foreign)
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

/// Supports values `0..=Long.MAX_VALUE`.
///
/// Negative `long` values are *not* reinterpreted as large `u64` values.
/// Note that this is different from the implementation of [`ResultTypeInfo`] for `u64`.
impl<'a> SimpleArgTypeInfo<'a> for u64 {
    type ArgType = jlong;
    fn convert_from(_env: &JNIEnv, foreign: jlong) -> SignalJniResult<Self> {
        jlong_to_u64(foreign)
    }
}

/// Supports all valid byte values `0..=255`.
impl<'a> SimpleArgTypeInfo<'a> for u8 {
    type ArgType = jint;
    fn convert_from(_env: &JNIEnv, foreign: jint) -> SignalJniResult<Self> {
        jint_to_u8(foreign)
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
        check_jobject_type(env, foreign, "java/util/UUID")?;
        let sig = jni_signature!(() -> long);
        let msb: jlong = call_method_checked(env, foreign, "getMostSignificantBits", sig, &[])?;
        let lsb: jlong = call_method_checked(env, foreign, "getLeastSignificantBits", sig, &[])?;

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
                for &'storage mut dyn libsignal_protocol::$name
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
                let handle = call_method_checked(
                    env,
                    foreign,
                    "nativeHandle",
                    jni_signature!(() -> long),
                    &[],
                )?;
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
                "org/whispersystems/libsignal/protocol/SignalMessage",
                Self::SignalMessage,
            )
            .transpose()
        })
        .or_else(|| {
            native_handle_from_message(
                env,
                foreign,
                "org/whispersystems/libsignal/protocol/PreKeySignalMessage",
                Self::PreKeySignalMessage,
            )
            .transpose()
        })
        .or_else(|| {
            native_handle_from_message(
                env,
                foreign,
                "org/whispersystems/libsignal/protocol/SenderKeyMessage",
                Self::SenderKeyMessage,
            )
            .transpose()
        })
        .unwrap_or(Err(SignalJniError::BadJniParameter("CiphertextMessage")))
    }
}

impl ResultTypeInfo for bool {
    type ResultType = jboolean;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(if self { JNI_TRUE } else { JNI_FALSE })
    }
}

/// Supports all valid byte values `0..=255`.
impl ResultTypeInfo for u8 {
    type ResultType = jint;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(self as jint)
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
}

/// Reinterprets the bits of the `u64` as a Java `long`.
///
/// Note that this is different from the implementation of [`ArgTypeInfo`] for `u64`.
impl ResultTypeInfo for u64 {
    type ResultType = jlong;
    fn convert_into(self, _env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        // Note that we don't check bounds here.
        Ok(self as jlong)
    }
}

impl ResultTypeInfo for String {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        self.deref().convert_into(env)
    }
}

impl ResultTypeInfo for Option<String> {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        self.as_deref().convert_into(env)
    }
}

impl ResultTypeInfo for &str {
    type ResultType = jstring;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(env.new_string(self)?.into_inner())
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
}

impl ResultTypeInfo for uuid::Uuid {
    type ResultType = jobject;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        let uuid_class = env.find_class("java/util/UUID")?;
        let uuid_bytes: [u8; 16] = *self.as_bytes();
        let ctor_args = [
            JValue::from(jlong::from_be_bytes(
                uuid_bytes[..8].try_into().expect("correct length"),
            )),
            JValue::from(jlong::from_be_bytes(
                uuid_bytes[8..].try_into().expect("correct length"),
            )),
        ];

        Ok(*env.new_object(uuid_class, "(JJ)V", &ctor_args)?)
    }
}

/// A translation to a Java interface where the implementing class wraps the Rust handle.
impl ResultTypeInfo for CiphertextMessage {
    type ResultType = JavaReturnCiphertextMessage;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        let obj = match self {
            CiphertextMessage::SignalMessage(m) => jobject_from_native_handle(
                &env,
                "org/whispersystems/libsignal/protocol/SignalMessage",
                box_object::<SignalMessage>(Ok(m))?,
            ),
            CiphertextMessage::PreKeySignalMessage(m) => jobject_from_native_handle(
                &env,
                "org/whispersystems/libsignal/protocol/PreKeySignalMessage",
                box_object::<PreKeySignalMessage>(Ok(m))?,
            ),
            CiphertextMessage::SenderKeyMessage(m) => jobject_from_native_handle(
                &env,
                "org/whispersystems/libsignal/protocol/SenderKeyMessage",
                box_object::<SenderKeyMessage>(Ok(m))?,
            ),
        };

        Ok(obj?.into_inner())
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, SignalProtocolError> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, device_transfer::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, signal_crypto::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for SignalJniResult<T> {
    type ResultType = T::ResultType;
    fn convert_into(self, env: &JNIEnv) -> SignalJniResult<Self::ResultType> {
        T::convert_into(self?, env)
    }
}

impl<T> ResultTypeInfo for Option<SignalJniResult<T>>
where
    Option<T>: ResultTypeInfo,
{
    type ResultType = <Option<T> as ResultTypeInfo>::ResultType;
    fn convert_into(self, env: &jni::JNIEnv) -> SignalJniResult<Self::ResultType> {
        self.transpose()?.convert_into(env)
    }
}

impl ResultTypeInfo for Option<jobject> {
    type ResultType = jobject;
    fn convert_into(self, _env: &jni::JNIEnv) -> SignalJniResult<Self::ResultType> {
        Ok(self.unwrap_or(std::ptr::null_mut()))
    }
}

impl crate::support::Env for &'_ JNIEnv<'_> {
    type Buffer = SignalJniResult<jbyteArray>;
    fn buffer<'a, T: Into<Cow<'a, [u8]>>>(self, input: T) -> Self::Buffer {
        to_jbytearray(&self, Ok(input.into()))
    }
}

/// Implementation of [`bridge_handle`](crate::support::bridge_handle) for JNI.
macro_rules! jni_bridge_handle {
    ( $typ:ty as false $(, $($_:tt)*)? ) => {};
    ( $typ:ty as $jni_name:ident ) => {
        impl<'a> jni::SimpleArgTypeInfo<'a> for &$typ {
            type ArgType = jni::ObjectHandle;
            fn convert_from(
                _env: &jni::JNIEnv,
                foreign: Self::ArgType,
            ) -> jni::SignalJniResult<Self> {
                Ok(unsafe { jni::native_handle_cast(foreign) }?)
            }
        }
        impl<'a> jni::SimpleArgTypeInfo<'a> for Option<&$typ> {
            type ArgType = jni::ObjectHandle;
            fn convert_from(
                env: &jni::JNIEnv,
                foreign: Self::ArgType,
            ) -> jni::SignalJniResult<Self> {
                if foreign == 0 {
                    Ok(None)
                } else {
                    <&$typ>::convert_from(env, foreign).map(Some)
                }
            }
        }
        impl<'a> jni::SimpleArgTypeInfo<'a> for &mut $typ {
            type ArgType = jni::ObjectHandle;
            fn convert_from(
                _env: &jni::JNIEnv,
                foreign: Self::ArgType,
            ) -> jni::SignalJniResult<Self> {
                Ok(unsafe { jni::native_handle_cast(foreign) }?)
            }
        }

        impl<'storage, 'context: 'storage> jni::ArgTypeInfo<'storage, 'context>
            for &'storage [&'storage $typ]
        {
            type ArgType = jni::jlongArray;
            type StoredType = jni::AutoArray<'context, 'context, jni::jlong>;
            fn borrow(
                env: &'context jni::JNIEnv,
                foreign: Self::ArgType,
            ) -> jni::SignalJniResult<Self::StoredType> {
                Ok(env.get_long_array_elements(foreign, jni::ReleaseMode::NoCopyBack)?)
            }
            fn load_from(
                _env: &jni::JNIEnv,
                stored: &'storage mut Self::StoredType,
            ) -> jni::SignalJniResult<&'storage [&'storage $typ]> {
                let len = stored.size()? as usize;
                let slice_of_pointers = unsafe {
                    std::slice::from_raw_parts(stored.as_ptr() as *const *const $typ, len)
                };
                if slice_of_pointers.contains(&std::ptr::null()) {
                    return Err(jni::SignalJniError::NullHandle);
                }

                Ok(unsafe { std::slice::from_raw_parts(stored.as_ptr() as *const &$typ, len) })
            }
        }
        impl jni::ResultTypeInfo for $typ {
            type ResultType = jni::ObjectHandle;
            fn convert_into(self, _env: &jni::JNIEnv) -> jni::SignalJniResult<Self::ResultType> {
                jni::box_object(Ok(self))
            }
        }
        impl jni::ResultTypeInfo for Option<$typ> {
            type ResultType = jni::ObjectHandle;
            fn convert_into(self, env: &jni::JNIEnv) -> jni::SignalJniResult<Self::ResultType> {
                match self {
                    Some(obj) => obj.convert_into(env),
                    None => Ok(0),
                }
            }
        }
        jni_bridge_destroy!($typ as $jni_name);
    };
    ( $typ:ty ) => {
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
        }
    };
}

trivial!(i32);
trivial!(jbyteArray);
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
    (Context) => {
        jni::JObject
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
    (Result<$typ:tt<$($args:tt),+> $(, $_:ty)?>) => {
        jni_result_type!($typ<$($args)+>)
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
    (u64) => {
        jni::jlong
    };
    (Option<u32>) => {
        jni::jint
    };
    (&str) => {
        jni::jstring
    };
    (String) => {
        jni::jstring
    };
    (Option<String>) => {
        jni::jstring
    };
    (Option<&str>) => {
        jni::jstring
    };
    (Uuid) => {
        jni::JavaReturnUUID
    };
    (Vec<u8>) => {
        jni::jbyteArray
    };
    (CiphertextMessage) => {
        jni::JavaReturnCiphertextMessage
    };
    ( $typ:ty ) => {
        jni::ObjectHandle
    };
}
