//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[allow(unused_imports)]
use libsignal_protocol::SignalProtocolError;

#[cfg(feature = "jni")]
use crate::jni::HandleJniError;
use crate::*;

/// A syntactic wrapper for a type that allows it to ignored by the macros in ffi/convert.rs and
/// jni/convert.rs, and by gen_ts_decl.py.
///
/// The app language will use a type that's compatible with `null`/`nil`.
pub type Ignored<T> = T;

/// A storage type that checks that it's cleaned up correctly.
///
/// Most useful with `bridge_io`, as well as async `bridge_fn` on Node, since those have to do
/// cleanup in a separate call frame from where arguments are initially saved.
#[allow(dead_code)] // Certain cases are only used with certain targets
pub enum NeedsCleanup {
    /// Does not do any special checks.
    None,
    /// Requires that the current thread be attached to the JVM on Drop.
    #[cfg(feature = "jni")]
    AttachedToJVM(::jni::JavaVM),
    /// Requires that the value be [finalized][neon::prelude::Finalize] instead of being dropped.
    FinalizedByNeon,
}

impl Drop for NeedsCleanup {
    fn drop(&mut self) {
        match self {
            Self::None => {}
            #[cfg(feature = "jni")]
            Self::AttachedToJVM(jvm) => {
                assert!(jvm.get_env().is_ok());
            }
            Self::FinalizedByNeon => {
                panic!("should been Finalized")
            }
        }
    }
}

#[cfg(feature = "node")]
impl node::Finalize for NeedsCleanup {
    fn finalize<'a, C: neon::prelude::Context<'a>>(self, _: &mut C) {
        std::mem::forget(self)
    }
}

#[cfg(feature = "ffi")]
impl ffi::SimpleArgTypeInfo for NeedsCleanup {
    type ArgType = *const std::ffi::c_void;

    fn convert_from(_foreign: Self::ArgType) -> ffi::SignalFfiResult<Self> {
        // The plain FFI bridge does not have any context or environment it's executed in,
        // so there's nothing to check.
        Ok(Self::None)
    }
}

#[cfg(feature = "jni")]
impl<'storage, 'param: 'storage, 'context: 'param> jni::ArgTypeInfo<'storage, 'param, 'context>
    for NeedsCleanup
{
    type ArgType = jni::JObject<'context>;
    type StoredType = Self;

    fn borrow(
        env: &mut jni::JNIEnv<'context>,
        _foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, jni::BridgeLayerError> {
        Ok(Self::AttachedToJVM(
            env.get_java_vm().expect_no_exceptions()?,
        ))
    }

    fn load_from(_stored: &'storage mut Self::StoredType) -> Self {
        // We only want to test that the storage is cleaned up, not the value passed into the
        // wrapped function.
        Self::None
    }
}

#[cfg(feature = "node")]
impl<'storage, 'context: 'storage> node::ArgTypeInfo<'storage, 'context> for NeedsCleanup {
    type ArgType = node::JsNull;
    // Synchronous uses of arguments in the Node bridge are not Finalized;
    // it is assumed they do not require it.
    type StoredType = ();

    fn borrow(
        _cx: &mut neon::prelude::FunctionContext<'context>,
        _foreign: neon::prelude::Handle<'context, Self::ArgType>,
    ) -> neon::result::NeonResult<Self::StoredType> {
        Ok(())
    }

    fn load_from(_stored: &'storage mut Self::StoredType) -> Self {
        Self::None
    }
}

#[cfg(feature = "node")]
impl<'storage> node::AsyncArgTypeInfo<'storage> for NeedsCleanup {
    type ArgType = node::JsNull;
    type StoredType = Self;

    fn save_async_arg(
        _cx: &mut neon::prelude::FunctionContext,
        _foreign: neon::prelude::Handle<Self::ArgType>,
    ) -> neon::result::NeonResult<Self::StoredType> {
        Ok(Self::FinalizedByNeon)
    }

    fn load_async_arg(_stored: &'storage mut Self::StoredType) -> Self {
        // We only want to test that the storage is cleaned up, not the value passed into the wrapped function.
        Self::None
    }
}

/// A type that implements ArgTypeInfo but always produces an error when "borrowed" from the
/// app-provided arguments.
pub struct ErrorOnBorrow;

#[cfg(feature = "ffi")]
impl ffi::SimpleArgTypeInfo for ErrorOnBorrow {
    type ArgType = *const std::ffi::c_void;

    fn convert_from(_foreign: Self::ArgType) -> ffi::SignalFfiResult<Self> {
        Err(SignalProtocolError::InvalidArgument("deliberate error".to_string()).into())
    }
}

#[cfg(feature = "jni")]
impl<'a> jni::SimpleArgTypeInfo<'a> for ErrorOnBorrow {
    type ArgType = jni::JObject<'a>;

    fn convert_from(
        _env: &mut jni::JNIEnv<'a>,
        _foreign: &Self::ArgType,
    ) -> Result<Self, jni::BridgeLayerError> {
        Err(jni::BridgeLayerError::BadArgument(
            "deliberate error".to_string(),
        ))
    }
}

#[cfg(feature = "node")]
impl node::SimpleArgTypeInfo for ErrorOnBorrow {
    type ArgType = node::JsNull;

    fn convert_from(
        cx: &mut node::FunctionContext,
        _foreign: node::Handle<Self::ArgType>,
    ) -> node::NeonResult<Self> {
        node::Context::throw_type_error(cx, "deliberate error")
    }
}

/// A type that implements ArgTypeInfo but panics as it is "borrowed" from the app-provided
/// arguments.
pub struct PanicOnBorrow;

#[cfg(feature = "ffi")]
impl ffi::SimpleArgTypeInfo for PanicOnBorrow {
    type ArgType = *const std::ffi::c_void;

    fn convert_from(_foreign: Self::ArgType) -> ffi::SignalFfiResult<Self> {
        panic!("deliberate panic")
    }
}

#[cfg(feature = "jni")]
impl<'a> jni::SimpleArgTypeInfo<'a> for PanicOnBorrow {
    type ArgType = jni::JObject<'a>;

    fn convert_from(
        _env: &mut jni::JNIEnv<'a>,
        _foreign: &Self::ArgType,
    ) -> Result<Self, jni::BridgeLayerError> {
        panic!("deliberate panic");
    }
}

#[cfg(feature = "node")]
impl node::SimpleArgTypeInfo for PanicOnBorrow {
    type ArgType = node::JsNull;

    fn convert_from(
        _cx: &mut node::FunctionContext,
        _foreign: node::Handle<Self::ArgType>,
    ) -> node::NeonResult<Self> {
        panic!("deliberate panic")
    }
}

/// A type that implements ArgTypeInfo but panics on the secondary "load" step after the "borrow"
/// step.
///
/// This is most relevant for `bridge_io`, as well as async `bridge_fn` on Node, since those load
/// from their saved values in a separate call frame from where arguments are initially saved.
pub struct PanicOnLoad;

#[cfg(feature = "ffi")]
impl<'storage> ffi::ArgTypeInfo<'storage> for PanicOnLoad {
    type ArgType = *const std::ffi::c_void;

    type StoredType = ();

    fn borrow(_foreign: Self::ArgType) -> ffi::SignalFfiResult<Self::StoredType> {
        Ok(())
    }

    fn load_from(_stored: &'storage mut Self::StoredType) -> Self {
        panic!("deliberate panic")
    }
}

#[cfg(feature = "jni")]
impl<'storage, 'param: 'storage, 'context: 'param> jni::ArgTypeInfo<'storage, 'param, 'context>
    for PanicOnLoad
{
    type ArgType = jni::JObject<'context>;
    type StoredType = NeedsCleanup;

    fn borrow(
        env: &mut ::jni::JNIEnv<'context>,
        _foreign: &'param Self::ArgType,
    ) -> Result<Self::StoredType, jni::BridgeLayerError> {
        <NeedsCleanup as jni::ArgTypeInfo>::borrow(env, _foreign)
    }

    fn load_from(_stored: &'storage mut Self::StoredType) -> Self {
        panic!("deliberate panic")
    }
}

#[cfg(feature = "node")]
impl<'storage, 'context: 'storage> node::ArgTypeInfo<'storage, 'context> for PanicOnLoad {
    type ArgType = node::JsNull;

    type StoredType = ();

    fn borrow(
        _cx: &mut neon::prelude::FunctionContext<'context>,
        _foreign: neon::prelude::Handle<'context, Self::ArgType>,
    ) -> neon::result::NeonResult<Self::StoredType> {
        Ok(())
    }

    fn load_from(_stored: &'storage mut Self::StoredType) -> Self {
        panic!("deliberate panic")
    }
}

#[cfg(feature = "node")]
impl<'storage> node::AsyncArgTypeInfo<'storage> for PanicOnLoad {
    type ArgType = node::JsNull;

    type StoredType = NeedsCleanup;

    fn save_async_arg(
        _cx: &mut neon::prelude::FunctionContext,
        _foreign: neon::prelude::Handle<Self::ArgType>,
    ) -> neon::result::NeonResult<Self::StoredType> {
        Ok(NeedsCleanup::FinalizedByNeon)
    }

    fn load_async_arg(_stored: &'storage mut Self::StoredType) -> Self {
        panic!("deliberate panic")
    }
}

/// A type that implements ResultTypeInfo but always fails to produce a result.
pub struct ErrorOnReturn;

#[cfg(feature = "ffi")]
impl ffi::ResultTypeInfo for ErrorOnReturn {
    type ResultType = *const std::ffi::c_void;

    fn convert_into(self) -> ffi::SignalFfiResult<Self::ResultType> {
        Err(SignalProtocolError::InvalidArgument("deliberate error".to_string()).into())
    }
}

#[cfg(feature = "jni")]
impl<'a> jni::ResultTypeInfo<'a> for ErrorOnReturn {
    type ResultType = jni::JObject<'a>;

    fn convert_into(
        self,
        _env: &mut jni::JNIEnv<'a>,
    ) -> Result<Self::ResultType, jni::BridgeLayerError> {
        Err(jni::BridgeLayerError::BadArgument(
            "deliberate error".to_string(),
        ))
    }
}

#[cfg(feature = "node")]
impl<'a> node::ResultTypeInfo<'a> for ErrorOnReturn {
    type ResultType = node::JsNull;

    fn convert_into(self, cx: &mut impl node::Context<'a>) -> node::JsResult<'a, Self::ResultType> {
        cx.throw_type_error("deliberate error")
    }
}

/// A type that implements ResultTypeInfo but always panics when producing a result.
pub struct PanicOnReturn;

#[cfg(feature = "ffi")]
impl ffi::ResultTypeInfo for PanicOnReturn {
    type ResultType = *const std::ffi::c_void;

    fn convert_into(self) -> ffi::SignalFfiResult<Self::ResultType> {
        panic!("deliberate panic");
    }
}

#[cfg(feature = "jni")]
impl<'a> jni::ResultTypeInfo<'a> for PanicOnReturn {
    type ResultType = jni::JObject<'a>;

    fn convert_into(
        self,
        _env: &mut jni::JNIEnv<'a>,
    ) -> Result<Self::ResultType, jni::BridgeLayerError> {
        panic!("deliberate panic");
    }
}

#[cfg(feature = "node")]
impl<'a> node::ResultTypeInfo<'a> for PanicOnReturn {
    type ResultType = node::JsNull;

    fn convert_into(
        self,
        _cx: &mut impl node::Context<'a>,
    ) -> node::JsResult<'a, Self::ResultType> {
        panic!("deliberate panic");
    }
}
