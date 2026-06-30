//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::Arc;

use libsignal_bridge_macros::{BridgedAsValue, bridge_io};

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
pub enum NeedsCleanup {
    /// Does not do any special checks.
    None,
    /// Requires that the current thread be attached to the JVM on Drop.
    #[cfg(feature = "jni")]
    AttachedToJVM(::jni::JavaVM),
    /// Requires that the value be [finalized][neon::prelude::Finalize] instead of being dropped.
    #[cfg(feature = "node")]
    FinalizedByNeon,
}

impl Drop for NeedsCleanup {
    fn drop(&mut self) {
        match self {
            Self::None => {}
            #[cfg(feature = "jni")]
            Self::AttachedToJVM(jvm) => {
                assert!(
                    jvm.with_top_local_frame(|_env| Ok::<_, ::jni::errors::Error>(()))
                        .is_ok()
                );
            }
            #[cfg(feature = "node")]
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
        env: &mut ::jni::Env<'context>,
        _foreign: &Self::ArgType,
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
    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(_: &mut metadata::node::TsMetadataContext) -> String {
        "null".into()
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
    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(_: &mut metadata::node::TsMetadataContext) -> String {
        "null".into()
    }
}

/// A type that implements ArgTypeInfo but always produces an error when "borrowed" from the
/// app-provided arguments.
pub struct ErrorOnBorrow;

#[cfg(feature = "ffi")]
impl ffi::SimpleArgTypeInfo for ErrorOnBorrow {
    type ArgType = *const std::ffi::c_void;

    fn convert_from(_foreign: Self::ArgType) -> ffi::SignalFfiResult<Self> {
        Err(IllegalArgumentError::new("deliberate error").into())
    }
}

#[cfg(feature = "jni")]
impl<'a> jni::SimpleArgTypeInfo<'a> for ErrorOnBorrow {
    type ArgType = jni::JObject<'a>;

    fn convert_from(
        _env: &mut ::jni::Env<'a>,
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
    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(_: &mut metadata::node::TsMetadataContext) -> String {
        "null".into()
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
        _env: &mut ::jni::Env<'a>,
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

    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(_: &mut metadata::node::TsMetadataContext) -> String {
        "null".into()
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
        env: &mut ::jni::Env<'context>,
        _foreign: &Self::ArgType,
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

    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(_: &mut metadata::node::TsMetadataContext) -> String {
        "null".into()
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

    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(_: &mut metadata::node::TsMetadataContext) -> String {
        "null".into()
    }
}

/// A type that implements ResultTypeInfo but always fails to produce a result.
pub struct ErrorOnReturn;

#[cfg(feature = "ffi")]
impl ffi::ResultTypeInfo for ErrorOnReturn {
    type ResultType = *const std::ffi::c_void;

    fn convert_into(self) -> ffi::SignalFfiResult<Self::ResultType> {
        Err(IllegalArgumentError::new("deliberate error").into())
    }
}

#[cfg(feature = "jni")]
impl<'a> jni::ResultTypeInfo<'a> for ErrorOnReturn {
    type ResultType = jni::JObject<'a>;

    fn convert_into(
        self,
        _env: &mut ::jni::Env<'a>,
    ) -> Result<Self::ResultType, jni::BridgeLayerError> {
        Err(jni::BridgeLayerError::BadArgument(
            "deliberate error".to_string(),
        ))
    }
}

#[cfg(feature = "node")]
impl<'a> node::ResultTypeInfo<'a> for ErrorOnReturn {
    type ResultType = node::JsNull;

    fn convert_into(self, cx: &mut node::Cx<'a>) -> node::JsResult<'a, Self::ResultType> {
        node::Context::throw_type_error(cx, "deliberate error")
    }

    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(_: &mut metadata::node::TsMetadataContext) -> String {
        "null".into()
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
        _env: &mut ::jni::Env<'a>,
    ) -> Result<Self::ResultType, jni::BridgeLayerError> {
        panic!("deliberate panic");
    }
}

#[cfg(feature = "node")]
impl<'a> node::ResultTypeInfo<'a> for PanicOnReturn {
    type ResultType = node::JsNull;

    fn convert_into(self, _cx: &mut node::Cx<'a>) -> node::JsResult<'a, Self::ResultType> {
        panic!("deliberate panic");
    }

    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(_: &mut metadata::node::TsMetadataContext) -> String {
        "null".into()
    }
}

#[derive(derive_more::Deref)]
pub struct TestingSemaphore(tokio::sync::Semaphore);
bridge_as_handle!(TestingSemaphore);
bridge_handle_fns!(TestingSemaphore, clone = false);

#[bridge_fn]
fn TestingSemaphore_New(initial: u32) -> TestingSemaphore {
    TestingSemaphore(tokio::sync::Semaphore::new(initial.try_into().unwrap()))
}

#[bridge_fn]
fn TestingSemaphore_AddPermits(semaphore: &TestingSemaphore, permits: u32) {
    semaphore.add_permits(permits.try_into().unwrap());
}

/// Counter for future cancellations
pub struct TestingFutureCancellationCounter(pub(crate) Arc<tokio::sync::Semaphore>);

impl UnwindSafe for TestingFutureCancellationCounter {}
impl RefUnwindSafe for TestingFutureCancellationCounter {}

/// RAII guard that increments a counter on `Drop`.
///
/// This is bridged as a reference to a [`TestingFutureCancellationCounter`].
pub struct TestingFutureCancellationGuard {
    increment_on_drop: Arc<tokio::sync::Semaphore>,
}

impl Drop for TestingFutureCancellationGuard {
    fn drop(&mut self) {
        self.increment_on_drop.add_permits(1);
    }
}

#[cfg(feature = "ffi")]
impl ffi::SimpleArgTypeInfo for TestingFutureCancellationGuard {
    type ArgType = <&'static TestingFutureCancellationCounter as ffi::SimpleArgTypeInfo>::ArgType;

    fn convert_from(foreign: Self::ArgType) -> ffi::SignalFfiResult<Self> {
        <&TestingFutureCancellationCounter as ffi::SimpleArgTypeInfo>::convert_from(foreign).map(
            |TestingFutureCancellationCounter(counter)| TestingFutureCancellationGuard {
                increment_on_drop: Arc::clone(counter),
            },
        )
    }
}

#[cfg(feature = "jni")]
impl<'a> jni::SimpleArgTypeInfo<'a> for TestingFutureCancellationGuard {
    type ArgType = jni::ObjectHandle;

    fn convert_from(
        env: &mut ::jni::Env<'a>,
        foreign: &Self::ArgType,
    ) -> Result<Self, jni::BridgeLayerError> {
        <&TestingFutureCancellationCounter as jni::ArgTypeInfo>::borrow(env, foreign).map(
            |container| TestingFutureCancellationGuard {
                increment_on_drop: Arc::clone(&container.0),
            },
        )
    }
}

#[cfg(feature = "node")]
impl<'storage> node::AsyncArgTypeInfo<'storage> for TestingFutureCancellationGuard {
    type ArgType = node::JsObject;
    type StoredType = Option<node::DefaultFinalize<Self>>;
    fn save_async_arg(
        cx: &mut neon::prelude::FunctionContext,
        foreign: neon::prelude::Handle<Self::ArgType>,
    ) -> neon::prelude::NeonResult<Self::StoredType> {
        <&TestingFutureCancellationCounter as node::AsyncArgTypeInfo>::save_async_arg(cx, foreign)
            .map(move |handle| {
                Some(node::DefaultFinalize(TestingFutureCancellationGuard {
                    increment_on_drop: Arc::clone(&handle.0),
                }))
            })
    }
    fn load_async_arg(stored: &'storage mut Self::StoredType) -> Self {
        stored.take().unwrap().0
    }

    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(_: &mut metadata::node::TsMetadataContext) -> String {
        "TestingFutureCancellationGuard".into()
    }
}

bridge_as_handle!(TestingFutureCancellationCounter);

pub struct TestingValueHolder(pub std::sync::atomic::AtomicI32);

impl Drop for TestingValueHolder {
    fn drop(&mut self) {
        self.0
            .store(0x1111_dead, std::sync::atomic::Ordering::SeqCst);
    }
}

bridge_as_handle!(TestingValueHolder);
bridge_handle_fns!(TestingValueHolder, clone = false);

#[bridge_fn]
fn TestingValueHolder_New(value: i32) -> TestingValueHolder {
    TestingValueHolder(value.into())
}

#[bridge_fn]
fn TestingValueHolder_Get(holder: &TestingValueHolder) -> i32 {
    holder.0.load(std::sync::atomic::Ordering::SeqCst)
}

#[bridge_fn]
fn TESTING_ReturnPair() -> (i32, String) {
    (1, "libsignal".into())
}

pub struct TestingIntBox(pub i32);
bridge_as_handle!(
    TestingIntBox,
    swift_type = "TestingIntBox",
    jni_class = "org.signal.libsignal.internal.TestingIntBox",
);
bridge_handle_fns!(TestingIntBox, clone = false);

#[bridge_fn]
fn TESTING_TestingIntBox_New(value: i32) -> TestingIntBox {
    TestingIntBox(value)
}
#[bridge_fn(nice = true)]
fn TESTING_TestingIntBox_Get(my_int_box: BridgeHandleRef<'_, TestingIntBox>) -> i32 {
    my_int_box.0
}

#[derive(BridgedAsValue, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MyTestStruct {
    my_numeric_field: i32,
    my_string_field: String,
}
#[derive(BridgedAsValue, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MyTestPoint(i32, i32);

#[derive(BridgedAsValue, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MyTestEnum {
    Unit,
    Single(i32),
    SingleNamed {
        x: i32,
    },
    Double(i32, i32),
    #[serde(rename_all = "camelCase")]
    Record {
        person_name: String,
        person_age: i32,
        position: MyTestPoint,
        fun_struct: MyTestStruct,
    },
}

#[derive(BridgedAsValue)]
pub enum MySimpleTestEnum {
    A,
    B,
}

#[bridge_fn(nice = true)]
pub fn TESTING_MySimpleTestEnum_identity(x: MySimpleTestEnum) -> MySimpleTestEnum {
    x
}

#[bridge_fn(nice = true)]
pub fn TESTING_MyTestPoint_identity(x: MyTestPoint) -> MyTestPoint {
    x
}

#[bridge_fn(nice = true)]
pub fn TESTING_MyTestStruct_identity(x: MyTestStruct) -> MyTestStruct {
    x
}

#[bridge_fn(nice = true)]
pub fn TESTING_MyTestEnum_identity(x: MyTestEnum) -> MyTestEnum {
    x
}

#[bridge_io(TokioAsyncContext, nice = true, jni = false, ffi = false)]
pub async fn TESTING_MySimpleTestEnum_identity_async(x: MySimpleTestEnum) -> MySimpleTestEnum {
    x
}

#[bridge_io(TokioAsyncContext, nice = true, jni = false, ffi = false)]
pub async fn TESTING_MyTestPoint_identity_async(x: MyTestPoint) -> MyTestPoint {
    x
}

#[bridge_io(TokioAsyncContext, nice = true, jni = false, ffi = false)]
pub async fn TESTING_MyTestStruct_identity_async(x: MyTestStruct) -> MyTestStruct {
    x
}

#[bridge_io(TokioAsyncContext, nice = true, jni = false, ffi = false)]
pub async fn TESTING_MyTestEnum_identity_async(x: MyTestEnum) -> MyTestEnum {
    x
}

#[bridge_fn(nice = true)]
pub fn TESTING_MySimpleTestEnum_to_string(x: MySimpleTestEnum) -> String {
    match x {
        MySimpleTestEnum::A => "A",
        MySimpleTestEnum::B => "B",
    }
    .to_string()
}

#[bridge_fn(nice = true)]
fn TESTING_MySimpleTestEnum_BridgeVec_to_string(x: BridgeVec<MySimpleTestEnum>) -> String {
    serde_json::to_string(
        &x.0.into_iter()
            .map(TESTING_MySimpleTestEnum_to_string)
            .collect::<Vec<_>>(),
    )
    .expect("JSON succeeds")
}
#[bridge_fn(nice = true)]
fn TESTING_MySimpleTestEnum_BridgeVec_identity(
    x: BridgeVec<MySimpleTestEnum>,
) -> BridgeVec<MySimpleTestEnum> {
    x
}
#[bridge_io(TokioAsyncContext, nice = true, jni = false, ffi = false)]
pub async fn TESTING_MySimpleTestEnum_BridgeVec_identity_async(
    x: BridgeVec<MySimpleTestEnum>,
) -> BridgeVec<MySimpleTestEnum> {
    x
}

#[bridge_fn(nice = true)]
pub fn TESTING_MyTestPoint_to_string(x: MyTestPoint) -> String {
    serde_json::to_string(&x).expect("JSON succeeds")
}

#[bridge_fn(nice = true)]
pub fn TESTING_MyTestStruct_to_string(x: MyTestStruct) -> String {
    serde_json::to_string(&x).expect("JSON succeeds")
}

#[bridge_fn(nice = true)]
pub fn TESTING_MyTestEnum_to_string(x: MyTestEnum) -> String {
    serde_json::to_string(&x).expect("JSON succeeds")
}

pub struct MyRemoteDeriveStruct {
    x: i32,
    y: i32,
}
pub enum MyRemoteDeriveEnum {
    Unit,
    Tuple(i32, i32),
    Record { x: String, y: i32 },
}

mod remote_derive_test {
    use libsignal_bridge_macros::BridgedAsValue;

    use crate::*;
    #[derive(BridgedAsValue)]
    #[bridge(remote = super::MyRemoteDeriveStruct)]
    #[allow(unused)] // Since it's a remote derive
    pub struct MyRemoteDeriveStruct {
        x: i32,
        y: i32,
    }
    #[derive(BridgedAsValue)]
    #[bridge(remote = super::MyRemoteDeriveEnum)]
    #[allow(unused)] // Since it's a remote derive
    pub enum MyRemoteDeriveEnum {
        Unit,
        Tuple(i32, i32),
        Record { x: String, y: i32 },
    }
}

#[cfg(feature = "ffi")]
use remote_derive_test::{
    MyRemoteDeriveEnumFfiArg, MyRemoteDeriveEnumFfiResult, MyRemoteDeriveStructFfiArg,
    MyRemoteDeriveStructFfiResult,
};
#[bridge_fn(nice = true, jni = false)]
pub fn TESTING_MyRemoteDeriveEnum_identity(x: MyRemoteDeriveEnum) -> MyRemoteDeriveEnum {
    x
}

#[bridge_fn(nice = true, jni = false)]
pub fn TESTING_MyRemoteDeriveStruct_identity(x: MyRemoteDeriveStruct) -> MyRemoteDeriveStruct {
    x
}

#[bridge_fn(nice = true)]
pub fn TESTING_ReturnIoError() -> BridgedError<std::io::Error> {
    BridgedError(std::io::Error::other("testing"))
}

#[bridge_fn(nice = true)]
pub fn TESTING_ReturnSomeIoError(present: bool) -> Option<BridgedError<std::io::Error>> {
    present.then(|| BridgedError(std::io::Error::other("testing")))
}
