//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;

use futures_util::{AsyncReadExt as _, FutureExt};
use io::{AsyncInput, InputStream};
use libsignal_bridge_macros::*;
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_bridge_types::support::*;
use libsignal_bridge_types::*;
use uuid::Uuid;

use crate::types::*;

pub struct NonSuspendingBackgroundThreadRuntime;
bridge_as_handle!(
    NonSuspendingBackgroundThreadRuntime,
    ffi = testing_NonSuspendingBackgroundThreadRuntime,
    jni = TESTING_1NonSuspendingBackgroundThreadRuntime
);
bridge_handle_fns!(
    NonSuspendingBackgroundThreadRuntime,
    clone = false,
    ffi = testing_NonSuspendingBackgroundThreadRuntime,
    jni = TESTING_1NonSuspendingBackgroundThreadRuntime
);

impl AsyncRuntimeBase for NonSuspendingBackgroundThreadRuntime {}

impl<F> AsyncRuntime<F> for NonSuspendingBackgroundThreadRuntime
where
    F: Future<Output: ResultReporter<Receiver: Send>> + Send + 'static,
{
    type Cancellation = std::future::Pending<()>;

    fn run_future(
        &self,
        make_future: impl FnOnce(Self::Cancellation) -> F,
        completer: <F::Output as ResultReporter>::Receiver,
        _label: &'static str,
    ) -> CancellationId {
        let future = make_future(std::future::pending());
        std::thread::spawn(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                future
                    .now_or_never()
                    .expect("no need to suspend in testing methods")
                    .report_to(completer);
            }))
            .unwrap_or_else(|_| {
                // Since this is a testing method, make sure we crash on uncaught panics.
                std::process::abort()
            })
        });
        CancellationId::NotSupported
    }
}

#[bridge_fn(ffi = false)]
fn TESTING_NonSuspendingBackgroundThreadRuntime_New() -> NonSuspendingBackgroundThreadRuntime {
    NonSuspendingBackgroundThreadRuntime
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime)]
async fn TESTING_FutureSuccess(input: u8) -> i32 {
    i32::from(input) * 2
}

#[bridge_io(TokioAsyncContext)]
async fn TESTING_TokioAsyncContext_FutureSuccessBytes(count: i32) -> Vec<u8> {
    vec![0; usize::try_from(count).unwrap()]
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime)]
async fn TESTING_FutureFailure(_input: u8) -> Result<i32, IllegalArgumentError> {
    Err(IllegalArgumentError::new("failure"))
}

bridge_handle_fns!(TestingFutureCancellationCounter, clone = false);

#[bridge_fn]
fn TESTING_FutureCancellationCounter_Create(initial_value: u8) -> TestingFutureCancellationCounter {
    TestingFutureCancellationCounter(tokio::sync::Semaphore::new(initial_value.into()).into())
}

#[bridge_io(TokioAsyncContext)]
async fn TESTING_FutureCancellationCounter_WaitForCount(
    count: &TestingFutureCancellationCounter,
    target: u8,
) {
    let _permits = count
        .0
        .acquire_many(target.into())
        .await
        .expect("not closed");
}

#[bridge_io(TokioAsyncContext)]
async fn TESTING_FutureIncrementOnCancel(_guard: TestingFutureCancellationGuard) {
    std::future::pending().await
}

#[bridge_io(TokioAsyncContext, ffi = false, node = false)]
async fn TESTING_AcquireSemaphoreAndGet(
    semaphore: &TestingSemaphore,
    value_holder: &TestingValueHolder,
) -> i32 {
    semaphore.acquire().await.expect("not dropped yet").forget();
    value_holder.0.load(std::sync::atomic::Ordering::SeqCst)
}

#[bridge_io(TokioAsyncContext)]
async fn TESTING_TokioAsyncFuture(input: u8) -> i32 {
    i32::from(input) * 3
}

#[derive(Clone)]
pub struct TestingHandleType {
    value: u8,
}
bridge_as_handle!(TestingHandleType);
bridge_handle_fns!(TestingHandleType);

#[bridge_fn]
fn TESTING_TestingHandleType_getValue(handle: &TestingHandleType) -> u8 {
    handle.value
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime)]
async fn TESTING_FutureProducesPointerType(input: u8) -> TestingHandleType {
    TestingHandleType { value: input }
}

#[derive(Clone)]
pub struct OtherTestingHandleType {
    value: String,
}
bridge_as_handle!(OtherTestingHandleType);
bridge_handle_fns!(OtherTestingHandleType);

#[bridge_fn]
fn TESTING_OtherTestingHandleType_getValue(handle: &OtherTestingHandleType) -> String {
    handle.value.clone()
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime)]
async fn TESTING_FutureProducesOtherPointerType(input: String) -> OtherTestingHandleType {
    OtherTestingHandleType { value: input }
}

#[bridge_fn]
fn TESTING_PanicOnBorrowSync(_input: Ignored<PanicOnBorrow>) {}

#[bridge_fn]
async fn TESTING_PanicOnBorrowAsync(_input: Ignored<PanicOnBorrow>) {}

#[bridge_io(NonSuspendingBackgroundThreadRuntime)]
async fn TESTING_PanicOnBorrowIo(_input: Ignored<PanicOnBorrow>) {}

#[bridge_fn]
fn TESTING_ErrorOnBorrowSync(_input: Ignored<ErrorOnBorrow>) {}

#[bridge_fn]
async fn TESTING_ErrorOnBorrowAsync(_input: Ignored<ErrorOnBorrow>) {}

#[bridge_io(NonSuspendingBackgroundThreadRuntime)]
async fn TESTING_ErrorOnBorrowIo(_input: Ignored<ErrorOnBorrow>) {}

#[bridge_fn]
fn TESTING_PanicOnLoadSync(_needs_cleanup: Ignored<NeedsCleanup>, _input: Ignored<PanicOnLoad>) {}

#[bridge_fn]
async fn TESTING_PanicOnLoadAsync(
    _needs_cleanup: Ignored<NeedsCleanup>,
    _input: Ignored<PanicOnLoad>,
) {
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime)]
async fn TESTING_PanicOnLoadIo(
    _needs_cleanup: Ignored<NeedsCleanup>,
    _input: Ignored<PanicOnLoad>,
) {
}

#[bridge_fn]
fn TESTING_PanicInBodySync(_input: Ignored<NeedsCleanup>) {
    panic!("deliberate panic");
}

#[bridge_fn]
async fn TESTING_PanicInBodyAsync(_input: Ignored<NeedsCleanup>) {
    panic!("deliberate panic");
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime)]
async fn TESTING_PanicInBodyIo(_input: Ignored<NeedsCleanup>) {
    panic!("deliberate panic");
}

#[bridge_fn]
fn TESTING_PanicOnReturnSync(_needs_cleanup: Ignored<NeedsCleanup>) -> Ignored<PanicOnReturn> {
    PanicOnReturn
}

#[bridge_fn]
async fn TESTING_PanicOnReturnAsync(
    _needs_cleanup: Ignored<NeedsCleanup>,
) -> Ignored<PanicOnReturn> {
    PanicOnReturn
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime)]
async fn TESTING_PanicOnReturnIo(_needs_cleanup: Ignored<NeedsCleanup>) -> Ignored<PanicOnReturn> {
    PanicOnReturn
}

#[bridge_fn]
fn TESTING_ErrorOnReturnSync(_needs_cleanup: Ignored<NeedsCleanup>) -> Ignored<ErrorOnReturn> {
    ErrorOnReturn
}

#[bridge_fn]
async fn TESTING_ErrorOnReturnAsync(
    _needs_cleanup: Ignored<NeedsCleanup>,
) -> Ignored<ErrorOnReturn> {
    ErrorOnReturn
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime)]
async fn TESTING_ErrorOnReturnIo(_needs_cleanup: Ignored<NeedsCleanup>) -> Ignored<ErrorOnReturn> {
    ErrorOnReturn
}

#[cfg(feature = "jni")]
struct CustomErrorType;

#[cfg(feature = "jni")]
impl From<CustomErrorType> for crate::jni::SignalJniError {
    fn from(CustomErrorType: CustomErrorType) -> Self {
        crate::jni::TestingError {
            exception_class: crate::jni::ClassName(
                "org.signal.libsignal.internal.TestingException",
            ),
        }
        .into()
    }
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime, ffi = false, node = false)]
async fn TESTING_FutureThrowsCustomErrorType() -> Result<(), CustomErrorType> {
    std::future::ready(Err(CustomErrorType)).await
}

#[cfg(feature = "jni")]
struct PoisonErrorType;

#[cfg(feature = "jni")]
impl From<PoisonErrorType> for crate::jni::SignalJniError {
    fn from(PoisonErrorType: PoisonErrorType) -> Self {
        crate::jni::TestingError {
            exception_class: crate::jni::ClassName(
                "org.signal.libsignal.internal.GuaranteedNonexistentException",
            ),
        }
        .into()
    }
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime, ffi = false, node = false)]
async fn TESTING_FutureThrowsPoisonErrorType() -> Result<(), PoisonErrorType> {
    std::future::ready(Err(PoisonErrorType)).await
}

#[bridge_fn]
fn TESTING_ReturnStringArray() -> Box<[String]> {
    ["easy", "as", "ABC", "123"]
        .map(String::from)
        .into_iter()
        .collect()
}

#[allow(clippy::boxed_local)] // &[String] isn't supported for bridging (yet).
#[bridge_fn(ffi = false)]
fn TESTING_JoinStringArray(array: Box<[String]>, join_with: String) -> String {
    array.join(&join_with)
}

#[bridge_fn]
fn TESTING_ProcessBytestringArray(input: Vec<&[u8]>) -> Box<[Vec<u8>]> {
    input
        .into_iter()
        .map(|x| [x, x].concat())
        .collect::<Vec<Vec<u8>>>()
        .into_boxed_slice()
}

// Not needed for the FFI bridge because C can exactly describe all of these types.
#[bridge_fn(ffi = false)]
fn TESTING_RoundTripU8(input: u8) -> u8 {
    input
}
#[bridge_fn(ffi = false)]
fn TESTING_RoundTripU16(input: u16) -> u16 {
    input
}
#[bridge_fn(ffi = false)]
fn TESTING_RoundTripU32(input: u32) -> u32 {
    input
}
#[bridge_fn(ffi = false)]
fn TESTING_RoundTripI32(input: i32) -> i32 {
    input
}
#[bridge_fn(ffi = false)]
fn TESTING_RoundTripU64(input: u64) -> u64 {
    input
}

#[bridge_fn]
fn TESTING_ConvertOptionalUuid(present: bool) -> Option<Uuid> {
    present.then_some(uuid::uuid!("abababab-1212-8989-baba-565656565656"))
}

#[bridge_fn]
async fn TESTING_InputStreamReadIntoZeroLengthSlice(
    caps_alphabet_input: &mut dyn InputStream,
) -> Vec<u8> {
    let mut async_input = AsyncInput::new(caps_alphabet_input, 26);
    let first = {
        let mut buf = [0; 10];
        async_input
            .read_exact(&mut buf)
            .await
            .expect("can read first");
        buf
    };
    {
        let mut zero_length_array = [0; 0];
        assert_eq!(
            async_input
                .read(&mut zero_length_array)
                .await
                .expect("can do zero-length read"),
            0
        );
    }
    let remainder = {
        let mut buf = Vec::with_capacity(16);
        async_input
            .read_to_end(&mut buf)
            .await
            .expect("can read to end");
        buf
    };

    assert_eq!(&first, b"ABCDEFGHIJ");
    assert_eq!(remainder, b"KLMNOPQRSTUVWXYZ");

    first.into_iter().chain(remainder).collect()
}

#[bridge_fn(jni = false, node = false)]
fn TESTING_FingerprintVersionMismatchError(
    theirs: u32,
    ours: u32,
) -> Result<(), libsignal_protocol::FingerprintError> {
    Err(libsignal_protocol::FingerprintError::VersionMismatch { theirs, ours })
}
