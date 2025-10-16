//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;

use futures_util::{FutureExt, TryFutureExt};

use super::*;
use crate::support::{AsyncRuntime, CancellationId, ResultReporter};

/// A baseline number of local references to allow on a background thread attaching to the JVM.
///
/// 16 is the default guaranteed number of local references for a JNI frame created by calling
/// *from* Java into a `native` function; if we can usually do a synchronous function's full work
/// with that, we should be able to do just the return value part as well.
///
/// cbindgen:ignore
pub const REASONABLE_JNI_BACKGROUND_THREAD_FRAME_SIZE: jint = 16;

/// Used to complete a Java CompletableFuture from any thread.
pub struct FutureCompleter<T> {
    jvm: JavaVM,
    future: GlobalRef,
    future_creation_stack_trace_elements: GlobalRef,
    complete_signature: PhantomData<fn(T)>,
}

/// [`ResultReporter`] that drops values after reporting an outcome.
pub struct FutureResultReporter<T, U> {
    result: SignalJniResult<T>,
    to_drop: U,
}

impl<T, U> FutureResultReporter<T, U> {
    pub fn new(result: SignalJniResult<T>, to_drop: U) -> Self {
        Self { result, to_drop }
    }
}

impl<T: for<'a> ResultTypeInfo<'a> + std::panic::UnwindSafe> FutureCompleter<T> {
    /// Stores a handle to the JVM, a global reference to the given future, and
    /// captures the current stack trace to be used later if the future completes
    /// with an exception.
    ///
    /// `future` is expected to refer to a CompletableFuture instance, and will
    /// have methods called on it that match the signatures on CompletableFuture.
    pub fn new(env: &mut JNIEnv, future: &JObject) -> Result<Self, BridgeLayerError> {
        let future_creation_stack_trace_elements = Self::get_current_thread_stack_trace(env)?;

        Ok(Self {
            jvm: env.get_java_vm().expect_no_exceptions()?,
            future: env.new_global_ref(future).expect_no_exceptions()?,
            future_creation_stack_trace_elements: env
                .new_global_ref(&future_creation_stack_trace_elements)
                .expect_no_exceptions()?,
            complete_signature: PhantomData,
        })
    }

    fn get_current_thread_stack_trace<'a>(
        env: &mut JNIEnv<'a>,
    ) -> Result<JObject<'a>, BridgeLayerError> {
        let thread_class = find_class(env, ClassName("java.lang.Thread")).expect_no_exceptions()?;
        let thread = call_static_method_checked(
            env,
            &thread_class,
            "currentThread",
            jni_args!(() -> java.lang.Thread),
        )?;

        let stack_trace_elements = call_method_checked(
            env,
            &thread,
            "getStackTrace",
            jni_args!(() -> [java.lang.StackTraceElement]),
        )?;

        Ok(stack_trace_elements)
    }
}

impl<T: for<'a> ResultTypeInfo<'a> + std::panic::UnwindSafe, U> ResultReporter
    for FutureResultReporter<T, U>
{
    type Receiver = FutureCompleter<T>;

    fn report_to(self, receiver: Self::Receiver) {
        let Self {
            result,
            to_drop: extra_args_to_drop,
        } = self;
        let FutureCompleter {
            jvm,
            future,
            future_creation_stack_trace_elements,
            complete_signature: _,
        } = receiver;

        let mut env = match jvm.attach_current_thread() {
            Ok(attach_guard) => attach_guard,
            Err(e) => {
                // Most likely this log will fail too,
                // but really we don't expect attach_current_thread to fail at all.
                log::error!("failed to attach to JVM: {e}");
                return;
            }
        };

        let result = env.with_local_frame(
            REASONABLE_JNI_BACKGROUND_THREAD_FRAME_SIZE,
            move |mut env| -> jni::errors::Result<()> {
                // Catch panics while converting successful results to Java values.
                // (We have no *expected* panics, but we don't want to bring down the process for a
                // libsignal-internal bug if we can help it.)
                let maybe_error: SignalJniResult<()> = {
                    // This AssertUnwindSafe isn't totally justified, but if we get a panic talking to the
                    // JVM, we have bigger problems.
                    // Note that we need an extra &mut even though `env` is already `&mut JNIEnv`,
                    // so we can *release* it once this block is over.
                    let env_for_catch_unwind = std::panic::AssertUnwindSafe(&mut env);
                    let future_for_catch_unwind = &future;
                    result.and_then(|result| {
                        std::panic::catch_unwind(move || {
                            // Force the lambda to capture the whole struct instead of an individual field.
                            let _ = &env_for_catch_unwind;
                            let env = env_for_catch_unwind.0;
                            result
                                .convert_into(env)
                                .and_then(|result| {
                                    let result_as_jobject = box_primitive_if_needed(env, result.into())?;
                                    _ = call_method_checked(
                                        env,
                                        future_for_catch_unwind,
                                        "complete",
                                        jni_args!((result_as_jobject => java.lang.Object) -> boolean),
                                    )?;
                                    Ok(())
                                })
                                .map_err(Into::into)
                        })
                        .unwrap_or_else(|panic| Err(BridgeLayerError::UnexpectedPanic(panic).into()))
                    })
                };

                // From this point on we can't catch panics, because SignalJniError isn't UnwindSafe. This
                // is consistent with the synchronous implementation in run_ffi_safe, which doesn't catch
                // panics when converting errors to exceptions either.
                let future_for_convert = &future;
                let stack_elements_for_convert = &future_creation_stack_trace_elements;
                maybe_error.unwrap_or_else(move |error| {
                    let throwable = error.to_throwable(env);
                    throwable
                        .and_then(move |throwable| {
                            call_method_checked(
                                env,
                                &throwable,
                                "setStackTrace",
                                jni_args!((stack_elements_for_convert => [java.lang.StackTraceElement]) -> void),
                            )?;

                            _ = call_method_checked(
                                env,
                                future_for_convert,
                                "completeExceptionally",
                                jni_args!((throwable => java.lang.Throwable) -> boolean),
                            )?;
                            Ok(())
                        })
                        .unwrap_or_else(|completion_error| {
                            log::error!(
                                "failed to complete Future with error \"{error}\": {completion_error}"
                            );
                        });
                });

                // Explicitly drop these while the thread is still attached to the JVM.
                drop(future);
                drop(future_creation_stack_trace_elements);
                drop(extra_args_to_drop);

                Ok(())
            });

        match result {
            Ok(()) => {}
            Err(e) => {
                // Most likely this log will fail too,
                // but really we don't expect with_local_frame's block to fail either.
                // We try to handle all errors within it explicitly.
                log::error!("failed to report result while attached to the JVM: {e}");
            }
        }
    }
}

/// Runs a future as a task on the given async runtime, and saves the result in a new Java Future
/// object (the return value).
///
/// More specifically, this method expects `make_future` to produce a Rust Future (`F`); that Future
/// should compute some output (`O`) and report it to the given `FutureCompleter`. This complex
/// arrangement allows the Rust Future to clean up any saved data that needs an attached JVM thread.
///
/// ## Example
///
/// ```no_run
/// # use jni::JNIEnv;
/// # use libsignal_bridge_types::jni::*;
/// # use libsignal_bridge_types::support::NoOpAsyncRuntime;
/// # fn test(env: &mut JNIEnv, async_runtime: &NoOpAsyncRuntime) -> SignalJniResult<()> {
/// let java_future = run_future_on_runtime(env, async_runtime, "task", |_cancel| async {
///     let result: i32 = 1 + 2;
///     // Do some complicated awaiting here.
///     FutureResultReporter::new(Ok(result), ())
/// })?;
/// # Ok(())
/// # }
pub fn run_future_on_runtime<'local, R, F, O>(
    env: &mut JNIEnv<'local>,
    runtime: &R,
    label: &'static str,
    future: impl FnOnce(R::Cancellation) -> F,
) -> SignalJniResult<JavaCompletableFuture<'local, <O as ResultTypeInfo<'local>>::ResultType>>
where
    R: AsyncRuntime<F>,
    F: Future<Output: ResultReporter<Receiver = FutureCompleter<O>>>
        + std::panic::UnwindSafe
        + 'static,
    O: for<'a> ResultTypeInfo<'a> + std::panic::UnwindSafe + 'static,
{
    let java_future = new_instance(
        env,
        ClassName("org.signal.libsignal.internal.CompletableFuture"),
        jni_args!(() -> void),
    )?;

    let completer = FutureCompleter::new(env, &java_future)?;
    let cancellation_token = runtime.run_future(future, completer, label);
    if let CancellationId::Id(cancellation_id) = cancellation_token {
        call_method_checked(
            env,
            &java_future,
            "setCancellationId",
            jni_args!((cancellation_id.get() as i64 => long) -> void),
        )?;
    }

    Ok(java_future.into())
}

/// Catches panics that occur in `future` and converts them to [`BridgeLayerError::UnexpectedPanic`].
pub fn catch_unwind<'a, O>(
    future: impl Future<Output = SignalJniResult<O>> + Send + std::panic::UnwindSafe + 'a,
) -> impl Future<Output = SignalJniResult<O>> + Send + std::panic::UnwindSafe + 'a {
    future
        .catch_unwind()
        .unwrap_or_else(|panic| Err(BridgeLayerError::UnexpectedPanic(panic).into()))
}
