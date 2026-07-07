//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(not(any(feature = "ffi", feature = "jni", feature = "node")))]
compile_error!("Feature \"ffi\", \"jni\", or \"node\" must be enabled for this crate.");

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::StreamExt as _;
use futures_util::stream::BoxStream;
use libsignal_bridge_macros::{BridgedAsValue, bridge_fn, bridge_io};
use libsignal_bridge_types::net::TokioAsyncContext;
#[cfg(feature = "node")]
pub use libsignal_bridge_types::node;
use libsignal_bridge_types::support::*;
use libsignal_bridge_types::*;
use libsignal_net_chat::stream_util::{
    BulkPolledStream, BulkPolledStreamChunk, BulkPolledStreamTerminationReason,
};

use crate::types::Ignored;

pub mod convert;
pub mod crypto;
pub mod message_backup;
pub mod net;
#[cfg(feature = "node")]
pub mod net_env;
pub mod protocol;
pub mod types;

#[bridge_fn]
pub fn test_only_fn_returns_123() -> u32 {
    123
}

#[bridge_fn]
pub fn TESTING_BridgedStringMap_dump_to_json(map: &BridgedStringMap) -> String {
    // Convert to a BTreeMap for sorted (deterministic) output.
    serde_json::to_string_pretty(&BTreeMap::from_iter(map.iter()))
        .expect("map of string -> string is always valid JSON")
}

#[bridge_fn]
pub fn TESTING_TokioAsyncContext_NewSingleThreaded() -> TokioAsyncContext {
    TokioAsyncContext::new_single_threaded()
}

#[bridge_fn(ffi = false, node = false)]
pub fn TESTING_TokioAsyncContext_AttachBlockingThreadToJVMPermanently(
    context: &TokioAsyncContext,
    jvm: Ignored<::jni::JavaVM>,
) {
    let tokio_handle = context.handle();
    // spawn_blocking produces a Future for its work;
    // block_on undoes that by waiting until it's complete.
    tokio_handle
        .block_on(tokio_handle.spawn_blocking(move || {
            jvm.attach_current_thread(|_env| Ok::<_, ::jni::errors::Error>(()))
                .expect("no error");
        }))
        .expect("no panic");
}

#[allow(clippy::type_complexity)]
pub struct TestStream {
    inner: AsyncMutex<
        Option<BulkPolledStream<BoxStream<'static, Result<String, IllegalArgumentError>>>>,
    >,
}

bridge_as_handle!(TestStream);
bridge_handle_fns!(TestStream, clone = false);

#[derive(BridgedAsValue)]
#[bridge(arg = false)]
pub struct TestStreamChunk {
    chunk: BridgeVec<String>,
    termination: Option<BulkPolledStreamTerminationReason<IllegalArgumentError>>,
}

#[bridge_fn]
pub fn TESTING_BulkPullFromStream_New(contents: Box<[String]>, end_with_error: bool) -> TestStream {
    TestStream {
        inner: Some(BulkPolledStream::new(
            futures_util::stream::iter(contents)
                .map(Ok)
                .chain(futures_util::stream::iter(
                    end_with_error.then_some(Err(IllegalArgumentError::new("error"))),
                ))
                .boxed(),
            5,
            Duration::MAX,
        ))
        .into(),
    }
}

#[bridge_io(TokioAsyncContext)]
pub async fn TESTING_BulkPullFromStream_NextChunk(stream: &TestStream) -> TestStreamChunk {
    let mut guard = stream.inner.lock().await;
    let Some(stream) = &mut *guard else {
        return TestStreamChunk {
            chunk: Vec::new().into(),
            termination: Some(BulkPolledStreamTerminationReason::Error(
                IllegalArgumentError::new("cancelled"),
            )),
        };
    };
    let BulkPolledStreamChunk { chunk, termination } = stream.next_chunk_unpin().await;
    TestStreamChunk {
        chunk: chunk.into(),
        termination,
    }
}

#[bridge_fn]
pub fn TESTING_BulkPullFromStream_Cancel(stream: &TestStream) {
    _ = stream.inner.blocking_lock().take();
}

// To generate the return converter
#[bridge_fn(nice = true)]
pub fn TESTING_TestStreamChunk_return() -> TestStreamChunk {
    unreachable!()
}
