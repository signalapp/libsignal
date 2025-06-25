//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Error as IoError;

use bytes::Bytes;
use futures_util::stream::FusedStream;
use futures_util::Sink;

mod handshake;
pub use handshake::*;
mod stream;
pub use stream::NoiseStream;

#[derive(Debug, thiserror::Error, displaydoc::Display, derive_more::Into)]
/// {0}
pub struct SendError(#[from] IoError);

impl From<snow::Error> for SendError {
    fn from(e: snow::Error) -> Self {
        Self(IoError::other(format!("noise error: {e}")))
    }
}

/// A frame-based transport that can be used to send Noise packets.
///
/// A blanket implementation is provided for types with compatible `Stream` and
/// `Sink` implementations.
pub trait Transport:
    FusedStream<Item = Result<Bytes, IoError>> + Sink<(FrameType, Bytes), Error = IoError>
{
}

impl<S> Transport for S where
    S: FusedStream<Item = Result<Bytes, IoError>> + Sink<(FrameType, Bytes), Error = IoError>
{
}

/// [`TransportFrameType`] implementation for transports that do differentiate frame types.
#[derive(Copy, Clone, Debug, PartialEq, displaydoc::Display, derive_more::From)]
pub enum FrameType {
    /// data
    Data,

    /// {0} auth
    Auth(#[from] HandshakeAuthKind),
}

#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use std::fmt::Debug;
    use std::future::Future;

    use futures_util::{SinkExt as _, StreamExt as _, TryStreamExt};

    use super::*;
    use crate::testutil::TestStream;

    /// Returns a [`Transport`] implementation and its paired remote end.
    ///
    /// The frame type sent by a `TestTransport` is received by the remote end,
    /// but the frame type sent by the remote end is ignored.
    pub fn new_transport(
        channel_size: usize,
    ) -> (
        impl Transport + Debug,
        TestStream<(FrameType, Bytes), IoError>,
    ) {
        let (a, b) = TestStream::new_pair(channel_size);
        (TryStreamExt::map_ok(a, |(_frame_type, bytes)| bytes), b)
    }

    pub trait ErrorSink {
        fn send_error(
            &mut self,
            err: IoError,
        ) -> impl Future<Output = Result<(), Option<IoError>>> + Send;
    }

    impl<F> ErrorSink for futures_util::stream::MapOk<TestStream<(FrameType, Bytes), IoError>, F> {
        fn send_error(
            &mut self,
            err: IoError,
        ) -> impl Future<Output = Result<(), Option<IoError>>> + Send {
            self.get_mut().send_error(err)
        }
    }

    /// Returns paired [`Transport`] implementations.
    ///
    /// The frame types sent to the transports are dropped immediately.
    pub fn new_transport_pair(
        channel_size: usize,
    ) -> (
        impl Transport + Debug + ErrorSink,
        impl Transport + Debug + ErrorSink,
    ) {
        let (a, b) = TestStream::new_pair(channel_size);
        let drop_frame_type = |(_frame_type, item)| item;
        (a.map_ok(drop_frame_type), b.map_ok(drop_frame_type))
    }

    /// Returns a future that echoes incoming payloads back to the same
    /// transport.
    pub async fn echo_forever(
        mut transport: impl Transport + Unpin,
        mut server_state: snow::TransportState,
    ) {
        log::debug!("beginning server echo");
        while let Some(block) = transport.next().await.transpose().unwrap() {
            let payload = {
                let mut payload = vec![0; 65535];
                let len = server_state.read_message(&block, &mut payload).unwrap();
                payload.truncate(len);
                payload
            };
            let mut message = vec![0; 65535];
            let len = server_state.write_message(&payload, &mut message).unwrap();
            transport
                .send((FrameType::Data, Bytes::copy_from_slice(&message[..len])))
                .await
                .unwrap();
        }
    }
}
