//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::io::Error as IoError;

use bytes::Bytes;
use futures_util::stream::FusedStream;
use futures_util::{Sink, TryFutureExt};

use crate::errors::TransportConnectError;
use crate::route::{Connector, NoiseRouteFragment};

mod direct;
pub use direct::DirectStream;
mod handshake;
pub use handshake::*;
mod stream;
pub use stream::NoiseStream;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SendError {
    /// {0}
    Io(#[from] IoError),
    /// {0}
    Noise(#[from] snow::Error),
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

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ConnectError {
    /// {0}
    Send(#[from] SendError),
    /// {0}
    Transport(#[from] TransportConnectError),
}

/// [`Connector`] that performs a Noise [handshake] to establish a [`NoiseStream`].
///
/// On success, the returned connection is a [`NoiseStream`] that can be used as
/// an [`AsyncRead`] & [`AsyncWrite`] stream and the initial payload sent with
/// the handshake response.
///
/// [`AsyncRead`]: tokio::io::AsyncRead
/// [`AsyncWrite`]: tokio::io::AsyncWrite
#[derive(Clone, Debug)]
pub struct NoiseConnector;

/// [`Connector`] that wraps a [`Transport`] stream into a [`NoiseStream`].
pub struct NoiseDirectConnector<C>(pub C);

impl<Inner: Transport + Send + Unpin, N: NoiseHandshake + Send>
    Connector<NoiseRouteFragment<N>, Inner> for NoiseConnector
{
    type Connection = (NoiseStream<Inner>, Box<[u8]>);

    type Error = SendError;

    async fn connect_over(
        &self,
        over: Inner,
        route: NoiseRouteFragment<N>,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        let NoiseRouteFragment {
            handshake: noise_handshake,
            initial_payload,
        } = route;
        log::debug!(
            "[{log_tag}] performing Noise {} handshake",
            noise_handshake.auth_kind()
        );

        handshake(
            over,
            noise_handshake,
            initial_payload.as_ref().map(AsRef::as_ref),
        )
        .await
        .inspect_err(|e| match e {
            SendError::Io(_) => (),
            SendError::Noise(e) => log::warn!("[{log_tag}] Noise handshake failed: {e}"),
        })
    }
}

impl<C: Connector<R, Inner>, R, Inner> Connector<R, Inner> for NoiseDirectConnector<C> {
    type Connection = DirectStream<C::Connection>;

    type Error = C::Error;

    fn connect_over(
        &self,
        over: Inner,
        route: R,
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let Self(c) = self;
        c.connect_over(over, route, log_tag)
            .map_ok(DirectStream::new)
    }
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
