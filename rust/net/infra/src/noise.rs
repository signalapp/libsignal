//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
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
    FusedStream<Item = Result<(Self::FrameType, Bytes), IoError>>
    + Sink<(Self::FrameType, Bytes), Error = IoError>
{
    type FrameType: TransportFrameType;
}

/// The type of a frame sent over a [`Transport`].
///
/// This represents the frame type sent "over the wire". It provides a
/// surjective mapping from [`HandshakeAuthKind`] to an inhabited type `Self`,
/// though it is legal (and the case for [`Untyped`]) to map all values to the
/// same frame type.
pub trait TransportFrameType: Display + PartialEq {
    const DATA: Self;

    fn from_auth(auth: HandshakeAuthKind) -> Self;
}

impl<F, S> Transport for S
where
    F: TransportFrameType,
    S: FusedStream<Item = Result<(F, Bytes), IoError>> + Sink<(F, Bytes), Error = IoError>,
{
    type FrameType = F;
}

/// [`TransportFrameType`] implementation for transports that don't
/// differentiate frame types.
#[derive(Copy, Clone, Debug, Default, PartialEq, derive_more::Display)]
#[display("untyped")]
pub struct Untyped;

impl TransportFrameType for Untyped {
    const DATA: Self = Self;

    fn from_auth(_: HandshakeAuthKind) -> Self {
        Self
    }
}

/// [`TransportFrameType`] implementation for transports that do differentiate frame types.
#[derive(Copy, Clone, Debug, PartialEq, displaydoc::Display, derive_more::From)]
pub enum FrameType {
    /// data
    Data,

    /// {0} auth
    Auth(#[from] HandshakeAuthKind),
}

impl TransportFrameType for FrameType {
    const DATA: Self = Self::Data;

    fn from_auth(auth: HandshakeAuthKind) -> Self {
        Self::Auth(auth)
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use futures_util::{SinkExt as _, StreamExt as _};

    use super::*;

    /// Returns a future that echoes incoming payloads back to the same
    /// transport.
    pub async fn echo_forever(
        mut transport: impl Transport + Unpin,
        mut server_state: snow::TransportState,
    ) {
        log::debug!("beginning server echo");
        while let Some((frame_type, block)) = transport.next().await.transpose().unwrap() {
            let payload = {
                let mut payload = vec![0; 65535];
                let len = server_state.read_message(&block, &mut payload).unwrap();
                payload.truncate(len);
                payload
            };
            let mut message = vec![0; 65535];
            let len = server_state.write_message(&payload, &mut message).unwrap();
            transport
                .send((frame_type, Bytes::copy_from_slice(&message[..len])))
                .await
                .unwrap();
        }
    }
}
