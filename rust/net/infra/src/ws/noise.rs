//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::pin::Pin;
use std::task::{Poll, ready};

use bytes::Bytes;
use futures_util::stream::FusedStream;
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};
use static_assertions::assert_impl_all;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tungstenite::Message;
use tungstenite::protocol::frame::coding::CloseCode;

use crate::noise::{FrameType, Transport};

/// A [`noise::Transport`](Transport) implementation over a websocket.
///
/// This is a simple wrapper over a [`WebSocketStream`] that sends and receives
/// Noise frames as [`Message::Binary`] messages.
pub struct WebSocketTransport<S>(pub WebSocketStream<S>);

assert_impl_all!(WebSocketTransport<tokio::io::DuplexStream>: Transport);

/// Errors encountered during [`WebSocketTransport`] as [`Transport`] operation.
///
/// This is a simple error type that is convertible to [`std::io::Error`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum TransportError {
    /// websocket unexpectedly closed with code {code:?}
    UnexpectedClose { code: CloseCode },
    /// websocket received a text frame ({bytes} bytes)
    UnexpectedTextFrame { bytes: usize },
}

impl<S: AsyncRead + AsyncWrite + Unpin> Sink<(FrameType, Bytes)> for WebSocketTransport<S> {
    type Error = IoError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready_unpin(cx).map_err(into_io_error)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        (_frame_type, item): (FrameType, Bytes),
    ) -> Result<(), Self::Error> {
        self.0
            .start_send_unpin(Message::Binary(item))
            .map_err(into_io_error)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.0.poll_flush_unpin(cx).map_err(into_io_error)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.0.poll_close_unpin(cx).map_err(into_io_error)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream for WebSocketTransport<S> {
    type Item = Result<Bytes, IoError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let message = ready!(self.0.poll_next_unpin(cx))
            .transpose()
            .map_err(into_io_error)?;
        Poll::Ready(
            match message {
                Some(Message::Ping(_)) => return self.poll_next(cx),
                Some(Message::Pong(_)) => return self.poll_next(cx),
                Some(Message::Binary(bytes)) => Some(Ok(bytes)),
                None | Some(Message::Close(None)) => None,
                Some(Message::Close(Some(frame)))
                    if frame.code == CloseCode::Normal && frame.reason.is_empty() =>
                {
                    None
                }
                Some(Message::Close(Some(frame))) => {
                    Some(Err(TransportError::UnexpectedClose { code: frame.code }))
                }
                Some(Message::Text(text)) => Some(Err(TransportError::UnexpectedTextFrame {
                    bytes: text.len(),
                })),
                Some(Message::Frame(_)) => unreachable!("can't get from read"),
            }
            .map(|r| r.map_err(Into::into)),
        )
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> FusedStream for WebSocketTransport<S> {
    fn is_terminated(&self) -> bool {
        FusedStream::is_terminated(&self.0)
    }
}

impl From<TransportError> for IoError {
    fn from(value: TransportError) -> Self {
        let kind = match &value {
            TransportError::UnexpectedClose { .. } => IoErrorKind::UnexpectedEof,
            TransportError::UnexpectedTextFrame { .. } => IoErrorKind::InvalidData,
        };
        IoError::new(kind, value)
    }
}

fn into_io_error(e: tungstenite::Error) -> IoError {
    let error_kind = match e {
        tungstenite::Error::Io(io_error) => return io_error,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            IoErrorKind::BrokenPipe
        }
        tungstenite::Error::Tls(_)
        | tungstenite::Error::Capacity(_)
        | tungstenite::Error::Protocol(_)
        | tungstenite::Error::WriteBufferFull(_)
        | tungstenite::Error::Utf8(_)
        | tungstenite::Error::AttackAttempt
        | tungstenite::Error::Url(_)
        | tungstenite::Error::Http(_)
        | tungstenite::Error::HttpFormat(_) => IoErrorKind::Other,
    };

    IoError::new(error_kind, crate::ws::WebSocketError::from(e))
}
