//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::pin::Pin;
use std::task::{ready, Poll};

use bytes::Bytes;
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::Message;

pub struct WebSocketTransport<S>(pub WebSocketStream<S>);

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum TransportError {
    /// websocket unexpectedly closed with code {code:?}
    UnexpectedClose { code: CloseCode },
    /// websocket received a text frame ({bytes} bytes)
    UnexpectedTextFrame { bytes: usize },
}

impl<S: AsyncRead + AsyncWrite + Unpin> Sink<Bytes> for WebSocketTransport<S> {
    type Error = IoError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready_unpin(cx).map_err(into_io_error)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.0
            .start_send_unpin(Message::Binary(item.into()))
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
                Some(Message::Binary(bytes)) => Some(Ok(bytes.into())),
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
    let (error_kind, error) = match e {
        tungstenite::Error::Io(io_error) => return io_error,
        e @ (tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
            (IoErrorKind::BrokenPipe, crate::ws::Error::from(e))
        }
        e @ (tungstenite::Error::Tls(_)
        | tungstenite::Error::Capacity(_)
        | tungstenite::Error::Protocol(_)
        | tungstenite::Error::WriteBufferFull(_)
        | tungstenite::Error::Utf8
        | tungstenite::Error::AttackAttempt
        | tungstenite::Error::Url(_)
        | tungstenite::Error::Http(_)
        | tungstenite::Error::HttpFormat(_)) => (IoErrorKind::Other, e.into()),
    };

    IoError::new(error_kind, error)
}
