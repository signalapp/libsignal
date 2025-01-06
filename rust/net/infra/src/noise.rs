//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use attest::client_connection::ClientConnection;
use bytes::Bytes;
use futures_util::stream::FusedStream;
use futures_util::{Sink, SinkExt as _, StreamExt as _};
use snow::TransportState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Stream abstraction that encrypts/decrypts with [Noise].
///
/// Implements [`AsyncRead`] and [`AsyncWrite`] over a block-based [`Transport`]
/// implementation by passing sent and received bytes through a
/// [`snow::TransportState`] instance to encrypt and decrypt.
///
/// [Noise]: https://noiseprotocol.org/noise.html
pub struct NoiseStream<S> {
    inner: S,
    transport: ClientConnection,
    write: Write,
    read: Read,
}

#[derive(Debug, Default)]
struct Write {
    buffer_policy: WriteBufferPolicy,
}

#[derive(Debug, Default)]
enum Read {
    #[default]
    AwaitingBlock,
    ReadFromBlock(Bytes),
}

#[derive(Debug, Default)]
enum WriteBufferPolicy {
    #[default]
    NoBuffering,
}

impl<S> NoiseStream<S> {
    /// Creates a new `NoiseStream` for an already-established transport that
    /// reads and writes to the provided stream/sink.
    pub fn new(inner: S, transport: TransportState, handshake_hash: Vec<u8>) -> Self {
        Self {
            inner,
            transport: ClientConnection {
                handshake_hash,
                transport,
            },
            read: Read::default(),
            write: Write::default(),
        }
    }
}

/// Convenience alias for types that implement [`FusedStream`] and [`Sink`] for
/// `NoiseStream` to wrap.
///
/// A blanket implementation is provided for types with compatible `Stream` and
/// `Sink` implementations.
pub trait Transport:
    FusedStream<Item = Result<Bytes, IoError>> + Sink<Bytes, Error = IoError>
{
}

impl<S: FusedStream<Item = Result<Bytes, IoError>> + Sink<Bytes, Error = IoError>> Transport for S {}

impl<S: Transport + Unpin> AsyncRead for NoiseStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let ptr = &*self as *const Self;
        let Self {
            transport,
            inner,
            read,
            write: _,
        } = self.get_mut();

        let read_from = match read {
            Read::AwaitingBlock => {
                log::trace!("{ptr:x?} trying to receive block");
                let next_block = if inner.is_terminated() {
                    None
                } else {
                    ready!(inner.poll_next_unpin(cx)).transpose()?
                };

                let block = match next_block {
                    None => {
                        log::debug!("{ptr:x?} got EOS, no more blocks");
                        return Poll::Ready(Ok(()));
                    }
                    Some(block) => block,
                };

                log::trace!("{ptr:x?} received block, decrypting");
                let plaintext = transport
                    .recv(&block)
                    .map_err(|e| IoError::new(IoErrorKind::Other, e))?;
                log::trace!("{ptr:x?} decrypted successfully");

                *read = Read::ReadFromBlock(plaintext.into());
                let Read::ReadFromBlock(block) = read else {
                    unreachable!("just set");
                };
                block
            }
            Read::ReadFromBlock(bytes) => bytes,
        };

        let read_amount = read_from.len().min(buf.remaining());
        log::trace!("{ptr:x?} reading {read_amount} bytes from the last block");
        buf.put_slice(&read_from[..read_amount]);

        let _ = read_from.split_to(read_amount);
        if read_from.is_empty() {
            *read = Read::AwaitingBlock;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: Transport + Unpin> AsyncWrite for NoiseStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        let ptr = &*self as *const Self;

        let Self {
            transport,
            inner,
            write,
            read: _,
        } = self.get_mut();

        let () = ready!(inner.poll_ready_unpin(cx))?;

        let WriteBufferPolicy::NoBuffering = write.buffer_policy;
        log::trace!("{ptr:x?} encrypting {} bytes to send", buf.len());
        let ciphertext = transport
            .send(buf)
            .map_err(|e| IoError::new(IoErrorKind::Other, e))?;
        log::trace!("{ptr:x?} encrypted to {} bytes", ciphertext.len());

        // Since the poll_ready above already succeeded, we can just send!
        inner.start_send_unpin(ciphertext.into())?;

        log::trace!("{ptr:x?} sent, waiting for next block");

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        self.get_mut().inner.poll_flush_unpin(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        self.get_mut().inner.poll_close_unpin(cx)
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use super::*;

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
                .send(Bytes::copy_from_slice(&message[..len]))
                .await
                .unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use const_str::concat;
    use futures_util::stream::FusedStream;
    use futures_util::{pin_mut, FutureExt, Stream};
    use testutil::echo_forever;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::testutil::TestStream;
    use crate::utils::testutil::TestWaker;

    fn new_handshaken_pair() -> Result<(TransportState, TransportState), snow::Error> {
        const PATTERN: &str = "Noise_NN_25519_ChaChaPoly_SHA256";

        let mut initiator = snow::Builder::new(PATTERN.parse().unwrap()).build_initiator()?;
        let mut responder = snow::Builder::new(PATTERN.parse().unwrap()).build_responder()?;

        let (mut read_buf, mut first_msg, mut second_msg) = ([0u8; 1024], [0u8; 1024], [0u8; 1024]);

        let len = initiator.write_message(&[], &mut first_msg)?;
        responder.read_message(&first_msg[..len], &mut read_buf)?;

        let len = responder.write_message(&[], &mut second_msg)?;
        initiator.read_message(&second_msg[..len], &mut read_buf)?;

        Ok((
            initiator.into_transport_mode()?,
            responder.into_transport_mode()?,
        ))
    }

    fn new_stream_pair() -> (NoiseStream<impl Transport>, NoiseStream<impl Transport>) {
        let (transport_a, transport_b) = new_handshaken_pair().unwrap();
        let (a, b) = TestStream::new_pair(100);
        let a = NoiseStream::new(a, transport_a, vec![0u8; 32]);
        let b = NoiseStream::new(b, transport_b, vec![0u8; 32]);
        (a, b)
    }

    #[tokio::test]
    async fn send_and_receive() {
        let (mut a, mut b) = new_stream_pair();

        a.write_all(b"abcde").await.unwrap();
        let mut buf = [0; 5];
        assert_eq!(buf.len(), b.read(&mut buf).await.unwrap());
        assert_eq!(&buf, b"abcde");

        b.write_all(b"1234567890").await.unwrap();
        b.write_all(b"abcdefghij").await.unwrap();
        let mut buf = [0; 20];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"1234567890abcdefghij");
    }

    #[tokio::test]
    async fn graceful_close() {
        const MESSAGE: &[u8] = b"message";
        let (mut a, mut b) = new_stream_pair();

        a.write_all(MESSAGE).await.unwrap();
        a.flush().await.unwrap();
        drop(a);

        let mut buf = [0; MESSAGE.len()];
        assert_eq!(b.read(&mut buf).await.unwrap(), MESSAGE.len());
        assert_eq!(buf, MESSAGE);

        assert_matches!(b.read(&mut buf).await, Ok(0));
    }

    #[tokio::test]
    async fn read_returns_inner_error() {
        let (transport, _) = new_handshaken_pair().unwrap();
        let (inner, mut other) = TestStream::new_pair(100);
        let mut stream = NoiseStream::new(inner, transport, vec![0u8; 32]);
        stream.write_all(b"ababcdcdefef").await.unwrap();

        other
            .send_error(IoError::new(IoErrorKind::UnexpectedEof, "fake EOF"))
            .await
            .unwrap();

        assert_matches!(stream.read(&mut [0; 32]).await, Err(e) if e.kind() == IoErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn returns_write_error() {
        let (transport, _) = new_handshaken_pair().unwrap();
        let (inner, other) = TestStream::new_pair(100);
        let mut stream = NoiseStream::new(inner, transport, vec![0u8; 32]);

        // Drop the read end. With nobody to receive sent bytes, the write to
        // the underlying channel should fail.
        drop(other);
        assert_matches!(stream.write_all(b"ababcdcdefef").await, Err(_));
    }

    /// [Transport] that terminates after `remaining` items are emitted.
    struct TerminateStreamAfter<S> {
        remaining: usize,
        inner: S,
    }

    impl<S: Stream + Unpin> Stream for TerminateStreamAfter<S> {
        type Item = S::Item;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let Self { remaining, inner } = self.get_mut();
            if *remaining == 0 {
                panic!("polled while terminated");
            }

            Poll::Ready(match ready!(inner.poll_next_unpin(cx)) {
                Some(item) => {
                    *remaining -= 1;
                    Some(item)
                }
                None => None,
            })
        }
    }

    /// Pass-through implementation
    impl<S: Sink<T> + Unpin, T> Sink<T> for TerminateStreamAfter<S> {
        type Error = S::Error;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut().inner.poll_ready_unpin(cx)
        }

        fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
            self.get_mut().inner.start_send_unpin(item)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut().inner.poll_flush_unpin(cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut().inner.poll_close_unpin(cx)
        }
    }

    impl<S: Stream + Unpin> FusedStream for TerminateStreamAfter<S> {
        fn is_terminated(&self) -> bool {
            self.remaining == 0
        }
    }

    #[tokio::test]
    async fn respects_fused_is_terminated() {
        let (transport, other_transport) = new_handshaken_pair().unwrap();
        let (inner, other) = TestStream::new_pair(1);
        let inner = TerminateStreamAfter {
            remaining: 2,
            inner,
        };
        let mut stream = NoiseStream::new(inner, transport, vec![0u8; 32]);

        let _echo_task = tokio::spawn(echo_forever(other, other_transport));

        let mut read_buf = [0; 32];

        // The first two blocks should be received and echoed.
        assert_matches!(stream.write(b"first").await, Ok(5));
        stream.flush().await.unwrap();
        assert_matches!(stream.read(&mut read_buf).await, Ok(5));

        assert_matches!(stream.write(b"second").await, Ok(6));
        stream.flush().await.unwrap();
        assert_matches!(stream.read(&mut read_buf).await, Ok(6));

        // The next block should be sent and echoed, but then not received
        // because the stream is terminated.
        assert_matches!(stream.write(b"second").await, Ok(6));
        stream.flush().await.unwrap();

        assert_matches!(stream.read(&mut read_buf).await, Ok(0));
        // Reading again is safe but should again return EOF.
        assert_matches!(stream.read(&mut read_buf).await, Ok(0));
    }

    #[test]
    fn write_with_full_transport_send_queue() {
        const CHANNEL_SIZE: usize = 2;
        let (transport_a, transport_b) = new_handshaken_pair().unwrap();
        let (a, b) = TestStream::new_pair(CHANNEL_SIZE);
        let mut a = NoiseStream::new(a, transport_a, vec![0u8; 32]);
        let mut b = NoiseStream::new(b, transport_b, vec![0u8; 32]);

        assert_matches!(a.write(b"first message").now_or_never(), Some(Ok(13)));
        assert_matches!(a.write(b"second message").now_or_never(), Some(Ok(14)));

        let a_write = a.write(b"third message");
        pin_mut!(a_write);
        let a_write_waker = Arc::new(TestWaker::default());
        assert_matches!(
            a_write.poll_unpin(&mut std::task::Context::from_waker(
                &Arc::clone(&a_write_waker).into()
            )),
            Poll::Pending
        );
        assert!(!a_write_waker.was_woken());

        let mut read_buf = vec![0; 64];
        assert_matches!(b.read(&mut read_buf).now_or_never(), Some(Ok(13)));
        assert_eq!(&read_buf[..13], b"first message");

        // Reading a message from the stream should unblock the writer.
        assert!(a_write_waker.was_woken());
        assert_matches!(
            a_write.poll_unpin(&mut std::task::Context::from_waker(&a_write_waker.into())),
            Poll::Ready(Ok(13))
        );

        drop(a);

        // Make sure no messages were dropped or mangled.
        read_buf.clear();
        assert_matches!(b.read_to_end(&mut read_buf).now_or_never(), Some(Ok(27)));
        assert_eq!(
            &read_buf[..27],
            concat!("second message", "third message").as_bytes()
        );
    }
}
