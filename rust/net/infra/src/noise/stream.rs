//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Error as IoError;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use attest::client_connection::{ClientConnection, NOISE_TRANSPORT_PER_PAYLOAD_MAX};
use bytes::Bytes;
use futures_util::stream::FusedStream;
use futures_util::{SinkExt as _, StreamExt as _};
use snow::TransportState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::Connection;
use crate::noise::{FrameType, Transport};

/// Stream abstraction that encrypts/decrypts with [Noise].
///
/// Implements [`AsyncRead`] and [`AsyncWrite`] over a block-based [`Transport`]
/// implementation by passing sent and received bytes through a
/// [`snow::TransportState`] instance to encrypt and decrypt.
///
/// [Noise]: https://noiseprotocol.org/noise.html
#[cfg_attr(any(test, feature = "test-util"), derive(Debug))]
pub struct NoiseStream<S> {
    inner: S,
    transport: ClientConnection,
    write: Write,
    read: Read,
}

#[derive(Debug, Default)]
struct Write {
    buffer: WriteBuffer,
}

#[derive(Debug, Default)]
enum Read {
    #[default]
    AwaitingBlock,
    ReadFromBlock(Bytes),
}

#[derive(Debug)]
struct WriteBuffer {
    length: u16,
    bytes: Box<[u8; NOISE_TRANSPORT_PER_PAYLOAD_MAX]>,
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

impl<S: Connection> Connection for NoiseStream<S> {
    fn transport_info(&self) -> crate::TransportInfo {
        self.inner.transport_info()
    }
}

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
                let plaintext = transport.recv(&block).map_err(IoError::other)?;
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
            write: Write { buffer },
            read: _,
        } = self.get_mut();

        let bytes_remaining = buffer.bytes.len() - usize::from(buffer.length);

        if bytes_remaining == 0 {
            // We need to make space by flushing the contents of the buffer.
            let () = ready!(buffer.poll_flush(ptr, cx, transport, inner))?;

            debug_assert_eq!(buffer.length, 0);
        }

        let count = buffer.copy_prefix(buf);
        log::trace!("{ptr:x?} buffered {count} bytes");
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        let ptr = &*self as *const Self;

        let Self {
            transport,
            inner,
            write: Write { buffer },
            read: _,
        } = self.get_mut();

        if buffer.length != 0 {
            log::trace!("{ptr:x?} trying to flush write buffer");
            let () = ready!(buffer.poll_flush(ptr, cx, transport, inner))?;

            debug_assert_eq!(buffer.length, 0);
        }

        inner.poll_flush_unpin(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        let ptr = &*self as *const Self;

        let Self {
            transport,
            inner,
            write: Write { buffer },
            read: _,
        } = self.get_mut();

        if buffer.length != 0 {
            log::trace!("{ptr:x?} flushing write buffer before shutdown");
            let () = ready!(buffer.poll_flush(ptr, cx, transport, inner))?;

            debug_assert_eq!(buffer.length, 0);
        }

        inner.poll_close_unpin(cx)
    }
}

impl WriteBuffer {
    fn poll_flush<S: Transport + Unpin>(
        &mut self,
        ptr: *const NoiseStream<S>,
        cx: &mut Context<'_>,
        transport: &mut ClientConnection,
        inner: &mut S,
    ) -> Poll<Result<(), IoError>> {
        // Check to see if the inner sink is ready before doing anything expensive
        // or destructive.
        let () = ready!(inner.poll_ready_unpin(cx))?;

        let Self { length, bytes } = self;

        log::trace!("{ptr:x?} encrypting {} bytes to send", length);
        let ciphertext = transport
            .send(&bytes[..usize::from(*length)])
            .map_err(IoError::other)?;
        log::trace!("{ptr:x?} encrypted to {} bytes", ciphertext.len());

        *length = 0;

        // Since the poll_ready above already succeeded, we can just send!
        inner.start_send_unpin((FrameType::Data, ciphertext.into()))?;

        log::trace!("{ptr:x?} flushed write buffer");
        Poll::Ready(Ok(()))
    }

    fn copy_prefix(&mut self, buf: &[u8]) -> usize {
        let Self { bytes, length } = self;
        let bytes_remaining = bytes.len() - usize::from(*length);

        let to_copy = buf.len().min(bytes_remaining);
        bytes[(*length).into()..][..to_copy].copy_from_slice(&buf[..to_copy]);
        *length += u16::try_from(to_copy).expect("small buffer");

        to_copy
    }
}

impl Default for WriteBuffer {
    fn default() -> Self {
        Self {
            length: 0,
            bytes: Box::new([0; NOISE_TRANSPORT_PER_PAYLOAD_MAX]),
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::ErrorKind as IoErrorKind;
    use std::pin::pin;
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use attest::client_connection::NOISE_TRANSPORT_PER_PACKET_MAX;
    use const_str::concat;
    use futures_util::stream::FusedStream;
    use futures_util::{FutureExt, Sink, Stream};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::noise::testutil::{ErrorSink as _, echo_forever, new_transport_pair};
    use crate::noise::{FrameType, HandshakeAuthKind};
    use crate::utils::testutil::TestWaker;

    fn new_stream_pair() -> (NoiseStream<impl Transport>, NoiseStream<impl Transport>) {
        let (transport_a, transport_b) = new_handshaken_pair().unwrap();
        let (a, b) = new_transport_pair(100);
        let a = NoiseStream::new(a, transport_a, vec![0u8; 32]);
        let b = NoiseStream::new(b, transport_b, vec![0u8; 32]);
        (a, b)
    }

    #[tokio::test]
    async fn send_and_receive() {
        let (mut a, mut b) = new_stream_pair();

        a.write_all(b"abcde").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0; 5];
        assert_eq!(buf.len(), b.read(&mut buf).await.unwrap());
        assert_eq!(&buf, b"abcde");

        b.write_all(b"1234567890").await.unwrap();
        b.flush().await.unwrap();
        b.write_all(b"abcdefghij").await.unwrap();
        b.flush().await.unwrap();
        let mut buf = [0; 20];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"1234567890abcdefghij");
    }

    #[tokio::test]
    async fn write_is_buffered() {
        // MITM the two streams so we can see when blocks pass through.
        let (transport_a, transport_d) = new_handshaken_pair().unwrap();
        let (a, mut b) = new_transport_pair(2);
        let (mut c, d) = new_transport_pair(2);
        let mut a = NoiseStream::new(a, transport_a, vec![0; 32]);
        let mut d = NoiseStream::new(d, transport_d, vec![0; 32]);

        a.write_all(&[b'a'; NOISE_TRANSPORT_PER_PAYLOAD_MAX - 1])
            .await
            .unwrap();
        assert_matches!(b.next().now_or_never(), None);

        a.write_all(&[b'b'; NOISE_TRANSPORT_PER_PAYLOAD_MAX + 1])
            .await
            .unwrap();

        // The second write should have spilled the buffer into the stream,
        // resulting in one block sent.
        let first_block = b.next().await.expect("received").expect("msg");
        assert_matches!(b.next().now_or_never(), None);

        assert!(
            first_block.len() <= NOISE_TRANSPORT_PER_PACKET_MAX,
            "first_block.len() = {}",
            first_block.len()
        );

        c.send((FrameType::Data, first_block)).await.unwrap();
        let mut buf = [0; NOISE_TRANSPORT_PER_PAYLOAD_MAX];
        d.read_exact(&mut buf).await.expect("can read");

        assert_eq!(
            buf.split_last(),
            Some((
                &b'b',
                [b'a'; NOISE_TRANSPORT_PER_PAYLOAD_MAX - 1].as_slice()
            ))
        );

        a.flush().await.unwrap();
        c.send((FrameType::Data, b.next().await.unwrap().unwrap()))
            .await
            .unwrap();

        let mut buf = [0; NOISE_TRANSPORT_PER_PAYLOAD_MAX];
        d.read_exact(&mut buf).await.expect("can read");
        assert_eq!(buf, [b'b'; NOISE_TRANSPORT_PER_PAYLOAD_MAX].as_slice());
    }

    #[tokio::test]
    async fn write_flushes_on_shutdown() {
        let (mut a, mut b) = new_stream_pair();

        a.write_all(b"abcdef").await.unwrap();
        a.shutdown().await.unwrap();

        let mut buf = vec![];
        b.read_to_end(&mut buf).await.expect("can read");
        assert_eq!(&buf, b"abcdef");
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

    #[tokio::test]
    async fn read_returns_inner_error() {
        let (transport, _) = new_handshaken_pair().unwrap();
        let (inner, mut other) = new_transport_pair(100);
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
        let (inner, other) = new_transport_pair(100);
        let mut stream = NoiseStream::new(inner, transport, vec![0u8; 32]);

        // Drop the read end. With nobody to receive sent bytes, the write and
        // flush to the underlying channel should fail.
        drop(other);
        assert_matches!(stream.write_all(b"ababcdcdefef").await, Ok(()));
        assert_matches!(stream.flush().await, Err(_));
    }

    #[tokio::test]
    async fn ignores_unexpected_frame_type() {
        let (transport, mut server) = new_handshaken_pair().unwrap();
        let (inner, mut other) = new_transport_pair(100);
        let mut stream = NoiseStream::new(inner, transport, vec![0u8; 32]);
        const CLEARTEXT: &[u8] = b"hi there";

        // Encrypt correctly but send the wrong frame type. That won't matter
        // since the client end doesn't receive the frame type from the
        // Transport.
        {
            let mut payload = [0; 64];
            let len = server.write_message(CLEARTEXT, &mut payload).unwrap();
            other
                .send((
                    FrameType::Auth(HandshakeAuthKind::IK),
                    Bytes::copy_from_slice(&payload[..len]),
                ))
                .await
                .unwrap();
        }

        let read = stream
            .read(&mut [0; 32])
            .await
            .expect("wrong frame type wasn't ignored");
        assert_eq!(read, CLEARTEXT.len());
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
        let (inner, other) = new_transport_pair(1);
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
        let (a, b) = new_transport_pair(CHANNEL_SIZE);
        let mut a = NoiseStream::new(a, transport_a, vec![0u8; 32]);
        let mut b = NoiseStream::new(b, transport_b, vec![0u8; 32]);

        assert_matches!(a.write(b"first message").now_or_never(), Some(Ok(13)));
        assert_matches!(a.flush().now_or_never(), Some(Ok(())));
        assert_matches!(a.write(b"second message").now_or_never(), Some(Ok(14)));
        assert_matches!(a.flush().now_or_never(), Some(Ok(())));

        assert_matches!(a.write(b"third message").now_or_never(), Some(Ok(13)));
        let mut a_flush = pin!(a.flush());
        let a_flush_waker = Arc::new(TestWaker::default());
        assert_matches!(
            a_flush.poll_unpin(&mut std::task::Context::from_waker(
                &Arc::clone(&a_flush_waker).into()
            )),
            Poll::Pending
        );
        assert!(!a_flush_waker.was_woken());

        let mut read_buf = vec![0; 64];
        assert_matches!(b.read(&mut read_buf).now_or_never(), Some(Ok(13)));
        assert_eq!(&read_buf[..13], b"first message");

        // Reading a message from the stream should unblock the writer.
        assert!(a_flush_waker.was_woken());
        assert_matches!(
            a_flush.poll_unpin(&mut std::task::Context::from_waker(&a_flush_waker.into())),
            Poll::Ready(Ok(()))
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
