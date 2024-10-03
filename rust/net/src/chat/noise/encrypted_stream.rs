//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Error as IoError;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use futures_util::FutureExt;
use libsignal_core::Aci;
use libsignal_net_infra::noise::{NoiseStream, Transport};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use super::handshake::{HandshakeAuth, Handshaker, EPHEMERAL_KEY_LEN, STATIC_KEY_LEN};
use super::waker::SharedWakers;
use super::SendError;

/// A Noise-encrypted stream that wraps an underlying block-based [`Transport`].
///
/// The stream type `S` must implement `Transport`.
pub struct EncryptedStream<S> {
    inner: Inner<S>,
}

/// How to identify the client to the server.
#[derive(Clone, Debug, PartialEq)]
pub enum Authorization {
    /// Authenticate as the provided account/device to a known server.
    Authenticated {
        aci: Aci,
        device_id: u8,
        server_public_key: [u8; STATIC_KEY_LEN],
        client_private_key: [u8; EPHEMERAL_KEY_LEN],
    },
    /// Connect to a known server as an anonymous client.
    Anonymous {
        server_public_key: [u8; STATIC_KEY_LEN],
    },
}

impl<S> EncryptedStream<S> {
    /// Creates a new stream over the provided transport with the given identification.
    pub fn new(authorization: Authorization, transport: S) -> Self {
        Self {
            inner: Inner::Nascent {
                auth: authorization,
                transport: Some(transport),
                buffer_policy: NascentBuffer::NoInitialPayload,
            },
        }
    }
}

enum Inner<S> {
    /// Initial state, before any bytes have been sent or received.
    Nascent {
        auth: Authorization,
        /// `Option`al so that the value can be taken during state transitions, otherwise always `Some`.
        transport: Option<S>,
        buffer_policy: NascentBuffer,
    },
    /// In the handshake phase, waiting for the server's response.
    Handshake {
        handshaker: Handshaker<S>,
        /// The waker state to provide when polling the handshaker.
        ///
        /// This should be used with [`Context::from_waker`] to provide the
        /// polling context for the handshaker. It holds wakers from read and
        /// write tasks an ensures that if the handshaker makes progress, both
        /// read and write tasks get woken up.
        wakers: SharedWakers,
    },
    /// Communicating over an established bidirectional stream.
    Established(NoiseStream<S>),
}

enum NascentBuffer {
    NoInitialPayload,
}

impl<S: Transport + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            Inner::Nascent {
                buffer_policy,
                auth,
                transport,
            } => match buffer_policy {
                NascentBuffer::NoInitialPayload => {
                    let handshaker = start_handshake(auth, transport)?;
                    self.inner = Inner::Handshake {
                        handshaker,
                        // We could save `cx.waker()` here as the read waker,
                        // but we're going to do it anyway in the branch for
                        // `Inner::Handshake` so just do it there.
                        wakers: Default::default(),
                    };
                    self.poll_read(cx, buf)
                }
            },
            Inner::Handshake { handshaker, wakers } => {
                // If the handshaker makes progress, we want it to wake up both
                // the read and write tasks. We ensure that by passing in a
                // context whose waker that will awake both, instead of the
                // context passed in from above.
                wakers.save_reader_from(cx);
                let stream =
                    ready!(handshaker.poll_unpin(&mut Context::from_waker(wakers.as_ref())))?;

                // The handshake finished, now move to the next state. We need
                // to wake the writer task if there is one. We don't need to
                // wake the read task since (a) that is the task that's
                // executing this code, and (b) we're going to call poll_read
                // which will either make progress or save the read task waker.
                wakers.wake_writer();
                self.inner = Inner::Established(stream);
                self.poll_read(cx, buf)
            }
            Inner::Established(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, AsBytes, FromZeroes, FromBytes)]
struct InitialPayloadAuth {
    uuid_high: zerocopy::big_endian::U64,
    uuid_low: zerocopy::big_endian::U64,
    device_id: u8,
}

impl InitialPayloadAuth {
    fn new(aci: Aci, device_id: u8) -> Self {
        let (uuid_high, uuid_low) = Uuid::from(aci).as_u64_pair();
        Self {
            uuid_high: uuid_high.into(),
            uuid_low: uuid_low.into(),
            device_id,
        }
    }
}

impl<S: Transport + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        match &mut self.inner {
            Inner::Nascent {
                auth,
                transport,
                buffer_policy,
            } => match buffer_policy {
                NascentBuffer::NoInitialPayload => {
                    let handshaker = start_handshake(auth, transport)?;

                    self.inner = Inner::Handshake {
                        handshaker,
                        // We could save `cx.waker()` here as the write waker,
                        // but we're going to do it anyway in the branch for
                        // `Inner::Handshake` so just do it there.
                        wakers: Default::default(),
                    };
                    self.poll_write(cx, buf)
                }
            },

            Inner::Handshake { handshaker, wakers } => {
                // Poll the handshaker with a context whose waker will wake both
                // read and write tasks. Record the waker from the write task polling here first.
                wakers.save_writer_from(cx);
                let stream: NoiseStream<_> =
                    ready!(handshaker.poll_unpin(&mut Context::from_waker(wakers.as_ref())))?;

                // The handshake finished, now move to the next state. We need
                // to wake the reader task if there is one. We don't need to
                // wake the writer task since (a) that is the task that's
                // executing this code, and (b) we're going to call poll_write
                // which will either make progress or save the write task waker.
                wakers.wake_reader();

                self.inner = Inner::Established(stream);
                self.poll_write(cx, buf)
            }
            Inner::Established(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        match &mut self.inner {
            Inner::Nascent {
                auth,
                transport,
                buffer_policy,
            } => match buffer_policy {
                NascentBuffer::NoInitialPayload => {
                    let handshaker = start_handshake(auth, transport)?;

                    self.inner = Inner::Handshake {
                        handshaker,
                        wakers: Default::default(),
                    };
                    self.poll_flush(cx)
                }
            },
            Inner::Handshake { handshaker, wakers } => {
                wakers.save_writer_from(cx);
                Pin::new(handshaker).poll_flush(&mut Context::from_waker(wakers.as_ref()))
            }
            Inner::Established(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        match &mut self.inner {
            Inner::Nascent {
                transport,
                auth: _,
                buffer_policy: _,
            } => {
                let transport = transport.as_mut().expect("only None after a state change");
                let () = ready!(Pin::new(transport).poll_close(cx))?;
                Poll::Ready(Ok(()))
            }
            Inner::Handshake { handshaker, wakers } => {
                wakers.save_writer_from(cx);
                handshaker.poll_shutdown(&mut Context::from_waker(wakers.as_ref()))
            }
            Inner::Established(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

fn start_handshake<S>(
    auth: &Authorization,
    transport: &mut Option<S>,
) -> Result<Handshaker<S>, SendError> {
    let (pattern, initial_payload) = match &auth {
        Authorization::Authenticated {
            aci,
            device_id,
            server_public_key,
            client_private_key,
        } => (
            HandshakeAuth::IK {
                server_public_key,
                client_private_key,
            },
            Some(InitialPayloadAuth::new(*aci, *device_id)),
        ),
        Authorization::Anonymous { server_public_key } => {
            (HandshakeAuth::NK { server_public_key }, None)
        }
    };
    Handshaker::new(
        transport.take().expect("always Some in Nascent state"),
        pattern,
        initial_payload.as_ref().map(AsBytes::as_bytes),
    )
    .map_err(SendError::Noise)
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use bytes::Bytes;
    use const_str::concat;
    use futures_util::{pin_mut, SinkExt, StreamExt};
    use hex_literal::hex;
    use libsignal_net_infra::noise::testutil::echo_forever;
    use libsignal_net_infra::testutil::TestStream;
    use libsignal_net_infra::utils::testutil::TestWaker;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::chat::noise::handshake::PAYLOAD_AEAD_TAG_LEN;

    async fn authenticating_server_handshake<S: Transport + Unpin>(
        transport: &mut S,
        mut server_state: snow::HandshakeState,
    ) -> (InitialPayloadAuth, snow::TransportState) {
        let auth = {
            let first = transport.next().await.unwrap().unwrap();
            let mut payload = [0; 128];
            let read_count = server_state.read_message(&first, &mut payload).unwrap();
            assert_eq!(read_count, std::mem::size_of::<InitialPayloadAuth>());
            InitialPayloadAuth::read_from_prefix(&payload).unwrap()
        };

        {
            let mut message = [0; 128];
            let written = server_state.write_message(&[], &mut message).unwrap();
            transport
                .send(Bytes::copy_from_slice(&message[..written]))
                .await
                .unwrap();
        }

        assert!(server_state.is_handshake_finished());
        (auth, server_state.into_transport_mode().unwrap())
    }

    async fn anonymous_server_handshake<S: Transport + Unpin>(
        transport: &mut S,
        mut server_state: snow::HandshakeState,
    ) -> snow::TransportState {
        {
            let first = transport.next().await.unwrap().unwrap();
            let mut payload = [0; 128];
            let read_count = server_state.read_message(&first, &mut payload).unwrap();
            assert_eq!(read_count, 0);
        };

        {
            let mut message = [0; 128];
            let written = server_state.write_message(&[], &mut message).unwrap();
            transport
                .send(Bytes::copy_from_slice(&message[..written]))
                .await
                .unwrap();
        }

        assert!(server_state.is_handshake_finished());
        server_state.into_transport_mode().unwrap()
    }

    const ACI: Aci = Aci::from_uuid_bytes(hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    const DEVICE_ID: u8 = 42;

    #[tokio::test]
    async fn encrypted_stream_authenticated_handshake_success() {
        let (a, b) = TestStream::new_pair(10);

        let server_builder = snow::Builder::new(
            crate::chat::noise::handshake::IK_NOISE_PATTERN
                .parse()
                .unwrap(),
        );

        let server_keypair = server_builder.generate_keypair().unwrap();
        let client_keypair = server_builder.generate_keypair().unwrap();

        let server_state = server_builder
            .local_private_key(&server_keypair.private)
            .remote_public_key(&client_keypair.public)
            .build_responder()
            .unwrap();

        let server = async {
            let mut transport = a;

            let (auth, server_state) =
                authenticating_server_handshake(&mut transport, server_state).await;

            assert_eq!(auth, InitialPayloadAuth::new(ACI, DEVICE_ID));

            // Echo back incoming payloads forever.
            echo_forever(transport, server_state).await;
        };

        let server_handle = tokio::spawn(server);

        let mut client = EncryptedStream::new(
            Authorization::Authenticated {
                aci: ACI,
                device_id: DEVICE_ID,
                server_public_key: server_keypair.public.try_into().unwrap(),
                client_private_key: client_keypair.private.try_into().unwrap(),
            },
            b,
        );

        client.write_all(b"message one").await.unwrap();
        client.write_all(b"message two").await.unwrap();
        client.flush().await.unwrap();

        let mut read_buf = [0; 2 * 11];
        let read_count = client.read_exact(&mut read_buf).await.unwrap();
        assert_eq!(read_count, read_buf.len());

        assert_eq!(read_buf, concat!("message one", "message two").as_bytes());

        drop(client);
        let () = server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn encrypted_stream_anonymous_handshake_success() {
        let (a, b) = TestStream::new_pair(10);

        let server_builder = snow::Builder::new(
            crate::chat::noise::handshake::NK_NOISE_PATTERN
                .parse()
                .unwrap(),
        );

        let server_keypair = server_builder.generate_keypair().unwrap();
        let server_state = server_builder
            .local_private_key(&server_keypair.private)
            .build_responder()
            .unwrap();

        let server = async {
            let mut transport = a;

            let server_state = anonymous_server_handshake(&mut transport, server_state).await;
            // Echo back incoming payloads forever.
            echo_forever(transport, server_state).await
        };

        let server_handle = tokio::spawn(server);

        let mut client = EncryptedStream::new(
            Authorization::Anonymous {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            b,
        );

        client.write_all(b"message one").await.unwrap();
        client.write_all(b"message two").await.unwrap();
        client.flush().await.unwrap();

        let mut read_buf = [0; 2 * 11];
        let read_count = client.read_exact(&mut read_buf).await.unwrap();
        assert_eq!(read_count, read_buf.len());

        assert_eq!(read_buf, concat!("message one", "message two").as_bytes());
        drop(client);
        let () = server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn read_only_stream_after_handshake() {
        let (a, b) = TestStream::new_pair(10);

        let server_builder = snow::Builder::new(
            crate::chat::noise::handshake::NK_NOISE_PATTERN
                .parse()
                .unwrap(),
        );

        let server_keypair = server_builder.generate_keypair().unwrap();
        let server_state = server_builder
            .local_private_key(&server_keypair.private)
            .build_responder()
            .unwrap();

        let server = async {
            let mut transport = a;

            let mut server_state = anonymous_server_handshake(&mut transport, server_state).await;
            // Send several messages, then end the connection.
            let messages = ["abc", "def", "ghi"].map(|message| {
                let mut buffer = [0; 64];
                let len = server_state
                    .write_message(message.as_bytes(), &mut buffer)
                    .unwrap();
                Ok(Bytes::copy_from_slice(&buffer[..len]))
            });
            transport
                .send_all(&mut futures_util::stream::iter(messages))
                .await
                .unwrap()
        };

        let server_handle = tokio::spawn(server);

        let mut client = EncryptedStream::new(
            Authorization::Anonymous {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            b,
        );

        let mut client_buf = vec![];
        client.read_to_end(&mut client_buf).await.unwrap();
        assert_eq!(client_buf, b"abcdefghi");

        let () = server_handle.await.unwrap();
    }

    #[test]
    fn early_read_gets_woken_up() {
        let (a, mut b) = TestStream::new_pair(10);

        let server_builder = snow::Builder::new(
            crate::chat::noise::handshake::NK_NOISE_PATTERN
                .parse()
                .unwrap(),
        );

        let server_keypair = server_builder.generate_keypair().unwrap();
        let server_state = server_builder
            .local_private_key(&server_keypair.private)
            .build_responder()
            .unwrap();

        let client = EncryptedStream::new(
            Authorization::Anonymous {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            a,
        );
        let (mut client_read, mut client_write) = tokio::io::split(client);

        let mut read_buf = [0; 32];
        let read_waker = Arc::new(TestWaker::default());

        // The server won't send anything until the client sends its initial
        // message, so there's nothing to read right now.
        let read = client_read.read(&mut read_buf);
        pin_mut!(read);

        assert_matches!(
            read.poll_unpin(&mut Context::from_waker(&read_waker.as_waker())),
            Poll::Pending
        );
        assert!(!read_waker.was_woken());

        // Send the initial Noise handshake message.
        {
            // This won't resolve until the server finishes the handshake, but that's fine.
            let write = client_write.write(&[]);
            pin_mut!(write);
            let write_waker = Arc::new(TestWaker::default()).into();
            let mut write_context = Context::from_waker(&write_waker);
            assert_matches!(write.poll_unpin(&mut write_context), Poll::Pending);

            // Handle the server side of the exchange.
            let _server_state = anonymous_server_handshake(&mut b, server_state)
                .now_or_never()
                .unwrap();

            // Now the write should be able to complete. This should wake up the read task.
            assert_matches!(write.poll_unpin(&mut write_context), Poll::Ready(Ok(0)));
        }

        assert!(read_waker.was_woken());
    }

    #[test]
    fn half_close_during_handshake() {
        env_logger::init();
        let (a, mut b) = TestStream::new_pair(10);

        let server_builder = snow::Builder::new(
            crate::chat::noise::handshake::NK_NOISE_PATTERN
                .parse()
                .unwrap(),
        );

        let server_keypair = server_builder.generate_keypair().unwrap();
        let mut server_state = server_builder
            .local_private_key(&server_keypair.private)
            .build_responder()
            .unwrap();

        let mut client = EncryptedStream::new(
            Authorization::Anonymous {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            a,
        );

        let client_write = client.write(&[]);
        pin_mut!(client_write);

        // Start the handshaking on the client end.
        assert_matches!(client_write.as_mut().now_or_never(), None);

        // The server should now have a message.
        let server_recv = b.next().now_or_never().unwrap().unwrap().unwrap();
        let mut read_buf = [0; 64];
        let read = server_state
            .read_message(&server_recv, &mut read_buf)
            .unwrap();
        assert_eq!(read, 0);

        // This is unusual but isn't illegal: abort the in-progress write and
        // shut down instead. This should complete immediately.
        let client_shutdown = client.shutdown();
        assert_matches!(client_shutdown.now_or_never(), Some(Ok(())));

        // Finish the server end of the handshake, then send some data to the
        // client. The client shutdown is a half-close, so it should continue to
        // be able to receive even if it won't send.
        let mut send_buf = [0; 64];
        let write_len = server_state.write_message(&[], &mut send_buf).unwrap();
        assert_matches!(
            b.send(Bytes::copy_from_slice(&send_buf[..write_len]))
                .now_or_never(),
            Some(Ok(()))
        );

        log::info!("sent handshake response from server");
        let mut server_state = server_state.into_transport_mode().unwrap();
        for message in ["abc", "def", "ghi"] {
            let len = server_state
                .write_message(message.as_bytes(), &mut send_buf)
                .unwrap();
            assert_matches!(
                b.feed(Bytes::copy_from_slice(&send_buf[..len]))
                    .now_or_never(),
                Some(Ok(()))
            );
            assert_eq!(len, message.len() + PAYLOAD_AEAD_TAG_LEN);
        }
        b.flush().now_or_never();
        log::info!("flushed all extra messages");
        drop(b);

        let mut read_buf = vec![];
        client
            .read_to_end(&mut read_buf)
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(read_buf, b"abcdefghi");
    }

    #[test]
    fn wake_count_during_handshake() {
        let (a, mut b) = TestStream::new_pair(10);

        let server_builder = snow::Builder::new(
            crate::chat::noise::handshake::NK_NOISE_PATTERN
                .parse()
                .unwrap(),
        );

        let server_keypair = server_builder.generate_keypair().unwrap();
        let mut server_state = server_builder
            .local_private_key(&server_keypair.private)
            .build_responder()
            .unwrap();

        let client = EncryptedStream::new(
            Authorization::Anonymous {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            a,
        );
        pin_mut!(client);

        let [read_waker, write_waker] = [(); 2].map(|()| Arc::new(TestWaker::default()));

        // Reading and writing during the initial handshake should cause the
        // wakers to be saved, but not yet woken.
        assert_matches!(
            client.as_mut().poll_read(
                &mut Context::from_waker(&read_waker.as_waker()),
                &mut tokio::io::ReadBuf::new(&mut [0; 32])
            ),
            Poll::Pending
        );
        assert_matches!(
            client
                .as_mut()
                .poll_write(&mut Context::from_waker(&write_waker.as_waker()), &[]),
            Poll::Pending
        );
        assert_eq!(Arc::strong_count(&read_waker), 2);
        assert_eq!(Arc::strong_count(&write_waker), 2);

        assert_eq!(read_waker.wake_count(), 0);
        assert_eq!(write_waker.wake_count(), 0);

        // Process the message on the server end and send a response to the
        // client. This should wake the read and write tasks.
        let handshake = b.next().now_or_never().unwrap().unwrap().unwrap();
        let mut server_buf = [0; 64];
        let _read = server_state
            .read_message(&handshake, &mut server_buf)
            .unwrap();
        let written = server_state.write_message(&[], &mut server_buf).unwrap();
        b.send(Bytes::copy_from_slice(&server_buf[..written]))
            .now_or_never()
            .unwrap()
            .unwrap();

        // Now both the read and write tasks should have been woken up.
        assert_eq!(read_waker.wake_count(), 1);
        assert_eq!(write_waker.wake_count(), 1);

        // A successful write should not result in any new wakeups.
        assert_matches!(
            client.poll_write(&mut Context::from_waker(&write_waker.as_waker()), b"abc"),
            Poll::Ready(Ok(3))
        );
        assert_eq!(read_waker.wake_count(), 1);
        assert_eq!(write_waker.wake_count(), 1);
    }
}
