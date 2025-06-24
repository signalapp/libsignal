//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::pin::Pin;
use std::task::{ready, Poll};

use futures_util::{SinkExt as _, StreamExt as _};
use snow::HandshakeState;

use crate::noise::{NoiseStream, SendError, Transport, TransportFrameType};

/// Future that performs a Noise handshake over a [`Transport`].
pub struct Handshaker<S> {
    /// Inner state.
    ///
    /// `Option`al to allow moving out of. This will only be `None` after
    /// `Future::poll` returns `Ready`.
    inner: Option<HandshakerInner<S>>,
}

pub trait NoiseHandshake {
    /// The number of bytes required in a [Noise handshake message] for this handshake type.
    ///
    /// [Noise handshake message]: https://noiseprotocol.org/noise.html#message-format
    fn handshake_message_len(&self) -> usize;

    fn auth_kind(&self) -> HandshakeAuthKind;

    fn into_handshake_state(self) -> snow::HandshakeState;
}

struct HandshakerInner<S> {
    transport: S,
    state: State,
    handshake: Box<HandshakeState>,
    auth_kind: HandshakeAuthKind,
}

enum State {
    SendRequest(SendRequest),
    ReadResponse,
}

enum SendRequest {
    InitialSend { ciphertext: Box<[u8]> },
    FlushSent,
}

#[derive(Copy, Clone, Debug, PartialEq, strum::Display)]
pub enum HandshakeAuthKind {
    IK,
    NK,
}

pub const EPHEMERAL_KEY_LEN: usize = 32;
pub const STATIC_KEY_LEN: usize = 32;
pub(super) const PAYLOAD_AEAD_TAG_LEN: usize = 16;

impl<S> Handshaker<S> {
    pub fn new(
        transport: S,
        handshake: impl NoiseHandshake,
        initial_payload: Option<&[u8]>,
    ) -> Result<Self, snow::Error> {
        let payload = initial_payload.unwrap_or_default();
        let initial_message_len =
            handshake.handshake_message_len() + payload.len() + PAYLOAD_AEAD_TAG_LEN;
        let auth_kind = handshake.auth_kind();

        let mut handshake = handshake.into_handshake_state();

        let mut initial_message = vec![0; initial_message_len];
        handshake.write_message(payload, &mut initial_message)?;
        let state = State::SendRequest(SendRequest::InitialSend {
            ciphertext: initial_message.into_boxed_slice(),
        });

        log::debug!("created {auth_kind} handshaker");
        Ok(Self {
            inner: Some(HandshakerInner {
                auth_kind,
                transport,
                state,
                handshake: Box::new(handshake),
            }),
        })
    }
}

impl SendRequest {
    fn poll_send_and_flush<S: Transport + Unpin>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        auth_kind: HandshakeAuthKind,
        transport: &mut S,
    ) -> Poll<Result<(), SendError>> {
        let ptr = self as *const Self;

        match self {
            SendRequest::InitialSend { ciphertext } => {
                // Before the flush can complete, the initial handshake message
                // needs to be sent.
                log::trace!(
                    "{ptr:x?} trying to send {}-byte ciphertext",
                    ciphertext.len()
                );
                let () = ready!(transport.poll_ready_unpin(cx)?);

                let frame_type = S::FrameType::from_auth(auth_kind);
                transport.start_send_unpin((frame_type, std::mem::take(ciphertext).into()))?;
                log::trace!("{ptr:x?} sent {}-byte ciphertext", ciphertext.len());

                *self = Self::FlushSent;
                self.poll_send_and_flush(cx, auth_kind, transport)
            }
            SendRequest::FlushSent => {
                // The flush still needs to be done. Once it finishes we can return to the caller.
                log::trace!("{ptr:x?} flushing");
                let () = ready!(transport.poll_flush_unpin(cx)?);
                log::trace!("{ptr:x?} flushed");

                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<S: Transport + Unpin> Future for Handshaker<S> {
    type Output = Result<(NoiseStream<S>, Box<[u8]>), SendError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let ptr = &*self as *const Self;

        let Self { inner } = self.as_mut().get_mut();
        let HandshakerInner {
            transport,
            state,
            handshake,
            auth_kind,
        } = inner.as_mut().expect("future polled after completion");

        match state {
            State::SendRequest(send_request) => {
                let () = ready!(send_request.poll_send_and_flush(cx, *auth_kind, transport))?;
                *state = State::ReadResponse;
                self.poll(cx)
            }
            State::ReadResponse => {
                log::trace!("{ptr:x?} trying to read next block");
                let (rx_frame_type, message) = ready!(transport.poll_next_unpin(cx))
                    .transpose()?
                    .ok_or_else(|| {
                    IoError::new(IoErrorKind::UnexpectedEof, "stream ended during handshake")
                })?;
                log::trace!(
                    "{ptr:x?} received {}-byte {rx_frame_type} block",
                    message.len()
                );

                let frame_type = S::FrameType::from_auth(*auth_kind);
                if frame_type != rx_frame_type {
                    return Poll::Ready(Err(IoError::other(format!(
                        "protocol error; expected {frame_type}, got {rx_frame_type} block"
                    ))
                    .into()));
                }

                let payload_len = message
                    .len()
                    .checked_sub(EPHEMERAL_KEY_LEN + PAYLOAD_AEAD_TAG_LEN)
                    .ok_or_else(|| {
                        IoError::new(IoErrorKind::InvalidData, "handshake message was too short")
                    })?;
                let mut payload = vec![0; payload_len];
                let read_count = handshake.read_message(&message, &mut payload)?;
                log::trace!("{ptr:x?} decrypted into {read_count}-byte plaintext");

                if read_count != payload.len() {
                    return Poll::Ready(Err(IoError::other(format!(
                        "expected {payload_len}-byte payload but got {read_count}",
                    ))
                    .into()));
                }

                let HandshakerInner {
                    state: _,
                    auth_kind: _,
                    transport,
                    handshake,
                } = self.inner.take().expect("just checked above");
                let handshake_hash = handshake.get_handshake_hash().to_vec();
                Poll::Ready(Ok((
                    NoiseStream::new(transport, handshake.into_transport_mode()?, handshake_hash),
                    payload.into_boxed_slice(),
                )))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::task::Context;

    use assert_matches::assert_matches;
    use bytes::Bytes;
    use futures_util::FutureExt;

    use super::*;
    use crate::noise::FrameType;
    use crate::testutil::TestStream;
    use crate::utils::testutil::TestWaker;

    struct NkHandshake {
        server_public_key: [u8; STATIC_KEY_LEN],
    }
    impl NkHandshake {
        const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2b";
    }

    impl NoiseHandshake for NkHandshake {
        fn auth_kind(&self) -> HandshakeAuthKind {
            HandshakeAuthKind::NK
        }
        fn into_handshake_state(self) -> snow::HandshakeState {
            snow::Builder::new(Self::NOISE_PATTERN.parse().unwrap())
                .remote_public_key(&self.server_public_key)
                .build_initiator()
                .unwrap()
        }
        fn handshake_message_len(&self) -> usize {
            self.server_public_key.len()
        }
    }

    #[test]
    fn successful_nk_handshake() {
        const EXTRA_PAYLOAD: &[u8] = b"extra payload";

        let (a, mut b) = TestStream::new_pair(3);

        let server_builder = snow::Builder::new(NkHandshake::NOISE_PATTERN.parse().unwrap());

        let server_keypair = server_builder.generate_keypair().unwrap();
        let mut server_state = server_builder
            .local_private_key(&server_keypair.private)
            .build_responder()
            .unwrap();

        let mut handshake = Handshaker::new(
            a,
            NkHandshake {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            Some(EXTRA_PAYLOAD),
        )
        .unwrap();

        let waker = Arc::new(TestWaker::default());
        assert_matches!(
            handshake.poll_unpin(&mut Context::from_waker(&waker.as_waker())),
            Poll::Pending
        );

        let (server_recv_kind, server_recv_payload) = b
            .next()
            .now_or_never()
            .expect("future finished")
            .expect("stream has value")
            .expect("not an error");
        assert_eq!(server_recv_kind, FrameType::Auth(HandshakeAuthKind::NK));

        let mut server_buffer = [0; 64];
        let len = server_state
            .read_message(&server_recv_payload, &mut server_buffer)
            .unwrap();
        assert_eq!(&server_buffer[..len], EXTRA_PAYLOAD);

        const OTHER_PAYLOAD: &[u8] = b"other payload";

        let mut server_buffer = [0; 64];
        let written = server_state
            .write_message(OTHER_PAYLOAD, &mut server_buffer)
            .unwrap();
        b.send((
            FrameType::Auth(HandshakeAuthKind::NK),
            Bytes::copy_from_slice(&server_buffer[..written]),
        ))
        .now_or_never()
        .unwrap()
        .unwrap();

        assert!(waker.was_woken());

        let (_stream, payload): (NoiseStream<_>, _) = handshake
            .now_or_never()
            .expect("handshake finished")
            .expect("success");
        assert_eq!(&*payload, OTHER_PAYLOAD);
    }

    #[tokio::test]
    async fn rejects_unexpected_frame_type() {
        let (a, mut b) = TestStream::new_pair(3);

        let server_builder = snow::Builder::new(NkHandshake::NOISE_PATTERN.parse().unwrap());

        let server_keypair = server_builder.generate_keypair().unwrap();
        let mut server_state = server_builder
            .local_private_key(&server_keypair.private)
            .build_responder()
            .unwrap();

        let mut handshake = Handshaker::new(
            a,
            NkHandshake {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            None,
        )
        .unwrap();

        // Poll the client so it sends a message, then retrieve that.
        let (rx_frame_type, message) = tokio::select! {
            _ = &mut handshake => unreachable!("server hasn't responded"),
            received = b.next() => received.unwrap().unwrap(),
        };
        assert_eq!(rx_frame_type, FrameType::Auth(HandshakeAuthKind::NK));

        let mut server_rx_payload = [0; 64];
        let len = server_state.read_message(&message, &mut server_rx_payload);
        assert_eq!(len, Ok(0));

        // Respond to the client but use the wrong frame type. The handshake
        // future should resolve to an error.

        let mut server_tx_payload = [0; 64];
        let len = server_state
            .write_message(&[], &mut server_tx_payload)
            .unwrap();
        b.send((
            FrameType::Auth(HandshakeAuthKind::IK),
            Bytes::copy_from_slice(&server_tx_payload[0..len]),
        ))
        .await
        .unwrap();

        let handshake_err: IoError = handshake
            .await
            .expect_err("wrong frame type accepted")
            .into();
        assert_eq!(handshake_err.kind(), IoErrorKind::Other);
        assert!(
            handshake_err
                .to_string()
                .contains("expected NK auth, got IK auth"),
            "message: {handshake_err}"
        );
    }
}
