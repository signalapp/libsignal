//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::pin::Pin;
use std::task::{ready, Poll};

use futures_util::{SinkExt as _, StreamExt as _};
use libsignal_net_infra::noise::{NoiseStream, Transport};
use snow::HandshakeState;

use super::SendError;

/// Future that performs a Noise handshake over a [`Transport`].
pub(super) struct Handshaker<S> {
    /// Inner state.
    ///
    /// `Option`al to allow moving out of. This will only be `None` after
    /// `Future::poll` returns `Ready`.
    inner: Option<HandshakerInner<S>>,
}

struct HandshakerInner<S> {
    transport: S,
    state: State,
    handshake: Box<HandshakeState>,
}

enum State {
    SendRequest(SendRequest),
    ReadResponse,
}

enum SendRequest {
    InitialSend { ciphertext: Box<[u8]> },
    FlushSent,
}

#[derive(strum::EnumDiscriminants)]
#[strum_discriminants(name(HandshakeAuthKind))]
pub(super) enum HandshakeAuth<'k> {
    IK {
        server_public_key: &'k [u8; STATIC_KEY_LEN],
        client_private_key: &'k [u8; EPHEMERAL_KEY_LEN],
    },
    NK {
        server_public_key: &'k [u8; STATIC_KEY_LEN],
    },
}

impl HandshakeAuthKind {
    /// The number of bytes required in a [Noise handshake message] for this handshake type.
    ///
    /// [Noise handshake message]: https://noiseprotocol.org/noise.html#message-format
    pub(super) fn handshake_message_len(&self) -> usize {
        match self {
            Self::IK => EPHEMERAL_KEY_LEN + STATIC_KEY_LEN + STATIC_KEY_AEAD_TAG_LEN,
            Self::NK => EPHEMERAL_KEY_LEN,
        }
    }
}

pub const IK_NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
pub const NK_NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2b";

pub(super) const EPHEMERAL_KEY_LEN: usize = 32;
pub(super) const STATIC_KEY_LEN: usize = 32;
pub(super) const STATIC_KEY_AEAD_TAG_LEN: usize = 16;
pub(super) const PAYLOAD_AEAD_TAG_LEN: usize = 16;

impl<S> Handshaker<S> {
    pub fn new(
        transport: S,
        pattern: HandshakeAuth,
        initial_payload: Option<&[u8]>,
    ) -> Result<Self, snow::Error> {
        let pattern_kind = HandshakeAuthKind::from(&pattern);
        let payload = initial_payload.unwrap_or_default();
        let initial_message_len =
            pattern_kind.handshake_message_len() + payload.len() + PAYLOAD_AEAD_TAG_LEN;

        let resolver = Box::new(attest::snow_resolver::Resolver);
        let mut handshake = match pattern {
            HandshakeAuth::IK {
                server_public_key,
                client_private_key,
            } => snow::Builder::with_resolver(IK_NOISE_PATTERN.parse().unwrap(), resolver)
                .remote_public_key(server_public_key)
                .local_private_key(client_private_key)
                .build_initiator()?,
            HandshakeAuth::NK { server_public_key } => {
                snow::Builder::with_resolver(NK_NOISE_PATTERN.parse().unwrap(), resolver)
                    .remote_public_key(server_public_key)
                    .build_initiator()?
            }
        };

        let mut initial_message = vec![0; initial_message_len];
        handshake.write_message(payload, &mut initial_message)?;
        let state = State::SendRequest(SendRequest::InitialSend {
            ciphertext: initial_message.into_boxed_slice(),
        });

        log::debug!("created {pattern_kind:?} handshaker");
        Ok(Self {
            inner: Some(HandshakerInner {
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

                transport.start_send_unpin(std::mem::take(ciphertext).into())?;
                log::trace!("{ptr:x?} sent {}-byte ciphertext", ciphertext.len());

                *self = Self::FlushSent;
                self.poll_send_and_flush(cx, transport)
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
        } = inner.as_mut().expect("future polled after completion");

        match state {
            State::SendRequest(send_request) => {
                let () = ready!(send_request.poll_send_and_flush(cx, transport))?;
                *state = State::ReadResponse;
                self.poll(cx)
            }
            State::ReadResponse => {
                log::trace!("{ptr:x?} trying to read next block");
                let message = ready!(transport.poll_next_unpin(cx))
                    .transpose()?
                    .ok_or_else(|| {
                        IoError::new(IoErrorKind::UnexpectedEof, "stream ended during handshake")
                    })?;
                log::trace!("{ptr:x?} received {}-byte block", message.len());

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
    use libsignal_net_infra::testutil::TestStream;
    use libsignal_net_infra::utils::testutil::TestWaker;

    use super::*;

    #[test]
    fn successful_nk_handshake() {
        const EXTRA_PAYLOAD: &[u8] = b"extra payload";

        let (a, mut b) = TestStream::new_pair(3);

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

        let mut handshake = Handshaker::new(
            a,
            HandshakeAuth::NK {
                server_public_key: &server_keypair.public.try_into().unwrap(),
            },
            Some(EXTRA_PAYLOAD),
        )
        .unwrap();

        let waker = Arc::new(TestWaker::default());
        assert_matches!(
            handshake.poll_unpin(&mut Context::from_waker(&waker.as_waker())),
            Poll::Pending
        );

        let server_recv = b
            .next()
            .now_or_never()
            .expect("future finished")
            .expect("stream has value")
            .expect("not an error");
        let mut server_buffer = [0; 64];
        let len = server_state
            .read_message(&server_recv, &mut server_buffer)
            .unwrap();
        assert_eq!(&server_buffer[..len], EXTRA_PAYLOAD);

        const OTHER_PAYLOAD: &[u8] = b"other payload";

        let mut server_buffer = [0; 64];
        let written = server_state
            .write_message(OTHER_PAYLOAD, &mut server_buffer)
            .unwrap();
        b.send(Bytes::copy_from_slice(&server_buffer[..written]))
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
}
