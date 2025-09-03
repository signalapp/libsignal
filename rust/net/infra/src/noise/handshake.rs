//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use futures_util::{SinkExt as _, StreamExt as _};

use crate::noise::{FrameType, NoiseStream, SendError, Transport};

pub trait NoiseHandshake {
    /// The number of bytes required in a [Noise handshake message] for this handshake type.
    ///
    /// [Noise handshake message]: https://noiseprotocol.org/noise.html#message-format
    fn handshake_message_len(&self) -> usize;

    fn auth_kind(&self) -> HandshakeAuthKind;

    fn into_handshake_state(self) -> snow::HandshakeState;
}

#[derive(Copy, Clone, Debug, PartialEq, strum::Display)]
pub enum HandshakeAuthKind {
    IK,
    NK,
}

pub const EPHEMERAL_KEY_LEN: usize = 32;
pub const STATIC_KEY_LEN: usize = 32;
pub(super) const PAYLOAD_AEAD_TAG_LEN: usize = 16;

/// Perform a Noise handshake over the given [`Transport`].
///
/// Sends an initial handshake message, then waits for the response. If the
/// handshake is successful, a [`NoiseStream`] representing the established
/// connection is returned along with the initial payload sent by the remote
/// end.
pub async fn handshake<S: Transport + Unpin, N: NoiseHandshake>(
    mut transport: S,
    handshake: N,
    initial_payload: Option<&[u8]>,
) -> Result<(NoiseStream<S>, Box<[u8]>), SendError> {
    let payload = initial_payload.unwrap_or_default();
    let initial_message_len =
        handshake.handshake_message_len() + payload.len() + PAYLOAD_AEAD_TAG_LEN;
    let auth_kind = handshake.auth_kind();

    let mut handshake = handshake.into_handshake_state();

    let mut initial_message = vec![0; initial_message_len];

    handshake.write_message(payload, &mut initial_message)?;

    let () = transport
        .send((FrameType::from(auth_kind), initial_message.into()))
        .await?;

    let received_message = transport.next().await.ok_or_else(|| {
        IoError::new(IoErrorKind::UnexpectedEof, "stream ended during handshake")
    })??;

    let payload_len = received_message
        .len()
        .checked_sub(EPHEMERAL_KEY_LEN + PAYLOAD_AEAD_TAG_LEN)
        .ok_or_else(|| IoError::new(IoErrorKind::InvalidData, "handshake message was too short"))?;

    let mut payload = vec![0; payload_len];
    let read_count = handshake.read_message(&received_message, &mut payload)?;

    if read_count != payload.len() {
        return Err(IoError::other(format!(
            "expected {payload_len}-byte payload but got {read_count}",
        ))
        .into());
    }

    let handshake_hash = handshake.get_handshake_hash().to_vec();
    Ok((
        NoiseStream::new(transport, handshake.into_transport_mode()?, handshake_hash),
        payload.into_boxed_slice(),
    ))
}

#[cfg(test)]
mod test {
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use assert_matches::assert_matches;
    use bytes::Bytes;
    use futures_util::{FutureExt, StreamExt};

    use super::*;
    use crate::noise::FrameType;
    use crate::noise::testutil::new_transport;
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
                .unwrap()
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

        let (a, mut b) = new_transport(3);

        let server_builder = snow::Builder::new(NkHandshake::NOISE_PATTERN.parse().unwrap());

        let server_keypair = server_builder.generate_keypair().unwrap();
        let mut server_state = server_builder
            .local_private_key(&server_keypair.private)
            .unwrap()
            .build_responder()
            .unwrap();

        let mut handshake = pin!(handshake(
            a,
            NkHandshake {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            Some(EXTRA_PAYLOAD),
        ));

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
            FrameType::Data,
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
    async fn transport_stream_drops_frame_type() {
        let (a, mut b) = new_transport(3);

        let server_builder = snow::Builder::new(NkHandshake::NOISE_PATTERN.parse().unwrap());

        let server_keypair = server_builder.generate_keypair().unwrap();
        let mut server_state = server_builder
            .local_private_key(&server_keypair.private)
            .unwrap()
            .build_responder()
            .unwrap();

        let mut handshake = pin!(handshake(
            a,
            NkHandshake {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            None,
        ));

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
        // future won't care because it doesn't receive the frame type from the
        // underlying transport.

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

        let (_handshake, _initial_payload) = handshake.await.expect("successful handshake");
    }
}
