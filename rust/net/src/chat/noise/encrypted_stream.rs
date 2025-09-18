//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Error as IoError;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use libsignal_core::{Aci, DeviceId};
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

use crate::chat::noise::{ChatNoiseFragment, HandshakeAuth};
use crate::infra::errors::{LogSafeDisplay, TransportConnectError};
use crate::infra::noise::{
    EPHEMERAL_KEY_LEN, NoiseConnector, NoiseStream, STATIC_KEY_LEN, SendError, Transport,
};
use crate::infra::route::{Connector, NoiseRouteFragment};

/// A Noise-encrypted stream that wraps an underlying block-based [`Transport`].
///
/// The stream type `S` must implement `Transport`.
pub struct EncryptedStream<S> {
    stream: NoiseStream<S>,
}

/// Convenience alias for a public server key.
pub type ServerPublicKey = [u8; STATIC_KEY_LEN];

/// How to identify the client to the server.
#[derive(Clone, Debug, PartialEq)]
pub enum Authorization {
    /// Authenticate as the provided account/device to a known server.
    Authenticated {
        aci: Aci,
        device_id: DeviceId,
        server_public_key: ServerPublicKey,
        client_private_key: [u8; EPHEMERAL_KEY_LEN],
    },
    /// Connect to a known server as an anonymous client.
    Anonymous { server_public_key: ServerPublicKey },
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ConnectError {
    /// send failed: {0}
    Send(#[from] SendError),
    /// transport error: {0}
    Transport(#[from] TransportConnectError),
    /// public key mismatch
    WrongPublicKey,
    /// client version is too old
    ClientVersionTooOld,
    /// invalid response code {0}
    InvalidResponseCode(i32),
    /// protobuf decode error
    ProtobufDecode,
    /// server sent an unexpected fast-open frame
    UnexpectedFastOpenResponse,
}
impl LogSafeDisplay for ConnectError {}

impl From<libsignal_net_infra::noise::ConnectError> for ConnectError {
    fn from(value: libsignal_net_infra::noise::ConnectError) -> Self {
        use libsignal_net_infra::noise::ConnectError;
        match value {
            ConnectError::Send(send) => Self::Send(send),
            ConnectError::Transport(transport) => Self::Transport(transport),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConnectMeta {
    pub accept_language: String,
    pub user_agent: String,
}
pub struct ChatNoiseConnector<C = NoiseConnector>(pub C);

impl<Inner, C, NS> Connector<ChatNoiseFragment, Inner> for ChatNoiseConnector<C>
where
    C: for<'a> Connector<
            NoiseRouteFragment<HandshakeAuth<'a>>,
            Inner,
            Connection = (NoiseStream<NS>, Box<[u8]>),
            Error: Into<ConnectError>,
        > + Sync,
    Inner: Send,
{
    type Connection = EncryptedStream<NS>;

    type Error = ConnectError;

    async fn connect_over(
        &self,
        over: Inner,
        (authorization, meta): ChatNoiseFragment,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        let Self(noise_connector) = self;
        let (pattern, initial_payload) = pattern_and_payload(&authorization, meta);
        let (stream, payload) = noise_connector
            .connect_over(
                over,
                NoiseRouteFragment {
                    handshake: pattern,
                    initial_payload: Some(initial_payload),
                },
                log_tag,
            )
            .await
            .map_err(Into::into)?;
        let crate::proto::chat_noise::HandshakeResponse {
            code,
            error_details,
            fast_open_response,
        } = prost::Message::decode(Bytes::from(payload))?;

        use crate::proto::chat_noise::handshake_response::Code;
        match Code::try_from(code).map_err(|_| ConnectError::InvalidResponseCode(code))? {
            e @ Code::Unspecified => Err(ConnectError::InvalidResponseCode(e.into())),
            Code::Ok => Ok(()),
            Code::WrongPublicKey => Err(ConnectError::WrongPublicKey),
            Code::Deprecated => Err(ConnectError::ClientVersionTooOld),
        }
        .inspect_err(|e| {
            log::debug!("server rejection: {e}; server-provided-details: {error_details:?}");
        })?;

        if !fast_open_response.is_empty() {
            return Err(ConnectError::UnexpectedFastOpenResponse);
        }
        Ok(EncryptedStream { stream })
    }
}

impl<S: Transport + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Self { stream } = &mut *self;
        Pin::new(stream).poll_read(cx, buf)
    }
}

#[derive(Debug, PartialEq)]
struct InitialPayload {
    auth: Option<(Aci, DeviceId)>,
    meta: ConnectMeta,
}

impl InitialPayload {
    fn into_bytes(self) -> Box<[u8]> {
        let Self {
            auth,
            meta:
                ConnectMeta {
                    accept_language,
                    user_agent,
                },
        } = self;
        let (aci, device_id) = auth.unzip();
        let aci = aci.map(|a| Bytes::copy_from_slice(Uuid::from(a).as_bytes()));
        crate::proto::chat_noise::HandshakeInit {
            aci: aci.unwrap_or_default(),
            accept_language,
            user_agent,
            fast_open_request: Bytes::new(),
            device_id: device_id.map(Into::into).unwrap_or_default(),
        }
        .encode_to_vec()
        .into()
    }
}

impl<S: Transport + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        let Self { stream } = &mut *self;
        Pin::new(stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        let Self { stream } = &mut *self;
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        let Self { stream } = &mut *self;
        Pin::new(stream).poll_shutdown(cx)
    }
}

impl From<prost::DecodeError> for ConnectError {
    fn from(value: prost::DecodeError) -> Self {
        log::debug!("protobuf decode failed: {value}");
        Self::ProtobufDecode
    }
}

fn pattern_and_payload(auth: &Authorization, meta: ConnectMeta) -> (HandshakeAuth<'_>, Box<[u8]>) {
    let (pattern, auth) = match &auth {
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
            Some((*aci, *device_id)),
        ),
        Authorization::Anonymous { server_public_key } => {
            (HandshakeAuth::NK { server_public_key }, None)
        }
    };

    let initial_payload = InitialPayload { auth, meta };
    (pattern, initial_payload.into_bytes())
}

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use const_str::{concat, hex};
    use futures_util::{SinkExt as _, StreamExt as _};
    use libsignal_net_infra::noise::FrameType;
    use libsignal_net_infra::noise::testutil::{echo_forever, new_transport_pair};
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::chat::noise::NK_NOISE_PATTERN;
    use crate::proto::chat_noise::{HandshakeInit, HandshakeResponse, handshake_response};

    async fn authenticating_server_handshake<S: Transport + Unpin>(
        transport: &mut S,
        mut server_state: snow::HandshakeState,
    ) -> (InitialPayload, snow::TransportState) {
        let auth = {
            let first = transport.next().await.unwrap().unwrap();
            let mut payload = [0; 128];
            let read_count = server_state.read_message(&first, &mut payload).unwrap();
            let HandshakeInit {
                user_agent,
                accept_language,
                aci,
                device_id,
                fast_open_request,
            } = Message::decode(&payload[..read_count]).unwrap();
            assert_eq!(fast_open_request, Bytes::new());
            let auth = if aci.is_empty() {
                assert_eq!(device_id, 0);
                None
            } else {
                Some((
                    Aci::from_uuid_bytes((&*aci).try_into().unwrap()),
                    DeviceId::try_from(device_id).unwrap(),
                ))
            };
            InitialPayload {
                auth,
                meta: ConnectMeta {
                    accept_language,
                    user_agent,
                },
            }
        };

        {
            let mut message = [0; 128];
            let payload = HandshakeResponse {
                code: handshake_response::Code::Ok.into(),
                ..Default::default()
            }
            .encode_to_vec();
            let written = server_state.write_message(&payload, &mut message).unwrap();
            transport
                .send((FrameType::Data, Bytes::copy_from_slice(&message[..written])))
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
            let written = server_state
                .write_message(
                    &HandshakeResponse {
                        code: handshake_response::Code::Ok.into(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                    &mut message,
                )
                .unwrap();
            transport
                .send((FrameType::Data, Bytes::copy_from_slice(&message[..written])))
                .await
                .unwrap();
        }

        assert!(server_state.is_handshake_finished());
        server_state.into_transport_mode().unwrap()
    }

    impl<T: Transport + Unpin + Send> EncryptedStream<T> {
        async fn connect(
            authorization: Authorization,
            meta: ConnectMeta,
            inner: T,
        ) -> Result<EncryptedStream<T>, ConnectError> {
            ChatNoiseConnector(NoiseConnector)
                .connect_over(inner, (authorization, meta), "test")
                .await
        }
    }

    const ACI: Aci = Aci::from_uuid_bytes(hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    const DEVICE_ID: DeviceId = match DeviceId::new(42) {
        Ok(d) => d,
        Err(_) => unreachable!(),
    };

    #[tokio::test]
    async fn encrypted_stream_authenticated_handshake_success() {
        let (a, b) = new_transport_pair(10);

        let server_builder =
            snow::Builder::new(crate::chat::noise::IK_NOISE_PATTERN.parse().unwrap());

        let server_keypair = server_builder.generate_keypair().unwrap();
        let client_keypair = server_builder.generate_keypair().unwrap();

        let server_state = server_builder
            .local_private_key(&server_keypair.private)
            .unwrap()
            .remote_public_key(&client_keypair.public)
            .unwrap()
            .build_responder()
            .unwrap();

        let server = async {
            let mut transport = a;

            let (auth, server_state) =
                authenticating_server_handshake(&mut transport, server_state).await;

            assert_eq!(
                auth,
                InitialPayload {
                    auth: Some((ACI, DEVICE_ID)),
                    meta: ConnectMeta::default()
                }
            );

            // Echo back incoming payloads forever.
            echo_forever(transport, server_state).await;
        };

        let server_handle = tokio::spawn(server);

        let mut client = EncryptedStream::connect(
            Authorization::Authenticated {
                aci: ACI,
                device_id: DEVICE_ID,
                server_public_key: server_keypair.public.try_into().unwrap(),
                client_private_key: client_keypair.private.try_into().unwrap(),
            },
            ConnectMeta::default(),
            b,
        )
        .await
        .unwrap();

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
        let (a, b) = new_transport_pair(10);

        let server_builder = snow::Builder::new(NK_NOISE_PATTERN.parse().unwrap());

        let server_keypair = server_builder.generate_keypair().unwrap();
        let server_state = server_builder
            .local_private_key(&server_keypair.private)
            .unwrap()
            .build_responder()
            .unwrap();

        let server = async {
            let mut transport = a;

            let server_state = anonymous_server_handshake(&mut transport, server_state).await;
            // Echo back incoming payloads forever.
            echo_forever(transport, server_state).await
        };

        let server_handle = tokio::spawn(server);

        let mut client = EncryptedStream::connect(
            Authorization::Anonymous {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            ConnectMeta::default(),
            b,
        )
        .await
        .expect("can connect");

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
        let (a, b) = new_transport_pair(10);

        let server_builder = snow::Builder::new(NK_NOISE_PATTERN.parse().unwrap());

        let server_keypair = server_builder.generate_keypair().unwrap();
        let server_state = server_builder
            .local_private_key(&server_keypair.private)
            .unwrap()
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
                Ok((FrameType::Data, Bytes::copy_from_slice(&buffer[..len])))
            });
            transport
                .send_all(&mut futures_util::stream::iter(messages))
                .await
                .unwrap()
        };

        let server_handle = tokio::spawn(server);

        let mut client = EncryptedStream::connect(
            Authorization::Anonymous {
                server_public_key: server_keypair.public.try_into().unwrap(),
            },
            ConnectMeta::default(),
            b,
        )
        .await
        .expect("can connect");

        let mut client_buf = vec![];
        client.read_to_end(&mut client_buf).await.unwrap();
        assert_eq!(client_buf, b"abcdefghi");

        let () = server_handle.await.unwrap();
    }
}
