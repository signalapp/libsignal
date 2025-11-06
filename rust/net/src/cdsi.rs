//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::default::Default;

use libsignal_core::{Aci, E164, Pni};
use libsignal_net_infra::errors::{LogSafeDisplay, RetryLater, TransportConnectError};
use libsignal_net_infra::route::{RouteProvider, UnresolvedWebsocketServiceRoute};
use libsignal_net_infra::ws::attested::{
    AttestedConnection, AttestedConnectionError, AttestedProtocolError,
};
use libsignal_net_infra::ws::{NextOrClose, WebSocketConnectError, WebSocketError};
use prost::Message as _;
use thiserror::Error;
use tungstenite::protocol::CloseFrame;
use tungstenite::protocol::frame::coding::CloseCode;
use uuid::Uuid;

use crate::auth::Auth;
use crate::connect_state::{ConnectionResources, WebSocketTransportConnectorFactory};
use crate::enclave::{Cdsi, EndpointParams};
use crate::proto::cds2::{ClientRequest, ClientResponse};

trait FixedLengthSerializable {
    const SERIALIZED_LEN: usize;

    // TODO: when feature(generic_const_exprs) is stabilized, make the target an
    // array reference instead of a slice.
    fn serialize_into(&self, target: &mut [u8]);
}

trait CollectSerialized {
    fn collect_serialized(self) -> Vec<u8>;
}

impl<It: ExactSizeIterator<Item = T>, T: FixedLengthSerializable> CollectSerialized for It {
    fn collect_serialized(self) -> Vec<u8> {
        let mut output = vec![0; T::SERIALIZED_LEN * self.len()];
        for (item, chunk) in self.zip(output.chunks_mut(T::SERIALIZED_LEN)) {
            item.serialize_into(chunk)
        }

        output
    }
}

impl FixedLengthSerializable for E164 {
    const SERIALIZED_LEN: usize = 8;

    fn serialize_into(&self, target: &mut [u8]) {
        target.copy_from_slice(&self.to_be_bytes())
    }
}

impl FixedLengthSerializable for Uuid {
    const SERIALIZED_LEN: usize = 16;
    fn serialize_into(&self, target: &mut [u8]) {
        target.copy_from_slice(self.as_bytes())
    }
}

#[cfg_attr(test, derive(Clone))]
pub struct AciAndAccessKey {
    pub aci: Aci,
    pub access_key: [u8; 16],
}

impl FixedLengthSerializable for AciAndAccessKey {
    const SERIALIZED_LEN: usize = 32;

    fn serialize_into(&self, target: &mut [u8]) {
        let (aci_bytes, access_key_bytes) = target.split_at_mut(Uuid::SERIALIZED_LEN);

        Uuid::from(self.aci).serialize_into(aci_bytes);
        access_key_bytes.copy_from_slice(&self.access_key)
    }
}

#[derive(Default)]
#[cfg_attr(test, derive(Clone))]
pub struct LookupRequest {
    pub new_e164s: Vec<E164>,
    pub prev_e164s: Vec<E164>,
    pub acis_and_access_keys: Vec<AciAndAccessKey>,
    pub token: Box<[u8]>,
}

impl LookupRequest {
    fn into_client_request(self) -> ClientRequest {
        let Self {
            new_e164s,
            prev_e164s,
            acis_and_access_keys,
            token,
        } = self;

        let aci_uak_pairs = acis_and_access_keys.into_iter().collect_serialized();
        let new_e164s = new_e164s.into_iter().collect_serialized();
        let prev_e164s = prev_e164s.into_iter().collect_serialized();

        ClientRequest {
            aci_uak_pairs,
            new_e164s,
            prev_e164s,
            token: token.into_vec(),
            token_ack: false,
            // TODO: use these for supporting non-desktop client requirements.
            discard_e164s: Vec::new(),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Token(pub Box<[u8]>);

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct LookupResponse {
    pub records: Vec<LookupResponseEntry>,
    pub debug_permits_used: i32,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct LookupResponseEntry {
    pub e164: E164,
    pub aci: Option<Aci>,
    pub pni: Option<Pni>,
}

impl TryFrom<ClientResponse> for LookupResponse {
    type Error = CdsiProtocolError;

    fn try_from(response: ClientResponse) -> Result<Self, Self::Error> {
        let ClientResponse {
            e164_pni_aci_triples,
            token: _,
            debug_permits_used,
        } = response;

        if e164_pni_aci_triples.len() % LookupResponseEntry::SERIALIZED_LEN != 0 {
            return Err(CdsiProtocolError::InvalidNumberOfBytes {
                actual_length: e164_pni_aci_triples.len(),
            });
        }

        let records = e164_pni_aci_triples
            .chunks(LookupResponseEntry::SERIALIZED_LEN)
            .flat_map(|record| {
                LookupResponseEntry::try_parse_from(
                    record.try_into().expect("chunk size is correct"),
                )
            })
            .collect();

        Ok(Self {
            records,
            debug_permits_used,
        })
    }
}

impl LookupResponseEntry {
    fn try_parse_from(record: &[u8; Self::SERIALIZED_LEN]) -> Option<Self> {
        fn non_nil_uuid<T: From<Uuid>>(bytes: &uuid::Bytes) -> Option<T> {
            let uuid = Uuid::from_bytes(*bytes);
            (!uuid.is_nil()).then(|| uuid.into())
        }

        // TODO(https://github.com/rust-lang/rust/issues/90091): use split_array
        // instead of expect() on the output.
        let (e164_bytes, record) = record.split_at(E164::SERIALIZED_LEN);
        let e164_bytes = <&[u8; E164::SERIALIZED_LEN]>::try_from(e164_bytes).expect("split at len");
        let e164 = E164::from_be_bytes(*e164_bytes)?;
        let (pni_bytes, aci_bytes) = record.split_at(Uuid::SERIALIZED_LEN);

        let pni = non_nil_uuid(pni_bytes.try_into().expect("split at len"));
        let aci = non_nil_uuid(aci_bytes.try_into().expect("split at len"));

        Some(Self { e164, aci, pni })
    }
}

impl FixedLengthSerializable for LookupResponseEntry {
    const SERIALIZED_LEN: usize = E164::SERIALIZED_LEN + Uuid::SERIALIZED_LEN * 2;

    fn serialize_into(&self, target: &mut [u8]) {
        let Self { e164, aci, pni } = self;

        let (e164_bytes, target) = target.split_at_mut(E164::SERIALIZED_LEN);
        e164.serialize_into(e164_bytes);

        let (pni_bytes, aci_bytes) = target.split_at_mut(Uuid::SERIALIZED_LEN);
        pni.map(Uuid::from)
            .unwrap_or(Uuid::nil())
            .serialize_into(pni_bytes);

        aci.map(Uuid::from)
            .unwrap_or(Uuid::nil())
            .serialize_into(aci_bytes);
    }
}

#[cfg_attr(test, derive(Debug))]
pub struct CdsiConnection(AttestedConnection);

impl AsMut<AttestedConnection> for CdsiConnection {
    fn as_mut(&mut self) -> &mut AttestedConnection {
        &mut self.0
    }
}

/// Anything that can go wrong during a CDSI lookup.
#[derive(Debug, Error, displaydoc::Display)]
pub enum LookupError {
    /// SGX attestation failed.
    AttestationError(attest::enclave::Error),
    /// retry later
    RateLimited(#[from] RetryLater),
    /// request token was invalid
    InvalidToken,
    /// protocol error after establishing a connection: {0}
    EnclaveProtocol(AttestedProtocolError),
    /// transport failed: {0}
    ConnectTransport(TransportConnectError),
    /// websocket error: {0}
    WebSocket(WebSocketError),
    /// no connection attempts succeeded before timeout
    AllConnectionAttemptsFailed,
    /// request was invalid: {server_reason}
    InvalidArgument { server_reason: String },
    /// server error: {reason}
    Server { reason: &'static str },
    /// CDS protocol: {0}
    CdsiProtocol(#[from] CdsiProtocolError),
}

#[derive(Debug, Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum CdsiProtocolError {
    /// no token found in response
    NoTokenInResponse,
    /// could not parse response triples ({actual_length} bytes)
    InvalidNumberOfBytes { actual_length: usize },
}

impl LogSafeDisplay for CdsiProtocolError {}

impl From<AttestedConnectionError> for LookupError {
    fn from(value: AttestedConnectionError) -> Self {
        match value {
            AttestedConnectionError::WebSocket(e) => Self::WebSocket(e),
            AttestedConnectionError::Protocol(error) => Self::EnclaveProtocol(error),
            AttestedConnectionError::Attestation(e) => Self::AttestationError(e),
        }
    }
}

impl From<crate::enclave::Error> for LookupError {
    fn from(value: crate::enclave::Error) -> Self {
        use crate::enclave::Error;
        match value {
            Error::WebSocketConnect(e) => match e {
                WebSocketConnectError::Transport(e) => Self::ConnectTransport(e),
                WebSocketConnectError::WebSocketError(e) => Self::WebSocket(e),
            },
            Error::RateLimited(inner) => Self::RateLimited(inner),
            Error::AttestationError(err) => Self::AttestationError(err),
            Error::WebSocket(err) => Self::WebSocket(err),
            Error::Protocol(error) => Self::EnclaveProtocol(error),
            Error::AllConnectionAttemptsFailed => Self::AllConnectionAttemptsFailed,
        }
    }
}

impl From<prost::DecodeError> for LookupError {
    fn from(_value: prost::DecodeError) -> Self {
        Self::EnclaveProtocol(AttestedProtocolError::ProtobufDecode)
    }
}

#[derive(serde::Deserialize)]
struct RateLimitExceededResponse {
    #[serde(rename = "retry_after")]
    retry_after_seconds: u32,
}

#[cfg_attr(test, derive(Debug))]
pub struct ClientResponseCollector(CdsiConnection);

impl CdsiConnection {
    pub async fn connect_with(
        connection_resources: ConnectionResources<'_, impl WebSocketTransportConnectorFactory>,
        route_provider: impl RouteProvider<Route = UnresolvedWebsocketServiceRoute>,
        ws_config: crate::infra::ws::Config,
        params: &EndpointParams<'_, Cdsi>,
        auth: &Auth,
    ) -> Result<Self, LookupError> {
        let (connection, _route_info) = connection_resources
            .connect_attested_ws(route_provider, auth, ws_config, "cdsi".into(), params)
            .await?;
        Ok(Self(connection))
    }

    pub async fn send_request(
        mut self,
        request: LookupRequest,
    ) -> Result<(Token, ClientResponseCollector), LookupError> {
        let request_info = LookupRequestDebugInfo::from(&request);
        let request = request.into_client_request().encode_to_vec();
        log::info!(
            "sending {}-byte initial request: {request_info}",
            request.len()
        );
        self.0.send_bytes(&request).await?;
        let token_response: ClientResponse = self.0.receive().await?.next_or_else(err_for_close)?;

        if token_response.token.is_empty() {
            return Err(LookupError::CdsiProtocol(
                CdsiProtocolError::NoTokenInResponse,
            ));
        }

        Ok((
            Token(token_response.token.into_boxed_slice()),
            ClientResponseCollector(self),
        ))
    }
}

impl ClientResponseCollector {
    pub async fn collect(self) -> Result<LookupResponse, LookupError> {
        let Self(mut connection) = self;

        let token_ack = ClientRequest {
            token_ack: true,
            ..Default::default()
        };

        connection.0.send(token_ack).await?;
        let mut response: ClientResponse =
            connection.0.receive().await?.next_or_else(err_for_close)?;
        loop {
            match connection.0.receive_bytes().await? {
                NextOrClose::Next(decoded) => {
                    response
                        .merge(decoded.as_ref())
                        .map_err(LookupError::from)?;
                }
                NextOrClose::Close(
                    None
                    | Some(CloseFrame {
                        code: CloseCode::Normal,
                        reason: _,
                    }),
                ) => {
                    log::info!("finished CDSI lookup");
                    break;
                }
                NextOrClose::Close(Some(close)) => return Err(err_for_close(Some(close))),
            }
        }
        Ok(response.try_into()?)
    }
}

/// For logging information about an initiated CDSI request.
struct LookupRequestDebugInfo {
    new_e164s: usize,
    prev_e164s: usize,
    acis_and_access_keys: usize,
    token: usize,
}

impl std::fmt::Display for LookupRequestDebugInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LookupRequestDebugInfo")
            .field("new_e164s", &self.new_e164s)
            .field("prev_e164s", &self.prev_e164s)
            .field("acis_and_access_keys", &self.acis_and_access_keys)
            .field("token", &self.token)
            .finish()
    }
}

impl LogSafeDisplay for LookupRequestDebugInfo {}

impl From<&LookupRequest> for LookupRequestDebugInfo {
    fn from(value: &LookupRequest) -> Self {
        let LookupRequest {
            new_e164s,
            prev_e164s,
            acis_and_access_keys,
            token,
        } = value;
        Self {
            new_e164s: new_e164s.len(),
            prev_e164s: prev_e164s.len(),
            acis_and_access_keys: acis_and_access_keys.len(),
            token: token.len(),
        }
    }
}

/// Numeric code set by the server on the websocket close frame.
#[repr(u16)]
#[derive(Copy, Clone, derive_more::TryFrom, strum::IntoStaticStr)]
#[try_from(repr)]
enum CdsiCloseCode {
    InvalidArgument = 4003,
    RateLimitExceeded = 4008,
    ServerInternalError = 4013,
    ServerUnavailable = 4014,
    InvalidToken = 4101,
}

/// Produces a [`LookupError`] for the provided [`CloseFrame`].
///
/// Returns `Some(err)` if there is a relevant `LookupError` value for the
/// provided close frame. Otherwise returns `None`.
fn err_for_close(close: Option<CloseFrame>) -> LookupError {
    fn unexpected_close(close: Option<CloseFrame>) -> LookupError {
        LookupError::EnclaveProtocol(AttestedProtocolError::UnexpectedClose(close.into()))
    }

    let Some(CloseFrame { code, reason }) = &close else {
        log::warn!("got unexpected connection close without a Close frame");
        return unexpected_close(close);
    };

    let Ok(code) = CdsiCloseCode::try_from(u16::from(code)) else {
        log::warn!("got unexpected websocket error code: {code}");
        return unexpected_close(close);
    };

    match code {
        CdsiCloseCode::InvalidArgument => LookupError::InvalidArgument {
            server_reason: reason.as_str().to_owned(),
        },
        CdsiCloseCode::InvalidToken => LookupError::InvalidToken,
        CdsiCloseCode::RateLimitExceeded => {
            let Some(RateLimitExceededResponse {
                retry_after_seconds,
            }) = serde_json::from_str(reason).ok()
            else {
                log::warn!("failed to parse rate limit from reason");
                return unexpected_close(close);
            };
            LookupError::RateLimited(RetryLater {
                retry_after_seconds,
            })
        }
        CdsiCloseCode::ServerInternalError | CdsiCloseCode::ServerUnavailable => {
            LookupError::Server {
                reason: code.into(),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::num::NonZeroU64;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use const_str::hex;
    use itertools::Itertools as _;
    use libsignal_net_infra::dns::DnsResolver;
    use libsignal_net_infra::route::DirectOrProxyProvider;
    use libsignal_net_infra::route::testutils::ConnectFn;
    use libsignal_net_infra::utils::no_network_change_events;
    use libsignal_net_infra::ws::attested::testutil::{
        AttestedServerOutput, FAKE_ATTESTATION, run_attested_server,
    };
    use libsignal_net_infra::ws::testutil::fake_websocket;
    use libsignal_net_infra::{
        AsStaticHttpHeader as _, EnableDomainFronting, RECOMMENDED_WS_CONFIG,
    };
    use nonzero_ext::nonzero;
    use tungstenite::protocol::CloseFrame;
    use tungstenite::protocol::frame::coding::CloseCode;
    use uuid::Uuid;
    use warp::Filter as _;

    use super::*;
    use crate::auth::Auth;
    use crate::connect_state::{ConnectState, SUGGESTED_CONNECT_CONFIG};
    use crate::env::StaticIpOrder;

    #[test]
    fn parse_lookup_response_entries() {
        const ACI_BYTES: [u8; 16] = hex!("0102030405060708a1a2a3a4a5a6a7a8");
        const PNI_BYTES: [u8; 16] = hex!("b1b2b3b4b5b6b7b81112131415161718");

        let e164: E164 = "+18005551001".parse().unwrap();
        let mut e164_bytes = [0; 8];
        e164.serialize_into(&mut e164_bytes);

        // Generate a sequence of triples by repeating the above data a few times.
        const NUM_REPEATS: usize = 4;
        let e164_pni_aci_triples =
            std::iter::repeat_n([e164_bytes.as_slice(), &PNI_BYTES, &ACI_BYTES], NUM_REPEATS)
                .flatten()
                .flatten()
                .cloned()
                .collect();

        let parsed = ClientResponse {
            e164_pni_aci_triples,
            token: vec![],
            debug_permits_used: 42,
        }
        .try_into();
        assert_eq!(
            parsed,
            Ok(LookupResponse {
                records: vec![
                    LookupResponseEntry {
                        e164,
                        aci: Some(Aci::from(Uuid::from_bytes(ACI_BYTES))),
                        pni: Some(Pni::from(Uuid::from_bytes(PNI_BYTES))),
                    };
                    NUM_REPEATS
                ],
                debug_permits_used: 42
            })
        );
    }

    #[test]
    fn serialize_e164s() {
        let e164s: Vec<E164> = (18005551001..)
            .take(5)
            .map(|n| E164::new(NonZeroU64::new(n).unwrap()))
            .collect();
        let serialized = e164s.into_iter().collect_serialized();

        assert_eq!(
            serialized.as_slice(),
            &hex!([
                "000000043136e799",
                "000000043136e79a",
                "000000043136e79b",
                "000000043136e79c",
                "000000043136e79d",
            ])
        );
    }

    #[test]
    fn serialize_acis_and_access_keys() {
        let pairs = [1, 2, 3, 4, 5].map(|i| AciAndAccessKey {
            access_key: [i; 16],
            aci: Aci::from_uuid_bytes([i | 0x80; 16]),
        });
        let serialized = pairs.into_iter().collect_serialized();

        assert_eq!(
            serialized.as_slice(),
            &hex!([
                "8181818181818181818181818181818101010101010101010101010101010101",
                "8282828282828282828282828282828202020202020202020202020202020202",
                "8383838383838383838383838383838303030303030303030303030303030303",
                "8484848484848484848484848484848404040404040404040404040404040404",
                "8585858585858585858585858585858505050505050505050505050505050505",
            ])
        );
    }

    /// Server-side state relative to a remote request.
    #[derive(Debug, Default, PartialEq)]
    enum FakeServerState {
        /// The client has not yet sent the first request message.
        #[default]
        AwaitingLookupRequest,
        /// Token response was sent, waiting for the client to ack it.
        AwaitingTokenAck,
        /// All response messages have been sent.
        Finished,
    }

    impl FakeServerState {
        const RESPONSE_TOKEN: &'static [u8] = b"new token";
        const RESPONSE_RECORD: LookupResponseEntry = LookupResponseEntry {
            aci: Some(Aci::from_uuid_bytes([b'a'; 16])),
            pni: Some(Pni::from_uuid_bytes([b'p'; 16])),
            e164: E164::new(nonzero!(18005550101u64)),
        };

        fn receive_frame(&mut self, frame: &[u8]) -> AttestedServerOutput {
            match self {
                Self::AwaitingLookupRequest => {
                    let _client_request = ClientRequest::decode(frame).expect("can decode");

                    *self = Self::AwaitingTokenAck;
                    AttestedServerOutput::message(
                        ClientResponse {
                            token: Self::RESPONSE_TOKEN.into(),
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    )
                }
                Self::AwaitingTokenAck => {
                    let client_request = ClientRequest::decode(frame).expect("can decode");
                    assert!(
                        client_request.token_ack,
                        "invalid message: {client_request:?}"
                    );
                    *self = Self::Finished;
                    let mut triples_bytes = [0; LookupResponseEntry::SERIALIZED_LEN];
                    Self::RESPONSE_RECORD.serialize_into(&mut triples_bytes);
                    AttestedServerOutput {
                        message: Some(
                            ClientResponse {
                                debug_permits_used: 1,
                                e164_pni_aci_triples: triples_bytes.to_vec(),
                                ..Default::default()
                            }
                            .encode_to_vec(),
                        ),
                        close_after: Some(None),
                    }
                }
                Self::Finished => {
                    panic!("no frame expected");
                }
            }
        }

        /// Produces a closure usable with [`run_attested_server`].
        fn into_handler(mut self) -> impl FnMut(NextOrClose<Vec<u8>>) -> AttestedServerOutput {
            move |frame| {
                let frame = match frame {
                    NextOrClose::Close(_) => panic!("unexpected client-originating close"),
                    NextOrClose::Next(frame) => frame,
                };
                self.receive_frame(&frame)
            }
        }

        fn into_handler_with_close_from(
            mut self,
            state_before_close: &'static FakeServerState,
            close_frame: CloseFrame,
        ) -> impl FnMut(NextOrClose<Vec<u8>>) -> AttestedServerOutput {
            move |frame| {
                if &self == state_before_close {
                    return AttestedServerOutput::close(Some(close_frame.clone()));
                }

                let frame = match frame {
                    NextOrClose::Close(_) => panic!("unexpected client-originating close"),
                    NextOrClose::Next(frame) => frame,
                };
                self.receive_frame(&frame)
            }
        }
    }

    const FAKE_WS_CONFIG: libsignal_net_infra::ws::Config = libsignal_net_infra::ws::Config {
        local_idle_timeout: Duration::from_secs(5),
        remote_idle_ping_timeout: Duration::from_secs(100),
        remote_idle_disconnect_timeout: Duration::from_secs(100),
    };

    #[tokio::test]
    async fn lookup_success() {
        let (server, client) = fake_websocket().await;

        let fake_server = FakeServerState::default().into_handler();
        tokio::spawn(run_attested_server(
            server,
            attest::sgx_session::testutil::private_key(),
            fake_server,
        ));

        let cdsi_connection = CdsiConnection(
            AttestedConnection::connect(
                client,
                FAKE_WS_CONFIG,
                "test".into(),
                |fake_attestation| {
                    assert_eq!(fake_attestation, FAKE_ATTESTATION);
                    attest::sgx_session::testutil::handshake_from_tests_data()
                },
            )
            .await
            .expect("handshake failed"),
        );

        let (token, collector) = cdsi_connection
            .send_request(LookupRequest {
                token: b"valid but ignored token".as_slice().into(),
                ..Default::default()
            })
            .await
            .expect("request accepted");

        assert_eq!(&*token.0, FakeServerState::RESPONSE_TOKEN);

        let response = collector.collect().await.expect("successful request");

        assert_eq!(
            response,
            LookupResponse {
                debug_permits_used: 1,
                records: vec![FakeServerState::RESPONSE_RECORD],
            }
        );
    }

    #[tokio::test]
    async fn large_request_split() {
        // Large requests should be split into multiple Noise packets, but those
        // will be sent concatenated as a single websocket message since that's
        // the form the CDSI server expectes.
        const LARGE_NUMBER_OF_ENTRIES: u16 = 20_000;

        let (server, client) = fake_websocket().await;

        let mut fake_server = FakeServerState::default();
        let (received_request_tx, mut received_request_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(run_attested_server(
            server,
            attest::sgx_session::testutil::private_key(),
            move |next_or_close| {
                let frame = next_or_close.next_or(()).unwrap();
                let mut output = fake_server.receive_frame(&frame);
                match &fake_server {
                    FakeServerState::AwaitingLookupRequest => (),
                    FakeServerState::AwaitingTokenAck => {
                        // Send the initial request for comparison.
                        received_request_tx.send(frame).unwrap();
                    }
                    FakeServerState::Finished => {
                        // Override the output to send a larger response message
                        // that will be split over multiple Noise packets.
                        let large_number_of_triples = (1..=LARGE_NUMBER_OF_ENTRIES)
                            .map(|i| LookupResponseEntry {
                                e164: E164::new(NonZeroU64::new(i.into()).unwrap()),
                                aci: None,
                                pni: None,
                            })
                            .collect_serialized();
                        let serialized_response = ClientResponse {
                            debug_permits_used: 1,
                            e164_pni_aci_triples: large_number_of_triples,
                            ..Default::default()
                        }
                        .encode_to_vec();
                        assert!(
                            serialized_response.len() > 10 * NOISE_TRANSPORT_PER_PACKET_MAX,
                            "response size: {}",
                            serialized_response.len()
                        );
                        *output.message.as_mut().unwrap() = serialized_response;
                    }
                }

                output
            },
        ));

        let cdsi_connection = CdsiConnection(
            AttestedConnection::connect(
                client,
                FAKE_WS_CONFIG,
                "test".into(),
                |fake_attestation| {
                    assert_eq!(fake_attestation, FAKE_ATTESTATION);
                    attest::sgx_session::testutil::handshake_from_tests_data()
                },
            )
            .await
            .expect("handshake failed"),
        );

        let large_number_of_e164s = (1..=LARGE_NUMBER_OF_ENTRIES)
            .map(|i| E164::new(NonZeroU64::new(i.into()).unwrap()))
            .collect_vec();
        let request = LookupRequest {
            token: b"valid but ignored token".as_slice().into(),
            new_e164s: large_number_of_e164s.clone(),
            prev_e164s: large_number_of_e164s,
            acis_and_access_keys: (1..=LARGE_NUMBER_OF_ENTRIES)
                .map(|i| {
                    let mut bytes = [0; 16];
                    *bytes.first_chunk_mut().expect("long enough") = i.to_be_bytes();
                    AciAndAccessKey {
                        access_key: bytes,
                        aci: Uuid::from_bytes(bytes).into(),
                    }
                })
                .collect(),
        };

        let serialized_request = request.clone().into_client_request().encode_to_vec();

        const NOISE_TRANSPORT_PER_PACKET_MAX: usize = 65535;
        assert!(
            serialized_request.len() > 10 * NOISE_TRANSPORT_PER_PACKET_MAX,
            "request size: {}",
            serialized_request.len()
        );

        let (_token, collector) = cdsi_connection
            .send_request(request)
            .await
            .expect("request accepted");

        let request_received_at_server = received_request_rx.recv().await.unwrap();
        assert_eq!(request_received_at_server.len(), serialized_request.len());

        let response = collector.collect().await.expect("successful request");
        assert_eq!(response.records.len(), LARGE_NUMBER_OF_ENTRIES as usize);
    }

    #[tokio::test]
    async fn websocket_close_with_rate_limit_exceeded_after_initial_request() {
        let (server, client) = fake_websocket().await;

        let fake_server = FakeServerState::default().into_handler_with_close_from(
            &FakeServerState::AwaitingLookupRequest,
            CloseFrame {
                code: CloseCode::Bad(4008),
                reason: r#"{"retry_after": 12345}"#.into(),
            },
        );

        tokio::spawn(run_attested_server(
            server,
            attest::sgx_session::testutil::private_key(),
            fake_server,
        ));

        let cdsi_connection = CdsiConnection(
            AttestedConnection::connect(
                client,
                FAKE_WS_CONFIG,
                "test".into(),
                |fake_attestation| {
                    assert_eq!(fake_attestation, FAKE_ATTESTATION);
                    attest::sgx_session::testutil::handshake_from_tests_data()
                },
            )
            .await
            .expect("handshake failed"),
        );

        let response = cdsi_connection
            .send_request(LookupRequest {
                token: b"valid but ignored token".as_slice().into(),
                ..Default::default()
            })
            .await;

        assert_matches!(
            response,
            Err(LookupError::RateLimited(RetryLater {
                retry_after_seconds: 12345
            }))
        );
    }

    #[tokio::test]
    async fn websocket_close_with_rate_limit_exceeded_after_token_ack() {
        let (server, client) = fake_websocket().await;

        let fake_server = FakeServerState::default().into_handler_with_close_from(
            &FakeServerState::AwaitingTokenAck,
            CloseFrame {
                code: CloseCode::Bad(4008),
                reason: r#"{"retry_after": 513}"#.into(),
            },
        );

        tokio::spawn(run_attested_server(
            server,
            attest::sgx_session::testutil::private_key(),
            fake_server,
        ));

        let cdsi_connection = CdsiConnection(
            AttestedConnection::connect(
                client,
                FAKE_WS_CONFIG,
                "test".into(),
                |fake_attestation| {
                    assert_eq!(fake_attestation, FAKE_ATTESTATION);
                    attest::sgx_session::testutil::handshake_from_tests_data()
                },
            )
            .await
            .expect("handshake failed"),
        );

        let (_token, collector) = cdsi_connection
            .send_request(LookupRequest {
                token: b"valid but ignored token".as_slice().into(),
                ..Default::default()
            })
            .await
            .expect("request accepted");

        let response = collector.collect().await;

        assert_matches!(
            response,
            Err(LookupError::RateLimited(RetryLater {
                retry_after_seconds: 513
            }))
        )
    }

    #[test_log::test(tokio::test)]
    async fn websocket_rejected_with_http_429_too_many_requests() {
        let service = warp::get().then(|| async move {
            let reply = warp::reply();
            let reply = warp::reply::with_header(reply, RetryLater::HEADER_NAME.as_str(), "100");
            warp::reply::with_status(reply, warp::http::StatusCode::TOO_MANY_REQUESTS)
        });

        let (tx_connections, mut incoming_connections) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(conn) = incoming_connections.recv().await {
                tokio::spawn(hyper::server::conn::http1::Builder::new().serve_connection(
                    hyper_util::rt::TokioIo::new(conn),
                    hyper_util::service::TowerToHyperService::new(warp::service(service)),
                ));
            }
        });

        let connector = ConnectFn(|(), _route| {
            let (local, remote) = tokio::io::duplex(1024);
            tx_connections.send(local).unwrap();
            std::future::ready(Ok::<_, TransportConnectError>(remote))
        });

        let env = crate::env::PROD;
        let ws2_config = RECOMMENDED_WS_CONFIG;
        let auth = Auth {
            username: "username".to_string(),
            password: "password".to_string(),
        };

        let connect_state =
            ConnectState::new_with_transport_connector(SUGGESTED_CONNECT_CONFIG, connector);
        let network_change_event = no_network_change_events();

        // If we don't mock out the DNS, this test will fail on machines without internet access.
        let static_map = HashMap::from([env
            .cdsi
            .domain_config
            .static_fallback(StaticIpOrder::HARDCODED)]);
        let dns_resolver = DnsResolver::new_from_static_map(static_map);

        let result = CdsiConnection::connect_with(
            ConnectionResources {
                connect_state: &connect_state,
                dns_resolver: &dns_resolver,
                network_change_event: &network_change_event,
                confirmation_header_name: None,
            },
            DirectOrProxyProvider::direct(
                env.cdsi
                    .enclave_websocket_provider(EnableDomainFronting::No),
            ),
            ws2_config,
            &env.cdsi.params,
            &auth,
        )
        .await;

        assert_matches!(
            result,
            Err(LookupError::RateLimited(RetryLater {
                retry_after_seconds: 100
            }))
        )
    }

    #[tokio::test]
    async fn websocket_invalid_token_close() {
        let (server, client) = fake_websocket().await;

        const INVALID_TOKEN: &[u8] = b"invalid token";
        let fake_server = FakeServerState::default().into_handler_with_close_from(
            &FakeServerState::AwaitingLookupRequest,
            CloseFrame {
                code: CloseCode::Bad(4101),
                reason: "invalid token".into(),
            },
        );

        tokio::spawn(run_attested_server(
            server,
            attest::sgx_session::testutil::private_key(),
            fake_server,
        ));

        let cdsi_connection = CdsiConnection(
            AttestedConnection::connect(
                client,
                FAKE_WS_CONFIG,
                "test".into(),
                |fake_attestation| {
                    assert_eq!(fake_attestation, FAKE_ATTESTATION);
                    attest::sgx_session::testutil::handshake_from_tests_data()
                },
            )
            .await
            .expect("handshake failed"),
        );

        let response = cdsi_connection
            .send_request(LookupRequest {
                token: INVALID_TOKEN.into(),
                ..Default::default()
            })
            .await;

        assert_matches!(response, Err(LookupError::InvalidToken));
    }
}
