//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::default::Default;
use std::fmt::Display;
use std::num::{NonZeroU64, ParseIntError};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use prost::Message as _;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_boring::SslStream;
use uuid::Uuid;

use libsignal_core::{Aci, Pni};

use crate::auth::HttpBasicAuth;
use crate::enclave::{Cdsi, EndpointConnection};
use crate::infra::connection_manager::ConnectionManager;
use crate::infra::errors::NetError;
use crate::infra::reconnect::{ServiceConnectorWithDecorator, ServiceInitializer, ServiceState};
use crate::infra::ws::{
    AttestedConnection, AttestedConnectionError, NextOrClose, WebSocketClientConnector,
};
use crate::infra::{AsyncDuplexStream, TransportConnector};
use crate::proto::cds2::{ClientRequest, ClientResponse};

pub struct Auth {
    pub username: String,
    pub password: String,
}

impl HttpBasicAuth for Auth {
    fn username(&self) -> &str {
        &self.username
    }

    fn password(&self) -> std::borrow::Cow<str> {
        Cow::Borrowed(&self.password)
    }
}

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct E164(NonZeroU64);

impl E164 {
    pub const fn new(number: NonZeroU64) -> Self {
        Self(number)
    }

    fn from_serialized(bytes: [u8; E164::SERIALIZED_LEN]) -> Option<Self> {
        NonZeroU64::new(u64::from_be_bytes(bytes)).map(Self)
    }
}

impl FromStr for E164 {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix('+').unwrap_or(s);
        NonZeroU64::from_str(s).map(Self)
    }
}

impl Display for E164 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "+{}", self.0)
    }
}

impl FixedLengthSerializable for E164 {
    const SERIALIZED_LEN: usize = 8;

    fn serialize_into(&self, target: &mut [u8]) {
        target.copy_from_slice(&self.0.get().to_be_bytes())
    }
}

pub struct AciAndAccessKey {
    pub aci: Aci,
    pub access_key: [u8; 16],
}

impl FixedLengthSerializable for AciAndAccessKey {
    const SERIALIZED_LEN: usize = 32;

    fn serialize_into(&self, target: &mut [u8]) {
        let uuid_bytes = Uuid::from(self.aci).into_bytes();

        target[0..uuid_bytes.len()].copy_from_slice(&uuid_bytes);
        target[uuid_bytes.len()..].copy_from_slice(&self.access_key);
    }
}

#[derive(Default)]
pub struct LookupRequest {
    pub new_e164s: Vec<E164>,
    pub prev_e164s: Vec<E164>,
    pub acis_and_access_keys: Vec<AciAndAccessKey>,
    pub return_acis_without_uaks: bool,
    pub token: Box<[u8]>,
}

impl LookupRequest {
    fn into_client_request(self) -> ClientRequest {
        let Self {
            new_e164s,
            prev_e164s,
            acis_and_access_keys,
            return_acis_without_uaks,
            token,
        } = self;

        let aci_uak_pairs = acis_and_access_keys.into_iter().collect_serialized();
        let new_e164s = new_e164s.into_iter().collect_serialized();
        let prev_e164s = prev_e164s.into_iter().collect_serialized();

        ClientRequest {
            aci_uak_pairs,
            new_e164s,
            prev_e164s,
            return_acis_without_uaks,
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
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct LookupResponseEntry {
    pub e164: E164,
    pub aci: Option<Aci>,
    pub pni: Option<Pni>,
}

#[derive(Debug, PartialEq)]
pub enum LookupResponseParseError {
    InvalidNumberOfBytes { actual_length: usize },
}

impl From<LookupResponseParseError> for Error {
    fn from(value: LookupResponseParseError) -> Self {
        match value {
            LookupResponseParseError::InvalidNumberOfBytes { .. } => Self::ParseError,
        }
    }
}

impl TryFrom<ClientResponse> for LookupResponse {
    type Error = LookupResponseParseError;

    fn try_from(response: ClientResponse) -> Result<Self, Self::Error> {
        let ClientResponse {
            e164_pni_aci_triples,
            token: _,
            debug_permits_used: _,
        } = response;

        if e164_pni_aci_triples.len() % LookupResponseEntry::SERIALIZED_LEN != 0 {
            return Err(LookupResponseParseError::InvalidNumberOfBytes {
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

        Ok(Self { records })
    }
}

impl LookupResponseEntry {
    const UUID_LEN: usize = 16;
    const SERIALIZED_LEN: usize = E164::SERIALIZED_LEN + Self::UUID_LEN * 2;

    fn try_parse_from(record: &[u8; Self::SERIALIZED_LEN]) -> Option<Self> {
        fn non_nil_uuid<T: From<Uuid>>(bytes: &uuid::Bytes) -> Option<T> {
            let uuid = Uuid::from_bytes(*bytes);
            (!uuid.is_nil()).then(|| uuid.into())
        }

        // TODO(https://github.com/rust-lang/rust/issues/90091): use split_array
        // instead of expect() on the output.
        let (e164_bytes, record) = record.split_at(E164::SERIALIZED_LEN);
        let e164_bytes = <&[u8; E164::SERIALIZED_LEN]>::try_from(e164_bytes).expect("split at len");
        let e164 = E164::from_serialized(*e164_bytes)?;
        let (pni_bytes, aci_bytes) = record.split_at(Self::UUID_LEN);

        let pni = non_nil_uuid(pni_bytes.try_into().expect("split at len"));
        let aci = non_nil_uuid(aci_bytes.try_into().expect("split at len"));

        Some(Self { e164, aci, pni })
    }
}

pub struct CdsiConnection<S>(AttestedConnection<S>);

impl<S> AsMut<AttestedConnection<S>> for CdsiConnection<S> {
    fn as_mut(&mut self) -> &mut AttestedConnection<S> {
        &mut self.0
    }
}

#[derive(Debug, Error, displaydoc::Display)]
pub enum Error {
    /// Network error
    Net(#[from] NetError),
    /// Protocol error after establishing a connection.
    Protocol,
    /// SGX attestation failed.
    AttestationError,
    /// Invalid response received from the server.
    InvalidResponse,
    /// Retry later.
    RateLimited { retry_after: Duration },
    /// Failed to parse the response from the server.
    ParseError,
}

impl From<AttestedConnectionError> for Error {
    fn from(value: AttestedConnectionError) -> Self {
        match value {
            AttestedConnectionError::ClientConnection(_) => Self::Protocol,
            AttestedConnectionError::Net(net) => Self::Net(net),
            AttestedConnectionError::Protocol => Self::Protocol,
            AttestedConnectionError::Sgx(_) => Self::AttestationError,
        }
    }
}

impl From<prost::DecodeError> for Error {
    fn from(_value: prost::DecodeError) -> Self {
        Self::Protocol
    }
}

#[derive(serde::Deserialize)]
struct RateLimitExceededResponse {
    retry_after: u32,
}

impl RateLimitExceededResponse {
    /// Numeric code set by the server on the websocket close frame.
    const CLOSE_CODE: u16 = 4008;
}

pub struct ClientResponseCollector<S = SslStream<TcpStream>>(CdsiConnection<S>);

impl<S: AsyncDuplexStream> CdsiConnection<S> {
    /// Connect to remote host and verify remote attestation.
    pub async fn connect<P, T>(env: &P, auth: impl HttpBasicAuth) -> Result<Self, Error>
    where
        P: CdsiConnectionParams<TransportConnector = T>,
        T: TransportConnector<Stream = S>,
    {
        let auth_decorator = auth.into();
        let connection_manager = env.connection_manager();
        let connector = ServiceConnectorWithDecorator::new(env.connector(), auth_decorator);
        let service_initializer = ServiceInitializer::new(&connector, connection_manager);
        let connection_attempt_result = service_initializer.connect().await;
        let websocket = match connection_attempt_result {
            ServiceState::Active(websocket, _) => Ok(websocket),
            ServiceState::Cooldown(_) => Err(Error::Net(NetError::NoServiceConnection)),
            ServiceState::Error(e) => Err(Error::Net(e)),
            ServiceState::TimedOut => Err(Error::Net(NetError::Timeout)),
        }?;
        let attested = AttestedConnection::connect(websocket, |attestation_msg| {
            attest::cds2::new_handshake(env.mr_enclave(), attestation_msg, SystemTime::now())
        })
        .await?;

        Ok(Self(attested))
    }

    pub async fn send_request(
        mut self,
        request: LookupRequest,
    ) -> Result<(Token, ClientResponseCollector<S>), Error> {
        self.0.send(request.into_client_request()).await?;
        let token_response: ClientResponse = match self.0.receive().await? {
            NextOrClose::Next(response) => response,
            NextOrClose::Close(close) => {
                if let Some(close) = close {
                    if u16::from(close.code) == RateLimitExceededResponse::CLOSE_CODE {
                        if let Ok(RateLimitExceededResponse { retry_after }) =
                            serde_json::from_str(&close.reason)
                        {
                            return Err(Error::RateLimited {
                                retry_after: Duration::from_secs(retry_after.into()),
                            });
                        }
                    }
                };
                return Err(Error::Protocol);
            }
        };

        if token_response.token.is_empty() {
            return Err(Error::Protocol);
        }

        Ok((
            Token(token_response.token.into_boxed_slice()),
            ClientResponseCollector(self),
        ))
    }
}

impl<S: AsyncDuplexStream> ClientResponseCollector<S> {
    pub async fn collect(self) -> Result<LookupResponse, Error> {
        let Self(mut connection) = self;

        let token_ack = ClientRequest {
            token_ack: true,
            ..Default::default()
        };

        connection.0.send(token_ack).await?;
        let mut response: ClientResponse =
            connection.0.receive().await?.next_or(Error::Protocol)?;
        while let NextOrClose::Next(decoded) = connection.0.receive_bytes().await? {
            response.merge(decoded.as_ref()).map_err(Error::from)?;
        }
        Ok(response.try_into()?)
    }
}

pub trait CdsiConnectionParams {
    /// The type returned by `connection_manager`.
    type ConnectionManager: ConnectionManager;

    /// The `TransportConnector` used by the `WebSocketClientConnector`
    type TransportConnector: TransportConnector;

    /// A connection manager with routes to the remote CDSI service.
    fn connection_manager(&self) -> &Self::ConnectionManager;

    /// A connector for websocket protocol
    fn connector(&self) -> &WebSocketClientConnector<Self::TransportConnector>;

    /// The signature of the remote enclave for verifying attestation.
    fn mr_enclave(&self) -> &[u8];
}

impl<C: ConnectionManager, T: TransportConnector> CdsiConnectionParams
    for EndpointConnection<Cdsi, C, T>
{
    type ConnectionManager = C;
    type TransportConnector = T;

    fn connection_manager(&self) -> &Self::ConnectionManager {
        &self.manager
    }

    fn connector(&self) -> &WebSocketClientConnector<Self::TransportConnector> {
        &self.connector
    }

    fn mr_enclave(&self) -> &[u8] {
        self.params.mr_enclave.as_ref()
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use uuid::Uuid;

    use super::*;

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
            std::iter::repeat([e164_bytes.as_slice(), &PNI_BYTES, &ACI_BYTES])
                .take(NUM_REPEATS)
                .flatten()
                .flatten()
                .cloned()
                .collect();

        let parsed = ClientResponse {
            e164_pni_aci_triples,
            token: vec![],
            debug_permits_used: 0,
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
                ]
            })
        );
    }

    #[test]
    fn serialize_e164s() {
        let e164s: Vec<E164> = (18005551001..)
            .take(5)
            .map(|n| E164(NonZeroU64::new(n).unwrap()))
            .collect();
        let serialized = e164s.into_iter().collect_serialized();

        assert_eq!(
            serialized.as_slice(),
            &hex!(
                "000000043136e799"
                "000000043136e79a"
                "000000043136e79b"
                "000000043136e79c"
                "000000043136e79d"
            )
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
            &hex!(
                "8181818181818181818181818181818101010101010101010101010101010101"
                "8282828282828282828282828282828202020202020202020202020202020202"
                "8383838383838383838383838383838303030303030303030303030303030303"
                "8484848484848484848484848484848404040404040404040404040404040404"
                "8585858585858585858585858585858505050505050505050505050505050505"
            )
        );
    }
}
