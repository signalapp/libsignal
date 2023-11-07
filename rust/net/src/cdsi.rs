//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::num::{NonZeroU64, ParseIntError};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use attest::cds2;
use libsignal_protocol::{Aci, Pni};
use prost::Message as _;
use thiserror::Error;
use uuid::Uuid;

use crate::infra::connection_manager::{ConnectionAttemptOutcome, ConnectionManager};
use crate::infra::errors::NetError;
use crate::infra::ws::{
    connect_websocket, AttestedConnection, AttestedConnectionError, NextOrClose, WebSocket,
};
use crate::infra::TcpSslTransportConnector;

use crate::proto::cds2::{ClientRequest, ClientResponse};
use crate::utils::{basic_authorization, timeout};

pub struct Auth {
    pub username: String,
    pub password: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct E164(NonZeroU64);

impl E164 {
    pub const fn new(number: NonZeroU64) -> Self {
        Self(number)
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

impl E164 {
    const SERIALIZED_LEN: usize = 8;

    pub fn serialize_into(&self, target: &mut [u8; Self::SERIALIZED_LEN]) {
        target.copy_from_slice(&self.0.get().to_be_bytes())
    }

    fn from_serialized(bytes: [u8; E164::SERIALIZED_LEN]) -> Option<Self> {
        NonZeroU64::new(u64::from_be_bytes(bytes)).map(Self)
    }
}

pub struct AciAndAccessKey {
    pub aci: Aci,
    pub access_key: [u8; 16],
}

impl AciAndAccessKey {
    const SERIALIZED_LEN: usize = 32;

    pub fn serialize_into(&self, target: &mut [u8; Self::SERIALIZED_LEN]) {
        let uuid_bytes = Uuid::from(self.aci).into_bytes();

        target[0..uuid_bytes.len()].copy_from_slice(&uuid_bytes);
        target[uuid_bytes.len()..].copy_from_slice(&self.access_key);
    }
}

#[derive(Default)]
pub struct LookupRequest {
    pub e164s: Vec<E164>,
    pub acis_and_access_keys: Vec<AciAndAccessKey>,
    pub return_acis_without_uaks: bool,
}

impl LookupRequest {
    fn into_client_request(self) -> ClientRequest {
        let Self {
            e164s,
            acis_and_access_keys,
            return_acis_without_uaks,
        } = self;

        let mut aci_uak_pairs =
            vec![0; acis_and_access_keys.len() * AciAndAccessKey::SERIALIZED_LEN];
        for (aci_and_access_key, chunk) in acis_and_access_keys
            .iter()
            .zip(aci_uak_pairs.chunks_mut(AciAndAccessKey::SERIALIZED_LEN))
        {
            aci_and_access_key
                .serialize_into(chunk.try_into().expect("chunk size chosen correctly"));
        }

        let mut new_e164s = vec![0; e164s.len() * E164::SERIALIZED_LEN];
        for (e164, chunk) in e164s.iter().zip(new_e164s.chunks_mut(E164::SERIALIZED_LEN)) {
            e164.serialize_into(chunk.try_into().expect("chunk size chosen correctly"))
        }

        ClientRequest {
            aci_uak_pairs,
            new_e164s,
            return_acis_without_uaks,
            token_ack: false,
            // TODO: use these for supporting non-desktop client requirements.
            prev_e164s: Vec::new(),
            discard_e164s: Vec::new(),
            token: Vec::new(),
        }
    }
}

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
enum LookupResponseParseError {
    InvalidNumberOfBytes { actual_length: usize },
}

impl From<LookupResponseParseError> for Error {
    fn from(value: LookupResponseParseError) -> Self {
        match value {
            LookupResponseParseError::InvalidNumberOfBytes { .. } => Self::ParseError,
        }
    }
}

impl LookupResponse {
    fn try_from_response(response: ClientResponse) -> Result<Self, LookupResponseParseError> {
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

pub struct CdsiConnection(AttestedConnection);

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
            AttestedConnectionError::ClientConnection(_) => Error::Protocol,
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

impl CdsiConnection {
    /// Connect to remote host and verify remote attestation.
    pub(crate) async fn connect(
        env: &impl CdsiConnectionParams,
        auth: Auth,
    ) -> Result<Self, Error> {
        let Auth { username, password } = auth;
        let header_auth_decorator = crate::infra::HttpRequestDecorator::HeaderAuth(
            basic_authorization(&username, &password),
        );
        let endpoint = env.endpoint();
        let connection_manager = env.connection_manager();

        let websocket = {
            match connection_manager
                .connect_or_wait(|connection_params| async {
                    let connection_params = connection_params
                        .clone()
                        .with_decorator(header_auth_decorator.clone());
                    connect_websocket(
                        &connection_params,
                        endpoint.clone(),
                        Default::default(),
                        &TcpSslTransportConnector,
                    )
                    .await
                })
                .await
            {
                ConnectionAttemptOutcome::Attempted(connection) => connection.map_err(Into::into),
                ConnectionAttemptOutcome::TimedOut | ConnectionAttemptOutcome::WaitUntil(_) => {
                    Err(NetError::Timeout)
                }
            }
        }?;
        let attested = AttestedConnection::connect(WebSocket::new(websocket), |attestation_msg| {
            cds2::new_handshake(env.mr_enclave(), attestation_msg, SystemTime::now())
        })
        .await?;

        Ok(Self(attested))
    }

    pub async fn send_request(&mut self, request: ClientRequest) -> Result<ClientResponse, Error> {
        self.0.send(request).await?;
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

        let token_ack = ClientRequest {
            token_ack: true,
            ..Default::default()
        };

        self.0.send(token_ack).await?;
        let mut response: ClientResponse = self.0.receive().await?.next_or(Error::Protocol)?;
        while let NextOrClose::Next(decoded) = self.0.receive_bytes().await? {
            response.merge(decoded.as_ref()).map_err(Error::from)?;
        }
        Ok(response)
    }
}

pub trait CdsiConnectionParams {
    /// The type returned by `connection_manager`.
    type ConnectionManager: ConnectionManager;

    /// A connection manager with routes to the remote CDSI service.
    fn connection_manager(&self) -> &Self::ConnectionManager;

    /// The path and query to use when initiating a websocket connection.
    fn endpoint(&self) -> http::uri::PathAndQuery;

    /// The signature of the remote enclave for verifying attestation.
    fn mr_enclave(&self) -> &[u8];
}

pub async fn cdsi_lookup(
    auth: Auth,
    cdsi: &impl CdsiConnectionParams,
    request: LookupRequest,
    action_timeout: Duration,
) -> Result<LookupResponse, Error> {
    let client_request = request.into_client_request();
    let mut connected = CdsiConnection::connect(cdsi, auth).await?;
    let response = timeout(
        action_timeout,
        NetError::Timeout.into(),
        connected.send_request(client_request),
    )
    .await?;

    LookupResponse::try_from_response(response).map_err(Into::into)
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use libsignal_protocol::{Aci, Pni};
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

        let parsed = LookupResponse::try_from_response(ClientResponse {
            e164_pni_aci_triples,
            token: vec![],
            debug_permits_used: 0,
        });
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
}
