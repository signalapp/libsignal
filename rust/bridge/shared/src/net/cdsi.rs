//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto as _;

use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_net::auth::Auth;
use libsignal_net::cdsi::{
    self, AciAndAccessKey, CdsiConnection, ClientResponseCollector, LookupResponse, Token, E164,
};
use libsignal_net::infra::tcp_ssl::TcpSslConnectorStream;
use libsignal_protocol::{Aci, SignalProtocolError};

use crate::net::{ConnectionManager, TokioAsyncContext};
use crate::support::*;
use crate::*;

#[cfg(feature = "jni")]
/// CDSI-protocol-specific subset of [`libsignal_net::cdsi::LookupError`] cases.
///
/// Contains cases for errors that aren't covered by other error types.
#[derive(Debug, displaydoc::Display)]
pub enum CdsiError {
    /// Protocol error after establishing a connection
    Protocol,
    /// Invalid response received from the server
    InvalidResponse,
    /// Retry later
    RateLimited { retry_after: std::time::Duration },
    /// Failed to parse the response from the server
    ParseError,
    /// Request token was invalid
    InvalidToken,
    /// Server error: {reason}
    Server { reason: &'static str },
}

#[derive(Default)]
pub struct LookupRequest(std::sync::Mutex<cdsi::LookupRequest>);

#[bridge_fn]
fn LookupRequest_new() -> LookupRequest {
    LookupRequest::default()
}

#[bridge_fn]
fn LookupRequest_addE164(request: &LookupRequest, e164: E164) {
    request.0.lock().expect("not poisoned").new_e164s.push(e164)
}

#[bridge_fn]
fn LookupRequest_addPreviousE164(request: &LookupRequest, e164: E164) {
    request
        .0
        .lock()
        .expect("not poisoned")
        .prev_e164s
        .push(e164)
}

#[bridge_fn]
fn LookupRequest_setToken(request: &LookupRequest, token: &[u8]) {
    request.0.lock().expect("not poisoned").token = token.into();
}

#[bridge_fn]
fn LookupRequest_addAciAndAccessKey(
    request: &LookupRequest,
    aci: Aci,
    access_key: &[u8],
) -> Result<(), SignalProtocolError> {
    let access_key = access_key
        .try_into()
        .map_err(|_: std::array::TryFromSliceError| {
            SignalProtocolError::InvalidArgument("access_key has wrong number of bytes".to_string())
        })?;
    request
        .0
        .lock()
        .expect("not poisoned")
        .acis_and_access_keys
        .push(AciAndAccessKey { aci, access_key });
    Ok(())
}

#[bridge_fn]
fn LookupRequest_setReturnAcisWithoutUaks(request: &LookupRequest, return_acis_without_uaks: bool) {
    request
        .0
        .lock()
        .expect("not poisoned")
        .return_acis_without_uaks = return_acis_without_uaks;
}

bridge_handle!(LookupRequest, clone = false);

pub struct CdsiLookup {
    token: Token,
    remaining: std::sync::Mutex<Option<ClientResponseCollector<TcpSslConnectorStream>>>,
}
bridge_handle!(CdsiLookup, clone = false);

#[bridge_io(TokioAsyncContext)]
async fn CdsiLookup_new(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
    request: &LookupRequest,
) -> Result<CdsiLookup, cdsi::LookupError> {
    let request = std::mem::take(&mut *request.0.lock().expect("not poisoned"));
    let auth = Auth { username, password };

    let transport_connector = connection_manager
        .transport_connector
        .lock()
        .expect("not poisoned")
        .clone();
    let connected =
        CdsiConnection::connect(&connection_manager.cdsi, transport_connector, auth).await?;
    let (token, remaining_response) = connected.send_request(request).await?;

    Ok(CdsiLookup {
        token,
        remaining: std::sync::Mutex::new(Some(remaining_response)),
    })
}

#[bridge_fn]
fn CdsiLookup_token(lookup: &CdsiLookup) -> &[u8] {
    &lookup.token.0
}

#[bridge_io(TokioAsyncContext)]
async fn CdsiLookup_complete(lookup: &CdsiLookup) -> Result<LookupResponse, cdsi::LookupError> {
    let CdsiLookup {
        token: _,
        remaining,
    } = lookup;

    let remaining = remaining
        .lock()
        .expect("not poisoned")
        .take()
        .expect("not completed yet");

    remaining.collect().await
}
