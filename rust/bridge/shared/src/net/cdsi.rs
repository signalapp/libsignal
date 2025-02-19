//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto as _;

use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::cdsi::{CdsiLookup, LookupRequest};
use libsignal_bridge_types::net::{ConnectionManager, TokioAsyncContext};
use libsignal_core::E164;
use libsignal_net::auth::Auth;
use libsignal_net::cdsi::{self, AciAndAccessKey, LookupResponse};
use libsignal_protocol::{Aci, SignalProtocolError};

use crate::support::*;
use crate::*;

bridge_handle_fns!(LookupRequest, clone = false);

#[bridge_fn]
fn LookupRequest_new() -> LookupRequest {
    LookupRequest::default()
}

#[bridge_fn]
fn LookupRequest_addE164(request: &LookupRequest, e164: E164) {
    request.lock().new_e164s.push(e164)
}

#[bridge_fn]
fn LookupRequest_addPreviousE164(request: &LookupRequest, e164: E164) {
    request.lock().prev_e164s.push(e164)
}

#[bridge_fn]
fn LookupRequest_setToken(request: &LookupRequest, token: &[u8]) {
    request.lock().token = token.into();
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
        .lock()
        .acis_and_access_keys
        .push(AciAndAccessKey { aci, access_key });
    Ok(())
}

bridge_handle_fns!(CdsiLookup, clone = false);

#[bridge_io(TokioAsyncContext)]
async fn CdsiLookup_new(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
    request: &LookupRequest,
) -> Result<CdsiLookup, cdsi::LookupError> {
    let request = std::mem::take(&mut *request.lock());
    let auth = Auth { username, password };

    CdsiLookup::new(connection_manager, auth, request).await
}

#[bridge_io(TokioAsyncContext)]
async fn CdsiLookup_new_routes(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
    request: &LookupRequest,
) -> Result<CdsiLookup, cdsi::LookupError> {
    let request = std::mem::take(&mut *request.lock());
    let auth = Auth { username, password };

    CdsiLookup::new_routes(connection_manager, auth, request).await
}

#[bridge_fn]
fn CdsiLookup_token(lookup: &CdsiLookup) -> &[u8] {
    &lookup.token.0
}

#[bridge_io(TokioAsyncContext)]
async fn CdsiLookup_complete(lookup: &CdsiLookup) -> Result<LookupResponse, cdsi::LookupError> {
    lookup
        .take_remaining()
        .expect("not completed yet")
        .collect()
        .await
}
