//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use itertools::Itertools;
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::keytrans::BridgeError;
use libsignal_bridge_types::net::chat::UnauthenticatedChatConnection;
pub use libsignal_bridge_types::net::{Environment, TokioAsyncContext};
use libsignal_bridge_types::support::AsType;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{AccountData, LocalStateUpdate, StoredAccountData, StoredTreeHead};
use libsignal_net_chat::api::Unauth;
use libsignal_net_chat::api::keytrans::{
    Error, KeyTransparencyClient, MaybePartial, MonitorMode, SearchKey,
    UnauthenticatedChatApi as _, UsernameHash, monitor_and_search,
};
use libsignal_protocol::PublicKey;
use prost::{DecodeError, Message};

use crate::support::*;
use crate::*;

/// An alias to make using `from` cleaner.
type UnauthConnectionRef<'a, T> = &'a Unauth<T>;

#[bridge_fn]
fn KeyTransparency_AciSearchKey(aci: Aci) -> Vec<u8> {
    aci.as_search_key()
}

#[bridge_fn]
fn KeyTransparency_E164SearchKey(e164: E164) -> Vec<u8> {
    e164.as_search_key()
}

#[bridge_fn]
fn KeyTransparency_UsernameHashSearchKey(hash: &[u8]) -> Vec<u8> {
    UsernameHash::from_slice(hash).as_search_key()
}

fn try_decode<B, T>(bytes: B) -> Result<T, DecodeError>
where
    B: AsRef<[u8]>,
    T: Message + Default,
{
    T::decode(bytes.as_ref())
}

#[bridge_io(TokioAsyncContext)]
#[expect(clippy::too_many_arguments)]
async fn KeyTransparency_Search(
    // TODO: it is currently possible to pass an env that does not match chat
    environment: AsType<Environment, u8>,
    chat_connection: &UnauthenticatedChatConnection,
    aci: Aci,
    aci_identity_key: &PublicKey,
    e164: Option<E164>,
    unidentified_access_key: Option<Box<[u8]>>,
    username_hash: Option<Box<[u8]>>,
    account_data: Option<Box<[u8]>>,
    last_distinguished_tree_head: Box<[u8]>,
) -> Result<Vec<u8>, BridgeError> {
    let username_hash = username_hash.map(UsernameHash::from);
    let config = environment.into_inner().env().keytrans_config;
    let kt = KeyTransparencyClient::new(UnauthConnectionRef::from(chat_connection), config);

    let e164_pair = make_e164_pair(e164, unidentified_access_key)?;

    let account_data = account_data
        .map(|bytes| {
            let stored: StoredAccountData = try_decode(bytes)
                .map_err(|_| Error::InvalidRequest("could not decode account data"))?;
            AccountData::try_from(stored).map_err(Error::from)
        })
        .transpose()?;

    let last_distinguished_tree_head = try_decode(last_distinguished_tree_head)
        .map(|stored: StoredTreeHead| stored.into_last_tree_head())
        .map_err(|_| Error::InvalidRequest("could not decode last distinguished tree head"))?
        .ok_or(Error::InvalidRequest("last distinguished tree is required"))?;

    let MaybePartial {
        inner: returned_account_data,
        missing_fields,
    } = kt
        .search(
            &aci,
            aci_identity_key,
            e164_pair,
            username_hash,
            account_data,
            &last_distinguished_tree_head,
        )
        .await?;

    if missing_fields.is_empty() {
        Ok(StoredAccountData::from(returned_account_data).encode_to_vec())
    } else {
        Err(Error::InvalidResponse(format!(
            "some fields are missing from the response: {}",
            &itertools::join(&missing_fields, ", ")
        ))
        .into())
    }
}

#[bridge_io(TokioAsyncContext)]
#[expect(clippy::too_many_arguments)]
async fn KeyTransparency_Monitor(
    // TODO: it is currently possible to pass an env that does not match chat
    environment: AsType<Environment, u8>,
    chat_connection: &UnauthenticatedChatConnection,
    aci: Aci,
    aci_identity_key: &PublicKey,
    e164: Option<E164>,
    unidentified_access_key: Option<Box<[u8]>>,
    username_hash: Option<Box<[u8]>>,
    // Bridging this as optional even though it is required because it is
    // simpler to produce an error once here than on all platforms.
    account_data: Option<Box<[u8]>>,
    last_distinguished_tree_head: Box<[u8]>,
    is_self_monitor: bool,
) -> Result<Vec<u8>, BridgeError> {
    let username_hash = username_hash.map(UsernameHash::from);

    let Some(account_data) = account_data else {
        return Err(Error::InvalidRequest("account data not found in store").into());
    };

    let account_data = {
        let stored: StoredAccountData = try_decode(account_data)
            .map_err(|_| Error::InvalidRequest("could not decode account data"))?;
        AccountData::try_from(stored).map_err(Error::from)?
    };

    let last_distinguished_tree_head = try_decode(last_distinguished_tree_head)
        .map(|stored: StoredTreeHead| stored.into_last_tree_head())
        .map_err(|_| Error::InvalidRequest("could not decode last distinguished tree head"))?
        .ok_or(Error::InvalidRequest("last distinguished tree is required"))?;

    let config = environment.into_inner().env().keytrans_config;
    let kt = KeyTransparencyClient::new(UnauthConnectionRef::from(chat_connection), config);

    let mode = if is_self_monitor {
        MonitorMode::MonitorSelf
    } else {
        MonitorMode::MonitorOther
    };

    let e164_pair = make_e164_pair(e164, unidentified_access_key)?;
    let MaybePartial {
        inner: updated_account_data,
        missing_fields,
    } = monitor_and_search(
        &kt,
        &aci,
        aci_identity_key,
        e164_pair,
        username_hash,
        account_data,
        &last_distinguished_tree_head,
        mode,
    )
    .await?;

    if !missing_fields.is_empty() {
        return Err(Error::InvalidResponse(format!(
            "Missing fields: {}",
            missing_fields.iter().join(", ")
        ))
        .into());
    }

    Ok(StoredAccountData::from(updated_account_data).encode_to_vec())
}

#[bridge_io(TokioAsyncContext)]
async fn KeyTransparency_Distinguished(
    // TODO: it is currently possible to pass an env that does not match chat
    environment: AsType<Environment, u8>,
    chat_connection: &UnauthenticatedChatConnection,
    last_distinguished_tree_head: Option<Box<[u8]>>,
) -> Result<Vec<u8>, BridgeError> {
    let config = environment.into_inner().env().keytrans_config;
    let kt = KeyTransparencyClient::new(UnauthConnectionRef::from(chat_connection), config);

    let known_distinguished = last_distinguished_tree_head
        .map(try_decode)
        .transpose()
        .map_err(|_| Error::InvalidRequest("could not decode account data"))?
        .and_then(|stored: StoredTreeHead| stored.into_last_tree_head());
    let LocalStateUpdate {
        tree_head,
        tree_root,
        monitoring_data: _,
    } = kt.distinguished(known_distinguished).await?;
    let updated_distinguished = StoredTreeHead::from((tree_head, tree_root));
    let serialized = updated_distinguished.encode_to_vec();
    Ok(serialized)
}

fn make_e164_pair(
    e164: Option<E164>,
    unidentified_access_key: Option<Box<[u8]>>,
) -> Result<Option<(E164, Vec<u8>)>, Error> {
    match (e164, unidentified_access_key) {
        (None, None) => Ok(None),
        (Some(e164), Some(uak)) => Ok(Some((e164, uak.into_vec()))),
        (None, Some(_uak)) => Err(Error::InvalidRequest(
            "Unidentified access key without an E164",
        )),
        (Some(_e164), None) => Err(Error::InvalidRequest(
            "E164 without unidentified access key",
        )),
    }
}
