//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use itertools::Itertools;
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::chat::UnauthenticatedChatConnection;
pub use libsignal_bridge_types::net::{Environment, TokioAsyncContext};
use libsignal_bridge_types::support::AsType;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{AccountData, StoredAccountData};
use libsignal_net_chat::api::RequestError;
use libsignal_net_chat::api::keytrans::{
    CheckMode, Error, KeyTransparencyClient, MaybePartial, SearchKey, TreeHeadWithTimestamp,
    UsernameHash, check,
};
use libsignal_protocol::PublicKey;
use prost::{DecodeError, Message};

use crate::support::*;
use crate::*;

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

#[bridge_io(TokioAsyncContext)]
#[expect(clippy::too_many_arguments)]
async fn KeyTransparency_Check(
    // TODO: it is currently possible to pass an env that does not match chat
    environment: AsType<Environment, u8>,
    chat_connection: &UnauthenticatedChatConnection,
    aci: Aci,
    aci_identity_key: &PublicKey,
    e164: Option<E164>,
    unidentified_access_key: Option<Box<[u8]>>,
    username_hash: Option<Box<[u8]>>,
    account_data: Option<Box<[u8]>>,
    last_distinguished_tree_head: Option<Box<[u8]>>,
    is_self_check: bool,
    is_e164_discoverable: bool,
    // Return a pair of (serialized account data, serialized distinguished)
    // If the last_distinguished_tree_head was reused, serialized distinguished will be empty.
    // Could have been an Option<Vec<u8>>, but that would be another layer of <> to handle in
    // the bridging macro to the same effect.
) -> Result<(Vec<u8>, Vec<u8>), RequestError<Error>> {
    let config = environment.into_inner().env().keytrans_config;

    let username_hash = username_hash.map(UsernameHash::from);
    let maybe_hash_search_key = username_hash.as_ref().map(|x| x.as_search_key());

    let account_data = account_data.map(try_decode_account_data).transpose()?;

    let mode = if is_self_check {
        CheckMode::SelfCheck {
            is_e164_discoverable,
        }
    } else {
        CheckMode::ContactCheck
    };

    let e164_pair = make_e164_pair(e164, unidentified_access_key)?;

    let last_distinguished_tree_head =
        last_distinguished_tree_head.and_then(try_decode_distinguished);

    let previously_stored_distinguished = last_distinguished_tree_head.clone();

    let (maybe_partial_result, updated_distinguished) = chat_connection
        .as_typed(|chat| {
            Box::pin(async move {
                let kt = KeyTransparencyClient::new(*chat, config);

                check(
                    &kt,
                    &aci,
                    aci_identity_key,
                    e164_pair,
                    username_hash,
                    account_data,
                    last_distinguished_tree_head,
                    mode,
                )
                .await
            })
        })
        .await?;

    let now = SystemTime::now();
    let serialized_account_data = maybe_partial_result.into_serialized_account_data(
        aci.as_search_key(),
        e164.map(|x| x.as_search_key()),
        maybe_hash_search_key,
        now,
    )?;
    let distinguished_to_be_stored = if let Some(known) = previously_stored_distinguished
        && known.tree_head == updated_distinguished
    {
        // Distinguished has not been updated, we must keep its stored_at
        vec![]
    } else {
        updated_distinguished.into_stored(now).encode_to_vec()
    };
    Ok((serialized_account_data, distinguished_to_be_stored))
}

fn invalid_request(msg: &'static str) -> RequestError<Error> {
    RequestError::Other(Error::InvalidRequest(msg))
}

fn invalid_response(msg: String) -> RequestError<Error> {
    RequestError::Other(Error::InvalidResponse(msg))
}

fn make_e164_pair(
    e164: Option<E164>,
    unidentified_access_key: Option<Box<[u8]>>,
) -> Result<Option<(E164, Vec<u8>)>, RequestError<Error>> {
    match (e164, unidentified_access_key) {
        (None, None) => Ok(None),
        (Some(e164), Some(uak)) => Ok(Some((e164, uak.into_vec()))),
        (None, Some(_uak)) => Err(invalid_request("Unidentified access key without an E164")),
        (Some(_e164), None) => Err(invalid_request("E164 without unidentified access key")),
    }
}

fn try_decode<B, T>(bytes: B) -> Result<T, DecodeError>
where
    B: AsRef<[u8]>,
    T: Message + Default,
{
    T::decode(bytes.as_ref())
}

fn try_decode_account_data(bytes: Box<[u8]>) -> Result<AccountData, RequestError<Error>> {
    let stored: StoredAccountData =
        try_decode(bytes).map_err(|_| invalid_request("could not decode account data"))?;
    AccountData::try_from(stored).map_err(|err| RequestError::Other(Error::from(err)))
}

fn try_decode_distinguished(bytes: Box<[u8]>) -> Option<TreeHeadWithTimestamp> {
    try_decode(bytes)
        .ok()
        .and_then(TreeHeadWithTimestamp::from_stored)
}

trait MaybePartialExt {
    fn into_serialized_account_data(
        self,
        aci_search_key: Vec<u8>,
        maybe_e164_search_key: Option<Vec<u8>>,
        maybe_hash_search_key: Option<Vec<u8>>,
        stored_at: SystemTime,
    ) -> Result<Vec<u8>, RequestError<Error>>;
}

impl MaybePartialExt for MaybePartial<AccountData> {
    fn into_serialized_account_data(
        self,
        aci_search_key: Vec<u8>,
        maybe_e164_search_key: Option<Vec<u8>>,
        maybe_hash_search_key: Option<Vec<u8>>,
        stored_at: SystemTime,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        self.map(|data| {
            data.into_stored(
                aci_search_key,
                maybe_e164_search_key,
                maybe_hash_search_key,
                stored_at,
            )
            .encode_to_vec()
        })
        .into_result()
        .map_err(|missing| {
            invalid_response(format!(
                "Some fields are missing from the response: {}",
                missing.iter().join(", ")
            ))
        })
    }
}
