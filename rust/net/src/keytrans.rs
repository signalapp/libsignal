//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::time::{Duration, SystemTime};

use base64::prelude::{
    Engine as _, BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE_NO_PAD,
};
use futures_util::future::BoxFuture;
use http::header::{ACCEPT, CONTENT_TYPE};
use http::uri::PathAndQuery;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{
    AccountData, ChatDistinguishedResponse, ChatMonitorResponse, ChatSearchResponse,
    CondensedTreeSearchResponse, FullSearchResponse, FullTreeHead, KeyTransparency, LastTreeHead,
    LocalStateUpdate, MonitorContext, MonitorKey, MonitorProof, MonitorRequest, MonitorResponse,
    MonitoringData, SearchContext, SearchStateUpdate, SlimSearchRequest, StoredAccountData,
    StoredMonitoringData, StoredTreeHead, VerifiedSearchResult,
};
use libsignal_protocol::{IdentityKey, PublicKey};
use prost::{DecodeError, Message};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::chat;

const SEARCH_PATH: &str = "/v1/key-transparency/search";
const DISTINGUISHED_PATH: &str = "/v1/key-transparency/distinguished";
const MONITOR_PATH: &str = "/v1/key-transparency/monitor";

const MIME_TYPE: &str = "application/json";

fn common_headers() -> http::HeaderMap {
    http::HeaderMap::from_iter([
        (CONTENT_TYPE, http::HeaderValue::from_static(MIME_TYPE)),
        (ACCEPT, http::HeaderValue::from_static(MIME_TYPE)),
    ])
}

#[derive(Debug, Error, displaydoc::Display)]
#[ignore_extra_doc_attributes]
pub enum Error {
    /// Chat request failed: {0}
    ChatServiceError(#[from] chat::ChatServiceError),
    /// Bad status code: {0}
    RequestFailed(http::StatusCode),
    /// Verification failed: {0}
    VerificationFailed(#[from] libsignal_keytrans::Error),
    /// Invalid response: {0}
    InvalidResponse(String),
    /// Invalid request: {0}
    InvalidRequest(&'static str),
    /// Invalid protobuf: {0}
    DecodingFailed(DecodeError),
}

impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Self {
        Error::DecodingFailed(err)
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawChatSearchRequest {
    aci: String,
    aci_identity_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    e164: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unidentified_access_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_tree_head_size: Option<u64>,
    distinguished_tree_head_size: u64,
}

impl RawChatSearchRequest {
    fn new(
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<&(E164, Vec<u8>)>,
        username_hash: Option<&UsernameHash>,
        last_tree_head_size: Option<u64>,
        distinguished_tree_head_size: u64,
    ) -> Self {
        Self {
            aci: aci.as_chat_value(),
            aci_identity_key: BASE64_STANDARD.encode(aci_identity_key.serialize()),
            e164: e164.map(|x| x.0.as_chat_value()),
            username_hash: username_hash.map(|x| x.as_chat_value()),
            unidentified_access_key: e164.map(|x| BASE64_STANDARD.encode(&x.1)),
            last_tree_head_size,
            distinguished_tree_head_size,
        }
    }
}

impl From<RawChatSearchRequest> for chat::Request {
    fn from(request: RawChatSearchRequest) -> Self {
        Self {
            method: http::Method::POST,
            body: Some(serde_json::to_vec(&request).unwrap().into_boxed_slice()),
            headers: common_headers(),
            path: PathAndQuery::from_static(SEARCH_PATH),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RawChatSerializedResponse {
    serialized_response: String,
}

impl TryFrom<chat::Response> for RawChatSerializedResponse {
    type Error = Error;

    fn try_from(response: chat::Response) -> Result<Self> {
        let body = response
            .body
            .ok_or(Error::InvalidResponse("missing body".to_string()))?;
        serde_json::from_slice(&body)
            .map_err(|_| Error::InvalidResponse("invalid JSON".to_string()))
    }
}

// Differs from [`ChatSearchResponse`] by establishing proper optionality of fields.
struct TypedSearchResponse {
    full_tree_head: FullTreeHead,
    aci_search_response: CondensedTreeSearchResponse,
    e164_search_response: Option<CondensedTreeSearchResponse>,
    username_hash_search_response: Option<CondensedTreeSearchResponse>,
}

impl TypedSearchResponse {
    fn from_untyped(
        require_e164: bool,
        require_username_hash: bool,
        response: ChatSearchResponse,
    ) -> Result<Self> {
        if require_e164 != response.e164.is_some()
            || require_username_hash != response.username_hash.is_some()
        {
            return Err(Error::InvalidResponse(
                "request/response optionality mismatch".to_string(),
            ));
        }
        let ChatSearchResponse {
            tree_head,
            aci,
            e164,
            username_hash,
        } = response;
        Ok(Self {
            full_tree_head: tree_head
                .ok_or(Error::InvalidResponse("missing tree head".to_string()))?,
            aci_search_response: aci.ok_or(Error::InvalidResponse(
                "missing ACI search response".to_string(),
            ))?,
            e164_search_response: e164,
            username_hash_search_response: username_hash,
        })
    }
}

fn decode_response<S, R>(b64: S) -> Result<R>
where
    S: AsRef<str>,
    R: Message + Default,
{
    let proto_bytes = BASE64_STANDARD_NO_PAD
        .decode(b64.as_ref())
        .map_err(|_| Error::InvalidResponse("invalid base64".to_string()))?;

    R::decode(proto_bytes.as_slice()).map_err(|_| {
        Error::InvalidResponse("invalid search response protobuf encoding".to_string())
    })
}

// 0x00 is the current version prefix
const SEARCH_VALUE_PREFIX: u8 = 0x00;

/// A safe-to-use wrapper around the values returned by KT server.
///
/// The KT server stores values prefixed with an extra "version" byte, that needs
/// to be stripped.
///
/// SearchValue validates the prefix upon construction from raw bytes, and
/// provides access to the actual underlying value via its payload method.
struct SearchValue<'a> {
    raw: &'a [u8],
}

impl<'a> TryFrom<&'a VerifiedSearchResult> for SearchValue<'a> {
    type Error = Error;

    fn try_from(result: &'a VerifiedSearchResult) -> Result<Self> {
        let raw = result.value.as_slice();
        if raw.first() == Some(&SEARCH_VALUE_PREFIX) {
            Ok(Self { raw })
        } else {
            Err(Error::InvalidResponse("bad value format".to_string()))
        }
    }
}

impl SearchValue<'_> {
    fn payload(&self) -> &[u8] {
        &self.raw[1..]
    }
}

impl TryFrom<SearchValue<'_>> for Aci {
    type Error = Error;

    fn try_from(value: SearchValue) -> std::result::Result<Self, Self::Error> {
        Aci::parse_from_service_id_binary(value.payload())
            .ok_or(Error::InvalidResponse("bad ACI".to_string()))
    }
}

impl TryFrom<SearchValue<'_>> for IdentityKey {
    type Error = Error;

    fn try_from(value: SearchValue) -> std::result::Result<Self, Self::Error> {
        IdentityKey::decode(value.payload())
            .map_err(|_| Error::InvalidResponse("bad identity key".to_string()))
    }
}

struct RawChatDistinguishedRequest {
    last_tree_head_size: Option<u64>,
}

impl From<RawChatDistinguishedRequest> for chat::Request {
    fn from(request: RawChatDistinguishedRequest) -> Self {
        let query_string = request
            .last_tree_head_size
            .map(|n| format!("lastTreeHeadSize={n}"))
            .unwrap_or_default();
        let path_and_query = PathAndQuery::try_from(format!("{DISTINGUISHED_PATH}?{query_string}"))
            .expect("valid path and query");
        Self {
            method: http::Method::GET,
            body: None,
            headers: common_headers(),
            path: path_and_query,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ValueMonitor {
    value: String,
    entry_position: u64,
    commitment_index: String,
}

impl ValueMonitor {
    fn new(value: String, entry_position: u64, commitment_index: &[u8]) -> Self {
        Self {
            value,
            entry_position,
            commitment_index: BASE64_STANDARD_NO_PAD.encode(commitment_index),
        }
    }

    fn for_aci(aci: &Aci, entry_position: u64, commitment_index: &[u8]) -> Self {
        Self::new(aci.as_chat_value(), entry_position, commitment_index)
    }

    fn for_e164(e164: E164, entry_position: u64, commitment_index: &[u8]) -> Self {
        Self::new(e164.as_chat_value(), entry_position, commitment_index)
    }

    fn for_username_hash(
        username_hash: &UsernameHash,
        entry_position: u64,
        commitment_index: &[u8],
    ) -> Self {
        Self::new(
            username_hash.as_chat_value(),
            entry_position,
            commitment_index,
        )
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawChatMonitorRequest {
    aci: ValueMonitor,
    #[serde(skip_serializing_if = "Option::is_none")]
    e164: Option<ValueMonitor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username_hash: Option<ValueMonitor>,
    last_non_distinguished_tree_head_size: u64,
    last_distinguished_tree_head_size: u64,
}

impl From<RawChatMonitorRequest> for chat::Request {
    fn from(request: RawChatMonitorRequest) -> Self {
        Self {
            method: http::Method::POST,
            body: Some(serde_json::to_vec(&request).unwrap().into_boxed_slice()),
            headers: common_headers(),
            path: PathAndQuery::from_static(MONITOR_PATH),
        }
    }
}

impl RawChatMonitorRequest {
    fn new(
        aci: &Aci,
        e164: Option<E164>,
        username_hash: &Option<UsernameHash<'_>>,
        account_data: &AccountData,
        distinguished_tree_head_size: u64,
    ) -> Result<Self> {
        let last_non_distinguished_tree_head_size = account_data.last_tree_head.0.tree_size;

        if e164.is_some() != account_data.e164.is_some()
            || username_hash.is_some() != account_data.username_hash.is_some()
        {
            return Err(Error::InvalidRequest(
                "account data does not match the monitor request",
            ));
        }

        Ok(Self {
            aci: ValueMonitor::for_aci(
                aci,
                account_data.aci.latest_log_position(),
                &account_data.aci.index,
            ),
            e164: e164.map(|e164| {
                ValueMonitor::for_e164(
                    e164,
                    account_data.e164.as_ref().unwrap().latest_log_position(),
                    &account_data.e164.as_ref().unwrap().index,
                )
            }),
            username_hash: username_hash.as_ref().map(|unh| {
                ValueMonitor::for_username_hash(
                    unh,
                    account_data
                        .username_hash
                        .as_ref()
                        .unwrap()
                        .latest_log_position(),
                    &account_data.username_hash.as_ref().unwrap().index,
                )
            }),
            last_non_distinguished_tree_head_size,
            last_distinguished_tree_head_size: distinguished_tree_head_size,
        })
    }
}

// Same as ChatMonitorResponse, only with the right optionality of fields
#[derive(Clone, Debug)]
struct TypedMonitorResponse {
    tree_head: FullTreeHead,
    aci: MonitorProof,
    e164: Option<MonitorProof>,
    username_hash: Option<MonitorProof>,
    inclusion: Vec<Vec<u8>>,
}

impl TypedMonitorResponse {
    fn from_untyped(
        require_e164: bool,
        require_username_hash: bool,
        response: ChatMonitorResponse,
    ) -> Result<Self> {
        if require_e164 != response.e164.is_some()
            || require_username_hash != response.username_hash.is_some()
        {
            return Err(Error::InvalidResponse(
                "request/response optionality mismatch".to_string(),
            ));
        }
        let ChatMonitorResponse {
            tree_head,
            aci,
            username_hash,
            e164,
            inclusion,
        } = response;
        Ok(Self {
            tree_head: tree_head.ok_or(Error::InvalidResponse("missing tree head".to_string()))?,
            aci: aci.ok_or(Error::InvalidResponse(
                "missing ACI monitor proof".to_string(),
            ))?,
            e164,
            username_hash,
            inclusion,
        })
    }
}

pub trait UnauthenticatedChat {
    fn send_unauthenticated(
        &self,
        request: chat::Request,
        timeout: Duration,
    ) -> BoxFuture<'_, std::result::Result<chat::Response, chat::ChatServiceError>>;
}

pub struct Config {
    chat_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chat_timeout: Duration::from_secs(10),
        }
    }
}

pub struct Kt<'a> {
    pub inner: KeyTransparency,
    pub chat: &'a (dyn UnauthenticatedChat + Sync),
    pub config: Config,
}

/// A tag identifying an optional field in [`AccountData`]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, displaydoc::Display)]
pub enum AccountDataField {
    /// E.164
    E164,
    /// Username hash
    UsernameHash,
}

/// This struct adds to its type parameter a (potentially empty) list of
/// account fields (see [`AccountDataField`]) that can no longer be verified
/// by the server.
///
/// Basically it is a non-generic version of a `Writer` monad with [`BTreeSet`] used
/// to accumulate missing field entries in some order while avoiding duplicates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaybePartial<T> {
    pub inner: T,
    pub missing_fields: BTreeSet<AccountDataField>,
}

impl<T> From<T> for MaybePartial<T> {
    fn from(value: T) -> Self {
        Self {
            inner: value,
            missing_fields: Default::default(),
        }
    }
}

impl<T> MaybePartial<T> {
    fn new_complete(inner: T) -> Self {
        Self {
            inner,
            missing_fields: Default::default(),
        }
    }

    fn new(inner: T, missing_fields: impl IntoIterator<Item = AccountDataField>) -> Self {
        Self {
            inner,
            missing_fields: BTreeSet::from_iter(missing_fields),
        }
    }

    fn map<U>(self, f: impl FnOnce(T) -> U) -> MaybePartial<U> {
        MaybePartial {
            inner: f(self.inner),
            missing_fields: self.missing_fields,
        }
    }

    fn and_then<U>(self, f: impl FnOnce(T) -> MaybePartial<U>) -> MaybePartial<U> {
        let MaybePartial {
            inner,
            mut missing_fields,
        } = self;
        let MaybePartial {
            inner: final_inner,
            missing_fields: other_missing,
        } = f(inner);
        missing_fields.extend(other_missing);
        MaybePartial {
            inner: final_inner,
            missing_fields,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T, E> MaybePartial<std::result::Result<T, E>> {
    fn transpose(self) -> std::result::Result<MaybePartial<T>, E> {
        let MaybePartial {
            inner,
            missing_fields,
        } = self;
        Ok(MaybePartial {
            inner: inner?,
            missing_fields,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub aci_identity_key: IdentityKey,
    pub aci_for_e164: Option<Aci>,
    pub aci_for_username_hash: Option<Aci>,
    pub timestamp: SystemTime,
    pub account_data: StoredAccountData,
}

pub trait KtApi {
    fn search(
        &self,
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<(E164, Vec<u8>)>,
        username_hash: Option<UsernameHash<'_>>,
        stored_account_data: Option<AccountData>,
        distinguished_tree_head: &LastTreeHead,
    ) -> impl Future<Output = Result<MaybePartial<SearchResult>>> + Send;

    fn distinguished(
        &self,
        last_distinguished: Option<LastTreeHead>,
    ) -> impl Future<Output = Result<SearchStateUpdate>> + Send;

    fn monitor(
        &self,
        aci: &Aci,
        e164: Option<E164>,
        username_hash: Option<UsernameHash<'_>>,
        account_data: AccountData,
        last_distinguished_tree_head: &LastTreeHead,
    ) -> impl Future<Output = Result<AccountData>> + Send;
}

pub async fn monitor_and_search(
    kt: &impl KtApi,
    aci: &Aci,
    aci_identity_key: &PublicKey,
    e164: Option<(E164, Vec<u8>)>,
    username_hash: Option<UsernameHash<'_>>,
    stored_account_data: AccountData,
    distinguished_tree_head: &LastTreeHead,
) -> Result<MaybePartial<AccountData>> {
    let updated_account_data = kt
        .monitor(
            aci,
            e164.as_ref().map(|(e164, _)| *e164),
            username_hash.clone(),
            stored_account_data.clone(),
            distinguished_tree_head,
        )
        .await?;

    // Call to `monitor` guarantees that the optionality of E.164 and username hash data
    // will match between `stored_account_data` and `updated_account_data`. Meaning, they will
    // either both be Some() or both None.
    let should_search = has_version_changed_between(&stored_account_data, &updated_account_data);
    let final_account_data = if should_search {
        let search_result = kt
            .search(
                aci,
                aci_identity_key,
                e164,
                username_hash,
                Some(stored_account_data),
                distinguished_tree_head,
            )
            .await?;
        search_result
            .map(|res| AccountData::try_from(res.account_data))
            .transpose()?
    } else {
        updated_account_data.into()
    };
    Ok(final_account_data)
}

fn cmp_by_key<T, K: Ord>(lhs: &T, rhs: &T, get_key: impl Fn(&T) -> K) -> Ordering {
    get_key(lhs).cmp(&get_key(rhs))
}

/// Compare the account data fields between stored and received from monitor call,
/// and decide whether there is a newer version of search key in the tree, in which
/// case search request needs to be performed.
fn has_version_changed_between(stored: &AccountData, updated: &AccountData) -> bool {
    let e164_version =
        |acc_data: &AccountData| acc_data.e164.as_ref().map(|md| md.greatest_version());
    let username_hash_version = |acc_data: &AccountData| {
        acc_data
            .username_hash
            .as_ref()
            .map(|md| md.greatest_version())
    };

    cmp_by_key(stored, updated, e164_version) == Ordering::Less
        || cmp_by_key(stored, updated, username_hash_version) == Ordering::Less
}

impl Kt<'_> {
    async fn send(&self, request: chat::Request) -> Result<chat::Response> {
        log::debug!("{}", &request.path.as_str());
        log::debug!(
            "{}",
            &String::from_utf8(request.clone().body.unwrap_or_default().to_vec()).unwrap()
        );
        let response = self
            .chat
            .send_unauthenticated(request, self.config.chat_timeout)
            .await?;
        log::debug!(
            "{} {:?}, headers: {:?}, body: {}",
            &response.status,
            &response.message,
            &response.headers,
            hex::encode({
                let body_slice = response.body.as_deref().unwrap_or_default();
                &body_slice[..body_slice.len().min(1024)]
            })
        );
        if !response.status.is_success() {
            Err(Error::RequestFailed(response.status))
        } else {
            Ok(response)
        }
    }
}

impl KtApi for Kt<'_> {
    async fn search(
        &self,
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<(E164, Vec<u8>)>,
        username_hash: Option<UsernameHash<'_>>,
        stored_account_data: Option<AccountData>,
        distinguished_tree_head: &LastTreeHead,
    ) -> Result<MaybePartial<SearchResult>> {
        let raw_request = RawChatSearchRequest::new(
            aci,
            aci_identity_key,
            e164.as_ref(),
            username_hash.as_ref(),
            stored_account_data
                .as_ref()
                .map(|acc_data| acc_data.last_tree_head.0.tree_size),
            distinguished_tree_head.0.tree_size,
        );
        let response = self.send(raw_request.into()).await?;

        let chat_search_response = RawChatSerializedResponse::try_from(response)
            .and_then(|r| decode_response(r.serialized_response))
            .and_then(|r| {
                TypedSearchResponse::from_untyped(e164.is_some(), username_hash.is_some(), r)
            })?;

        let now = SystemTime::now();

        verify_chat_search_response(
            &self.inner,
            aci,
            e164.map(|(e164, _)| e164),
            username_hash,
            stored_account_data,
            chat_search_response,
            Some(distinguished_tree_head),
            now,
        )
    }

    async fn distinguished(
        &self,
        last_distinguished: Option<LastTreeHead>,
    ) -> Result<SearchStateUpdate> {
        let distinguished_size = last_distinguished
            .as_ref()
            .map(|last_tree_head| last_tree_head.0.tree_size);

        let raw_request = RawChatDistinguishedRequest {
            last_tree_head_size: distinguished_size,
        };
        let response = self.send(raw_request.into()).await?;

        let ChatDistinguishedResponse {
            tree_head,
            distinguished,
        } = RawChatSerializedResponse::try_from(response)
            .and_then(|r| decode_response(r.serialized_response))?;

        let tree_head = tree_head.ok_or(Error::InvalidResponse(
            "tree head must be present".to_string(),
        ))?;
        let condensed_response = distinguished.ok_or(Error::InvalidResponse(
            "search response must be present".to_string(),
        ))?;
        let search_response = FullSearchResponse::new(condensed_response, &tree_head);

        let slim_search_request = SlimSearchRequest::new(b"distinguished".to_vec());

        let verified_result = self.inner.verify_search(
            slim_search_request,
            search_response,
            SearchContext {
                last_tree_head: None,
                last_distinguished_tree_head: last_distinguished.as_ref(),
                data: None,
            },
            false,
            SystemTime::now(),
        )?;
        Ok(verified_result.state_update)
    }

    async fn monitor(
        &self,
        aci: &Aci,
        e164: Option<E164>,
        username_hash: Option<UsernameHash<'_>>,
        account_data: AccountData,
        last_distinguished_tree_head: &LastTreeHead,
    ) -> Result<AccountData> {
        let raw_request = RawChatMonitorRequest::new(
            aci,
            e164,
            &username_hash,
            &account_data,
            last_distinguished_tree_head.0.tree_size,
        )?;
        let response = self.send(raw_request.into()).await?;

        let chat_monitor_response = RawChatSerializedResponse::try_from(response)
            .and_then(|r| decode_response(r.serialized_response))
            .and_then(|r| {
                TypedMonitorResponse::from_untyped(e164.is_some(), username_hash.is_some(), r)
            })?;

        let now = SystemTime::now();

        let updated_account_data = {
            let AccountData {
                aci: aci_monitoring_data,
                e164: e164_monitoring_data,
                username_hash: username_hash_monitoring_data,
                last_tree_head,
            } = account_data;

            let mut monitor_keys = Vec::with_capacity(3);
            let mut proofs = Vec::with_capacity(3);
            let mut monitoring_data_map = HashMap::with_capacity(3);

            let aci_monitor_key = MonitorKey {
                search_key: aci.as_search_key(),
                entry_position: aci_monitoring_data.latest_log_position(),
                commitment_index: aci_monitoring_data.index.to_vec(),
            };
            monitor_keys.push(aci_monitor_key);
            proofs.push(chat_monitor_response.aci);
            monitoring_data_map.insert(aci.as_search_key(), aci_monitoring_data.clone());

            if let Some(e164) = e164 {
                let monitoring_data = e164_monitoring_data
                    .ok_or(Error::InvalidRequest("missing E.164 monitoring data"))?;
                let key = MonitorKey {
                    search_key: e164.as_search_key(),
                    entry_position: monitoring_data.latest_log_position(),
                    commitment_index: monitoring_data.index.to_vec(),
                };
                monitor_keys.push(key);

                // The proof must be present. Checked in TypedMonitorResponse::from_untyped
                proofs.push(chat_monitor_response.e164.unwrap());
                monitoring_data_map.insert(e164.as_search_key(), monitoring_data);
            }

            if let Some(username_hash) = username_hash.clone() {
                let monitoring_data = username_hash_monitoring_data.ok_or(
                    Error::InvalidRequest("missing username hash monitoring data"),
                )?;
                let key = MonitorKey {
                    search_key: username_hash.as_search_key().to_vec(),
                    entry_position: monitoring_data.latest_log_position(),
                    commitment_index: monitoring_data.index.to_vec(),
                };
                monitor_keys.push(key);
                // The proof must be present. Checked in TypedMonitorResponse::from_untyped
                proofs.push(chat_monitor_response.username_hash.unwrap());
                monitoring_data_map.insert(username_hash.as_search_key(), monitoring_data);
            }

            // We are using a single monitor request/response pair for all the possible keys
            let monitor_request = MonitorRequest {
                keys: monitor_keys,
                // Consistency is only used to verify "distinguished" search key
                consistency: None,
            };

            let monitor_response = MonitorResponse {
                tree_head: Some(chat_monitor_response.tree_head.clone()),
                proofs,
                inclusion: chat_monitor_response.inclusion,
            };

            let monitor_context = MonitorContext {
                last_tree_head: Some(&last_tree_head),
                last_distinguished_tree_head,
                data: monitoring_data_map,
            };

            let verified = self.inner.verify_monitor(
                &monitor_request,
                &monitor_response,
                monitor_context,
                now,
            )?;

            let LocalStateUpdate {
                tree_head,
                tree_root,
                mut monitoring_data,
            } = verified;

            let mut take_data = move |search_key: &[u8], err_message: &'static str| {
                monitoring_data
                    .remove(search_key)
                    .ok_or(Error::InvalidResponse(err_message.to_string()))
            };

            AccountData {
                aci: take_data(&aci.as_search_key(), "ACI monitoring data is missing")?,
                e164: e164
                    .map(|e164| {
                        take_data(&e164.as_search_key(), "E.164 monitoring data is missing")
                    })
                    .transpose()?,
                username_hash: username_hash
                    .map(|username_hash| {
                        take_data(
                            &username_hash.as_search_key(),
                            "username hash monitoring data is missing",
                        )
                    })
                    .transpose()?,
                last_tree_head: (tree_head, tree_root),
            }
        };

        Ok(updated_account_data)
    }
}

fn verify_single_search_response(
    kt: &KeyTransparency,
    search_key: Vec<u8>,
    response: CondensedTreeSearchResponse,
    monitoring_data: Option<MonitoringData>,
    full_tree_head: &FullTreeHead,
    last_tree_head: Option<&LastTreeHead>,
    last_distinguished_tree_head: Option<&LastTreeHead>,
    now: SystemTime,
) -> Result<VerifiedSearchResult> {
    let result = kt.verify_search(
        SlimSearchRequest::new(search_key),
        FullSearchResponse::new(response, full_tree_head),
        SearchContext {
            last_tree_head,
            last_distinguished_tree_head,
            data: monitoring_data.map(MonitoringData::from),
        },
        true,
        now,
    )?;
    Ok(result)
}

fn verify_chat_search_response(
    kt: &KeyTransparency,
    aci: &Aci,
    e164: Option<E164>,
    username_hash: Option<UsernameHash>,
    stored_account_data: Option<AccountData>,
    chat_search_response: TypedSearchResponse,
    last_distinguished_tree_head: Option<&LastTreeHead>,
    now: SystemTime,
) -> Result<MaybePartial<SearchResult>> {
    let TypedSearchResponse {
        full_tree_head,
        aci_search_response,
        e164_search_response,
        username_hash_search_response,
    } = chat_search_response;

    let (
        aci_monitoring_data,
        e164_monitoring_data,
        username_hash_monitoring_data,
        stored_last_tree_head,
    ) = match stored_account_data {
        None => (None, None, None, None),
        Some(acc) => {
            let AccountData {
                aci,
                e164,
                username_hash,
                last_tree_head,
            } = acc;
            (Some(aci), e164, username_hash, Some(last_tree_head))
        }
    };

    let aci_result = verify_single_search_response(
        kt,
        aci.as_search_key(),
        aci_search_response,
        aci_monitoring_data,
        &full_tree_head,
        stored_last_tree_head.as_ref(),
        last_distinguished_tree_head,
        now,
    )?;

    let e164_result = match_optional_fields(e164, e164_search_response, AccountDataField::E164)?
        .map(|non_partial| {
            non_partial
                .map(|(e164, e164_search_response)| {
                    verify_single_search_response(
                        kt,
                        e164.as_search_key(),
                        e164_search_response,
                        e164_monitoring_data,
                        &full_tree_head,
                        stored_last_tree_head.as_ref(),
                        last_distinguished_tree_head,
                        now,
                    )
                })
                .transpose()
        })
        .transpose()?;

    let username_hash_result = match_optional_fields(
        username_hash,
        username_hash_search_response,
        AccountDataField::UsernameHash,
    )?
    .map(|non_partial| {
        non_partial
            .map(|(username_hash, username_hash_response)| {
                verify_single_search_response(
                    kt,
                    username_hash.as_search_key(),
                    username_hash_response,
                    username_hash_monitoring_data,
                    &full_tree_head,
                    stored_last_tree_head.as_ref(),
                    last_distinguished_tree_head,
                    now,
                )
            })
            .transpose()
    })
    .transpose()?;

    let MaybePartial {
        inner: (e164_result, username_hash_result),
        missing_fields,
    } = e164_result.and_then(|e164| username_hash_result.map(|hash| (e164, hash)));

    if !aci_result.are_all_roots_equal([e164_result.as_ref(), username_hash_result.as_ref()]) {
        return Err(Error::InvalidResponse("mismatching tree roots".to_string()));
    }

    let identity_key = extract_value_as::<IdentityKey>(&aci_result)?;
    let aci_for_e164 = e164_result
        .as_ref()
        .map(extract_value_as::<Aci>)
        .transpose()?;
    let aci_for_username_hash = username_hash_result
        .as_ref()
        .map(extract_value_as::<Aci>)
        .transpose()?;

    // ACI response is guaranteed to be present, taking the last tree head from it.
    let LocalStateUpdate {
        tree_head,
        tree_root,
        monitoring_data: updated_aci_monitoring_data,
    } = aci_result.state_update;

    let last_tree_head = StoredTreeHead {
        tree_head: Some(tree_head),
        root: tree_root.into(),
    };

    let updated_account_data = StoredAccountData {
        aci: updated_aci_monitoring_data.map(StoredMonitoringData::from),
        e164: e164_result
            .and_then(|r| r.state_update.monitoring_data)
            .map(StoredMonitoringData::from),
        username_hash: username_hash_result
            .and_then(|r| r.state_update.monitoring_data)
            .map(StoredMonitoringData::from),
        last_tree_head: Some(last_tree_head),
    };

    let search_result = SearchResult {
        aci_identity_key: identity_key,
        aci_for_e164,
        aci_for_username_hash,
        timestamp: now,
        account_data: updated_account_data,
    };

    Ok(MaybePartial {
        inner: search_result,
        missing_fields,
    })
}

/// This function tries to match the optional value in request and response.
///
/// The rules of matching are:
/// - If neither `request_value` nor `response_value` is present, the result is
///   considered complete (in `MaybePartial` terms) and will require no further
///   handling. It is expected to not have a value in the response if it had
///   never been requested to start with.
/// - If both `request_value` and `response_value` are present, the result is
///   considered complete and ready for further verification.
/// - If `response_value` is present but `request_value` is not, there is
///   something wrong with the server implementation. We never requested the
///   field, but the response contains a corresponding value.
/// - If `request_value` is present but `response_value` isn't we consider the
///   response complete but not suitable for further processing and record a
///   missing field inside `MaybePartial`.
fn match_optional_fields<T, U>(
    request_value: Option<T>,
    response_value: Option<U>,
    field: AccountDataField,
) -> Result<MaybePartial<Option<(T, U)>>> {
    match (request_value, response_value) {
        (Some(a), Some(b)) => Ok(MaybePartial::new_complete(Some((a, b)))),
        (None, None) => Ok(MaybePartial::new_complete(None)),
        (None, Some(_)) => Err(Error::InvalidResponse(format!(
            "Unexpected field in the response: {}",
            &field
        ))),
        (Some(_), None) => Ok(MaybePartial::new(None, vec![field])),
    }
}

// Cannot be a method on VerifiedSearchResult due to use of SearchValue
fn extract_value_as<T>(result: &VerifiedSearchResult) -> Result<T>
where
    T: for<'a> TryFrom<SearchValue<'a>, Error = Error>,
{
    let val = SearchValue::try_from(result)?;
    val.try_into()
}

const SEARCH_KEY_PREFIX_ACI: &[u8] = b"a";
const SEARCH_KEY_PREFIX_E164: &[u8] = b"n";
const SEARCH_KEY_PREFIX_USERNAME_HASH: &[u8] = b"u";

/// Representation of an object as "search key" aligned with conversion
/// performed by the chat server.
///
/// Search keys from the Key Transparency server perspective are just arrays of
/// bytes, therefore in order to distinguish them and avoid (highly unlikely)
/// clashes Chat server adds unique prefixes to keys representing ACIs, E.164's,
/// and username hashes.
pub trait SearchKey {
    fn as_search_key(&self) -> Vec<u8>;
}

impl SearchKey for Aci {
    fn as_search_key(&self) -> Vec<u8> {
        [SEARCH_KEY_PREFIX_ACI, self.service_id_binary().as_slice()].concat()
    }
}

impl SearchKey for E164 {
    fn as_search_key(&self) -> Vec<u8> {
        [SEARCH_KEY_PREFIX_E164, self.to_string().as_bytes()].concat()
    }
}

/// Type-safe wrapper for a byte slice representing username hash.
#[derive(Clone)]
pub struct UsernameHash<'a>(Cow<'a, [u8]>);

impl AsRef<[u8]> for UsernameHash<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Debug for UsernameHash<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsernameHash")
            .field("hex", &hex::encode(self.0.as_ref()))
            .finish()
    }
}

impl<'a> UsernameHash<'a> {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Cow::Owned(bytes))
    }

    pub fn from_slice(bytes: &'a [u8]) -> Self {
        Self(Cow::Borrowed(bytes))
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0.into_owned()
    }
}

impl From<Vec<u8>> for UsernameHash<'_> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Cow::Owned(vec))
    }
}

impl From<Box<[u8]>> for UsernameHash<'_> {
    fn from(value: Box<[u8]>) -> Self {
        Self(Cow::Owned(value.into_vec()))
    }
}

impl SearchKey for UsernameHash<'_> {
    fn as_search_key(&self) -> Vec<u8> {
        [SEARCH_KEY_PREFIX_USERNAME_HASH, self.0.as_ref()].concat()
    }
}

/// String representation of a value to be sent in chat server JSON requests.
trait AsChatValue {
    fn as_chat_value(&self) -> String;
}

impl AsChatValue for Aci {
    fn as_chat_value(&self) -> String {
        self.service_id_string()
    }
}

impl AsChatValue for E164 {
    fn as_chat_value(&self) -> String {
        self.to_string()
    }
}

impl AsChatValue for UsernameHash<'_> {
    fn as_chat_value(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.as_ref())
    }
}

#[cfg(test)]
mod test_support {
    use futures_util::FutureExt as _;
    use libsignal_keytrans::{DeploymentMode, PublicConfig, VerifyingKey, VrfPublicKey};
    use libsignal_net_infra::route::DirectOrProxyRoute;

    use super::*;
    use crate::chat::ChatConnection;
    use crate::env;
    use crate::env::{
        KEYTRANS_AUDITOR_KEY_MATERIAL_STAGING, KEYTRANS_SIGNING_KEY_MATERIAL_STAGING,
        KEYTRANS_VRF_KEY_MATERIAL_STAGING,
    };

    pub(super) mod test_account {
        use std::borrow::Cow;

        use hex_literal::hex;
        use libsignal_core::curve::PublicKey;
        use libsignal_core::{Aci, E164};
        use nonzero_ext::nonzero;
        use uuid::Uuid;

        use super::UsernameHash;

        pub const ACI: Uuid = uuid::uuid!("90c979fd-eab4-4a08-b6da-69dedeab9b29");
        pub const ACI_IDENTITY_KEY_BYTES: &[u8] =
            &hex!("05d0e797ec91a4bce0e88959c419e96eb4fdabbb3dc688965584c966dc24195609");
        pub const USERNAME_HASH: &[u8] =
            &hex!("d237a4b83b463ca7da58d4a16bf6a3ba104506eb412b235eb603ea10f467c655");
        pub const PHONE_NUMBER: E164 = E164::new(nonzero!(18005550100u64));
        pub const UNIDENTIFIED_ACCESS_KEY: &[u8] = &hex!("fdc7951d1507268daf1834b74d23b76c");

        pub fn aci() -> Aci {
            Aci::from(ACI)
        }

        pub fn aci_identity_key() -> PublicKey {
            PublicKey::deserialize(ACI_IDENTITY_KEY_BYTES).expect("valid key bytes")
        }

        pub fn username_hash() -> UsernameHash<'static> {
            UsernameHash(Cow::Borrowed(USERNAME_HASH))
        }
    }

    pub(super) fn make_key_transparency() -> KeyTransparency {
        let signature_key = VerifyingKey::from_bytes(KEYTRANS_SIGNING_KEY_MATERIAL_STAGING)
            .expect("valid signature key material");
        let vrf_key = VrfPublicKey::try_from(*KEYTRANS_VRF_KEY_MATERIAL_STAGING)
            .expect("valid vrf key material");
        let auditor_key = VerifyingKey::from_bytes(KEYTRANS_AUDITOR_KEY_MATERIAL_STAGING)
            .expect("valid auditor key material");
        KeyTransparency {
            config: PublicConfig {
                mode: DeploymentMode::ThirdPartyAuditing(auditor_key),
                signature_key,
                vrf_key,
            },
        }
    }

    pub(super) fn make_kt(chat: &(dyn UnauthenticatedChat + Sync)) -> Kt<'_> {
        Kt {
            inner: make_key_transparency(),
            chat,
            config: Default::default(),
        }
    }

    /// Wrapper for [`ChatConnection`] known to be connected without
    /// authentication.
    pub(super) struct KtUnauthChatConnection(ChatConnection);

    impl UnauthenticatedChat for KtUnauthChatConnection {
        fn send_unauthenticated(
            &self,
            request: chat::Request,
            timeout: Duration,
        ) -> BoxFuture<'_, std::result::Result<chat::Response, chat::ChatServiceError>> {
            self.0.send(request, timeout).boxed()
        }
    }

    pub(super) async fn make_chat() -> KtUnauthChatConnection {
        use crate::chat::test_support::simple_chat_connection;
        let chat = simple_chat_connection(&env::STAGING, |route| {
            matches!(route.inner.inner, DirectOrProxyRoute::Direct(_))
        })
        .await
        .expect("can connect to chat");
        KtUnauthChatConnection(chat)
    }

    #[allow(dead_code)]
    // This function automates the collection of the test data.
    //
    // In particular, the constants that start with:
    // - DISTINGUISHED_TREE_
    // - STORED_ACCOUNT_DATA_
    //
    // In order to collect the test data:
    // - Uncomment the #[tokio::test] line
    // - Execute the test as `cargo test --package libsignal-net --all-features collect_test_data -- --nocapture`
    // - Follow the prompts
    // - Replace the "const" definitions in the code with the ones printed out by the test.
    // - Copy the "chat_search_response.dat" file to "rust/net/tests/data/" replacing the existing one.
    //
    //#[tokio::test]
    async fn collect_test_data() {
        fn prompt(text: &str) {
            println!("{} >", text);

            let mut input = String::new();

            std::io::stdin()
                .read_line(&mut input)
                .expect("can read_line from stdin");
        }

        let chat = make_chat().await;
        let kt = make_kt(&chat);

        prompt("Let's collect some data (press ENTER)");

        println!("Requesting distinguished tree...");
        let result = kt.distinguished(None).await.expect("can get distinguished");

        let distinguished_tree_size = result.tree_head.tree_size;
        println!("Distinguished tree");
        println!("Size: {}", &result.tree_head.tree_size);
        println!(
            "const DISTINGUISHED_TREE_{}_HEAD: &[u8] = &hex!(\"{}\");",
            distinguished_tree_size,
            &hex::encode(result.tree_head.encode_to_vec())
        );
        println!(
            "const DISTINGUISHED_TREE_{}_ROOT: &[u8] = &hex!(\"{}\");",
            distinguished_tree_size,
            &hex::encode(result.tree_root)
        );

        let distinguished_tree = (result.tree_head, result.tree_root);

        prompt("Now advance the tree (and press ENTER)");

        let aci = Aci::from(test_account::ACI);
        let aci_identity_key =
            PublicKey::deserialize(test_account::ACI_IDENTITY_KEY_BYTES).expect("valid key bytes");
        let e164 = (
            test_account::PHONE_NUMBER,
            test_account::UNIDENTIFIED_ACCESS_KEY.to_vec(),
        );
        let username_hash = UsernameHash(Cow::Borrowed(test_account::USERNAME_HASH));

        println!("Requesting account data...");

        let result = kt
            .search(
                &aci,
                &aci_identity_key,
                Some(e164.clone()),
                Some(username_hash.clone()),
                None,
                &distinguished_tree,
            )
            .await
            .expect("can perform search");

        let last_tree_size = result
            .inner
            .account_data
            .clone()
            .last_tree_head
            .unwrap()
            .tree_head
            .unwrap()
            .tree_size;

        assert_ne!(
            distinguished_tree_size, last_tree_size,
            "The tree did not advance!"
        );

        println!("Stored account data:");
        println!(
            "const STORED_ACCOUNT_DATA_{}: &[u8] = &hex!(\"{}\");",
            last_tree_size,
            &hex::encode(result.inner.account_data.encode_to_vec())
        );

        let account_data =
            AccountData::try_from(result.inner.account_data).expect("valid account data");

        prompt("Now advance the tree. Yes, again! (and press ENTER)");

        let raw_request = RawChatSearchRequest::new(
            &aci,
            &aci_identity_key,
            Some(&e164),
            Some(&username_hash),
            Some(account_data.last_tree_head.0.tree_size),
            distinguished_tree.0.tree_size,
        );
        let response = kt
            .send(raw_request.into())
            .await
            .expect("can send raw search request");

        let raw_response = RawChatSerializedResponse::try_from(response).expect("valid response");
        let response_bytes = BASE64_STANDARD_NO_PAD
            .decode(raw_response.serialized_response.as_bytes())
            .expect("valid base64");

        {
            let search_response = ChatSearchResponse::decode(response_bytes.as_ref())
                .map_err(|_| Error::InvalidResponse("bad protobuf".to_string()))
                .and_then(|r| TypedSearchResponse::from_untyped(true, true, r))
                .expect("valid search response");

            let tree_size = search_response.full_tree_head.tree_head.unwrap().tree_size;
            assert_ne!(last_tree_size, tree_size, "The tree did not advance!");
        }

        println!(
            "const CHAT_SEARCH_RESPONSE_VALID_AT: Duration = Duration::from_secs({});",
            SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs()
        );

        const PATH: &str = "/tmp/chat_search_response.dat";
        println!("Response written to '{PATH}'");
        std::fs::write(PATH, &response_bytes).unwrap()
    }
}

#[cfg(test)]
mod test {
    use std::cmp::Ordering;
    use std::sync::{Arc, Mutex};

    use assert_matches::assert_matches;
    use hex_literal::hex;
    use http::StatusCode;
    use libsignal_keytrans::TreeHead;
    use test_case::test_case;

    use super::test_support::{make_chat, make_key_transparency, make_kt, test_account};
    use super::*;

    // Distinguished tree parameters as of size 11526
    const DISTINGUISHED_TREE_19941_HEAD: &[u8] =
        &hex!("08e59b0110898a95cfd2321a4026d5499cad422621f01e4b3874b7bdda5e7d4a3f7b152ad34ac57a644f2efeb9458b527e5de5e44bb776d19f317206e6f4d02ddd3215038d66c426e531113b02");
    const DISTINGUISHED_TREE_19941_ROOT: &[u8] =
        &hex!("9f661d1beb7c567e1fbf281a54b2372f95dab2bb3c8d1389c2590103c785c092");

    const STORED_ACCOUNT_DATA_19996: &[u8] =
        &hex!("0a2b0a203901c94081c4e6321e92b3e434dcaf788f5326913e7bdcab47b4fd2ae7a6848a10231a0308ff7f2001122c0a2086052cc2a2689558e852d053c5ab411d8c3baef20171ec298e551574806ca95d1081011a0308ff7f20011a2c0a20bc1cfaae736c27c437b99175798933ee32caf07a5226840ec963a4e614916e9010dc011a0308ff7f200122710a4d089c9c0110ffdf95cfd2321a407ad5434982865677e3a31513aa78afaf3bebec2174aefd6331be83aa80dad9731eaeca611573e6592605e2014f2ee47f76eb804cf676c6ca7e1be0f907f4cc02122013846855087b9268e136e7920bc5e84dcbe470f6ee4e629ecba7f10f64caaf96");

    fn test_distinguished_tree() -> LastTreeHead {
        (
            TreeHead::decode(DISTINGUISHED_TREE_19941_HEAD).expect("valid TreeHead"),
            DISTINGUISHED_TREE_19941_ROOT
                .try_into()
                .expect("valid root size"),
        )
    }

    fn test_stored_account_data() -> StoredAccountData {
        StoredAccountData::decode(STORED_ACCOUNT_DATA_19996).expect("valid stored acc data")
    }

    fn test_account_data() -> AccountData {
        AccountData::try_from(test_stored_account_data()).expect("valid account data")
    }

    #[tokio::test]
    #[test_case(false, false; "ACI")]
    #[test_case(true, false; "ACI + E164")]
    #[test_case(false, true; "ACI + Username Hash")]
    #[test_case(true, true; "ACI + E164 + Username Hash")]
    async fn search_permutations_integration_test(use_e164: bool, use_username_hash: bool) {
        if std::env::var("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_err() {
            println!("SKIPPED: running integration tests is not enabled");
            return;
        }
        let chat = make_chat().await;
        let kt = make_kt(&chat);

        let aci = test_account::aci();
        let aci_identity_key = test_account::aci_identity_key();
        let e164 = (
            test_account::PHONE_NUMBER,
            test_account::UNIDENTIFIED_ACCESS_KEY.to_vec(),
        );
        let username_hash = test_account::username_hash();

        let acc_data = test_account_data();

        let result = kt
            .search(
                &aci,
                &aci_identity_key,
                use_e164.then_some(e164),
                use_username_hash.then_some(username_hash),
                Some(acc_data),
                &test_distinguished_tree(),
            )
            .await
            .expect("can perform search");

        assert_eq!(
            &hex::encode(test_account::ACI_IDENTITY_KEY_BYTES),
            &hex::encode(result.inner.aci_identity_key.serialize())
        );
    }

    #[tokio::test]
    #[test_case(false; "unknown_distinguished")]
    #[test_case(true; "known_distinguished")]
    async fn distinguished_integration_test(have_last_distinguished: bool) {
        if std::env::var("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_err() {
            println!("SKIPPED: running integration tests is not enabled");
            return;
        }

        let chat = make_chat().await;
        let kt = make_kt(&chat);

        let result = kt
            .distinguished(have_last_distinguished.then_some(test_distinguished_tree()))
            .await;

        assert_matches!(result, Ok( LocalStateUpdate {tree_head, ..}) => assert_ne!(tree_head.tree_size, 0));
    }

    #[tokio::test]
    #[test_case(false, false; "ACI")]
    #[test_case(true, false; "ACI + E164")]
    #[test_case(false, true; "ACI + Username Hash")]
    #[test_case(true, true; "ACI + E164 + Username Hash")]
    async fn monitor_permutations_integration_test(use_e164: bool, use_username_hash: bool) {
        if std::env::var("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_err() {
            println!("SKIPPED: running integration tests is not enabled");
            return;
        }
        let chat = make_chat().await;
        let kt = make_kt(&chat);

        let aci = test_account::aci();
        let e164 = test_account::PHONE_NUMBER;
        let username_hash = test_account::username_hash();

        let account_data = {
            let mut data = test_account_data();
            if !use_e164 {
                data.e164 = None;
            }
            if !use_username_hash {
                data.username_hash = None;
            }
            data
        };

        let updated_account_data = kt
            .monitor(
                &aci,
                use_e164.then_some(e164),
                use_username_hash.then_some(username_hash),
                account_data.clone(),
                &test_distinguished_tree(),
            )
            .await
            .expect("can monitor");

        match Ord::cmp(
            &updated_account_data.last_tree_head.0.tree_size,
            &account_data.last_tree_head.0.tree_size,
        ) {
            Ordering::Less => panic!("The tree is shrinking"),
            Ordering::Equal => assert_eq!(&updated_account_data, &account_data),
            Ordering::Greater => {
                // verify that the initial position of the ACI in the tree has not changed, at least
                assert_eq!(&updated_account_data.aci.pos, &account_data.aci.pos)
            }
        }
    }

    const CHAT_SEARCH_RESPONSE: &[u8] = include_bytes!("../tests/data/chat_search_response.dat");
    const CHAT_SEARCH_RESPONSE_VALID_AT: Duration = Duration::from_secs(1740164663);

    fn test_search_response() -> TypedSearchResponse {
        let chat_search_response =
            libsignal_keytrans::ChatSearchResponse::decode(CHAT_SEARCH_RESPONSE)
                .expect("valid response");
        TypedSearchResponse::from_untyped(true, true, chat_search_response)
            .expect("valid typed search response")
    }

    #[test_case(&[AccountDataField::E164]; "e164")]
    #[test_case(&[AccountDataField::UsernameHash]; "username_hash")]
    #[test_case(&[AccountDataField::E164, AccountDataField::UsernameHash]; "e164 + username_hash")]
    fn search_returns_data_not_requested(skip: &[AccountDataField]) {
        let valid_at = SystemTime::UNIX_EPOCH + CHAT_SEARCH_RESPONSE_VALID_AT;

        let aci = test_account::aci();
        let mut e164 = Some(test_account::PHONE_NUMBER);
        let mut username_hash = Some(test_account::username_hash());

        for what in skip {
            match what {
                AccountDataField::E164 => {
                    e164 = None;
                }
                AccountDataField::UsernameHash => {
                    username_hash = None;
                }
            }
        }

        let account_data = test_account_data();

        let kt_impl = make_key_transparency();

        let result = verify_chat_search_response(
            &kt_impl,
            &aci,
            e164,
            username_hash,
            Some(account_data),
            test_search_response(),
            Some(&test_distinguished_tree()),
            valid_at,
        );

        assert_matches!(result, Err(Error::InvalidResponse(_)))
    }

    #[test_case(&[AccountDataField::E164]; "e164")]
    #[test_case(&[AccountDataField::UsernameHash]; "username_hash")]
    #[test_case(&[AccountDataField::E164, AccountDataField::UsernameHash]; "e164 + username_hash")]
    fn search_does_not_return_requested_data(skip: &[AccountDataField]) {
        let valid_at = SystemTime::UNIX_EPOCH + CHAT_SEARCH_RESPONSE_VALID_AT;

        let aci = test_account::aci();
        let e164 = test_account::PHONE_NUMBER;
        let username_hash = test_account::username_hash();

        let kt_impl = make_key_transparency();
        let mut search_response = test_search_response();
        for what in skip {
            match what {
                AccountDataField::E164 => {
                    search_response.e164_search_response = None;
                }
                AccountDataField::UsernameHash => {
                    search_response.username_hash_search_response = None;
                }
            }
        }

        let account_data = test_account_data();

        let result = verify_chat_search_response(
            &kt_impl,
            &aci,
            Some(e164),
            Some(username_hash),
            Some(account_data),
            search_response,
            Some(&test_distinguished_tree()),
            valid_at,
        );

        assert_matches!(result, Ok(MaybePartial {missing_fields, ..}) =>
            assert_eq!(skip.to_vec(), missing_fields.into_iter().collect::<Vec<_>>())
        );
    }

    struct TestKt {
        monitor: Arc<Mutex<Option<Result<AccountData>>>>,
        search: Arc<Mutex<Option<Result<MaybePartial<SearchResult>>>>>,
    }

    impl TestKt {
        fn for_monitor(monitor: Result<AccountData>) -> Self {
            Self {
                monitor: Arc::new(Mutex::new(Some(monitor))),
                search: Arc::new(Mutex::new(None)),
            }
        }

        fn new(monitor: Result<AccountData>, search: Result<MaybePartial<SearchResult>>) -> Self {
            Self {
                monitor: Arc::new(Mutex::new(Some(monitor))),
                search: Arc::new(Mutex::new(Some(search))),
            }
        }
    }

    impl KtApi for TestKt {
        fn search(
            &self,
            _aci: &Aci,
            _aci_identity_key: &PublicKey,
            _e164: Option<(E164, Vec<u8>)>,
            _username_hash: Option<UsernameHash<'_>>,
            _stored_account_data: Option<AccountData>,
            _distinguished_tree_head: &LastTreeHead,
        ) -> impl Future<Output = Result<MaybePartial<SearchResult>>> + Send {
            let result = self
                .search
                .lock()
                .unwrap()
                .take()
                .expect("unexpected call to search");
            async move { result }
        }

        async fn distinguished(&self, _: Option<LastTreeHead>) -> Result<SearchStateUpdate> {
            // not used in the tests
            unreachable!()
        }

        fn monitor(
            &self,
            _aci: &Aci,
            _e164: Option<E164>,
            _username_hash: Option<UsernameHash<'_>>,
            _account_data: AccountData,
            _last_distinguished_tree_head: &LastTreeHead,
        ) -> impl Future<Output = Result<AccountData>> + Send {
            let result = self
                .monitor
                .lock()
                .unwrap()
                .take()
                .expect("unexpected call to monitor");
            async move { result }
        }
    }

    #[tokio::test]
    async fn monitor_and_search_monitor_error_is_returned() {
        let kt = TestKt::for_monitor(Err(Error::RequestFailed(StatusCode::EXPECTATION_FAILED)));
        let result = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            test_account_data(),
            &test_distinguished_tree(),
        )
        .await;
        assert_matches!(
            result,
            Err(Error::RequestFailed(StatusCode::EXPECTATION_FAILED))
        );
    }

    #[tokio::test]
    async fn monitor_and_search_no_search_needed() {
        let monitor_result = test_account_data();
        // TestKt constructed like this will panic if search is invoked
        let kt = TestKt::for_monitor(Ok(monitor_result.clone()));

        let actual = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            test_account_data(),
            &test_distinguished_tree(),
        )
        .await
        .expect("monitor should succeed");
        assert_eq!(actual, monitor_result.into());
    }

    enum BumpVersionFor {
        E164,
        UsernameHash,
    }

    #[tokio::test]
    #[test_case(BumpVersionFor::E164; "newer E.164")]
    #[test_case(BumpVersionFor::UsernameHash; "newer username hash")]
    async fn monitor_and_search_e164_changed(bump: BumpVersionFor) {
        let mut monitor_result = test_account_data();
        let subject = match bump {
            BumpVersionFor::E164 => monitor_result.e164.as_mut(),
            BumpVersionFor::UsernameHash => monitor_result.username_hash.as_mut(),
        }
        .unwrap();
        // inserting a newer version of the subject
        let max_version = subject.greatest_version();
        subject.ptrs.insert(u64::MAX, max_version + 1);

        let kt = TestKt::new(
            Ok(monitor_result.clone()),
            Err(Error::RequestFailed(StatusCode::EXPECTATION_FAILED)),
        );

        let result = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            test_account_data(),
            &test_distinguished_tree(),
        )
        .await;

        // monitor invocation should have succeeded, and search
        // should have been invoked returning our custom error
        assert_matches!(
            result,
            Err(Error::RequestFailed(StatusCode::EXPECTATION_FAILED))
        );
    }

    #[tokio::test]
    async fn monitor_and_search_search_success() {
        let mut monitor_result = test_account_data();

        // inserting a newer version of the username hash
        let max_version = monitor_result
            .username_hash
            .as_ref()
            .unwrap()
            .greatest_version();
        monitor_result
            .username_hash
            .as_mut()
            .unwrap()
            .ptrs
            .insert(u64::MAX, max_version + 1);

        let mut search_result_account_data = test_account_data();
        // make some unique change to validate this is the one that gets returned
        search_result_account_data.last_tree_head.1 = [42; 32];

        let search_result = SearchResult {
            aci_identity_key: IdentityKey::new(test_account::aci_identity_key()),
            aci_for_e164: None,
            aci_for_username_hash: None,
            timestamp: SystemTime::now(),
            account_data: search_result_account_data.clone().into(),
        };

        let kt = TestKt::new(Ok(monitor_result.clone()), Ok(search_result.into()));

        let updated_account_data = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            test_account_data(),
            &test_distinguished_tree(),
        )
        .await
        .expect("both monitor and search should have succeeded");

        assert_eq!(
            search_result_account_data,
            updated_account_data.into_inner()
        );
    }

    #[tokio::test]
    async fn search_for_deleted_account() {
        if std::env::var("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_err() {
            println!("SKIPPED: running integration tests is not enabled");
            return;
        }

        let chat = make_chat().await;
        let kt = make_kt(&chat);

        // This ACI belongs to account 18005550102
        // The correct ACI identity key is `hex!("05b65b151f64638b0ea549efb2989e9d726ad2b87fbca1328d872ed6f8fbb7a333")`
        let aci = Aci::from(uuid::uuid!("4129e9d6-dbb3-4f44-97b4-2dd29f0e2681"));

        let wrong_identity_key = test_account::aci_identity_key();

        let result = kt
            .search(
                &aci,
                &wrong_identity_key,
                None,
                None,
                None,
                &test_distinguished_tree(),
            )
            .await;
        assert_matches!(result, Err(Error::RequestFailed(StatusCode::FORBIDDEN)));
    }

    #[tokio::test]
    async fn search_for_account_that_isnt() {
        if std::env::var("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_err() {
            println!("SKIPPED: running integration tests is not enabled");
            return;
        }

        let chat = make_chat().await;
        let kt = make_kt(&chat);

        let aci = Aci::from(uuid::uuid!("00000000-0000-0000-0000-000000000000"));

        let wrong_identity_key = test_account::aci_identity_key();

        let result = kt
            .search(
                &aci,
                &wrong_identity_key,
                None,
                None,
                None,
                &test_distinguished_tree(),
            )
            .await;
        assert_matches!(result, Err(Error::RequestFailed(StatusCode::NOT_FOUND)));
    }
}
