//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::time::SystemTime;

use async_trait::async_trait;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{
    AccountData, ChatDistinguishedResponse, ChatMonitorResponse, ChatSearchResponse,
    CondensedTreeSearchResponse, FullSearchResponse, FullTreeHead, KeyTransparency, LastTreeHead,
    LocalStateUpdate, MonitorContext, MonitorKey, MonitorProof, MonitorRequest, MonitorResponse,
    MonitoringData, SearchContext, SearchStateUpdate, SlimSearchRequest, VerifiedSearchResult,
    Versioned,
};
use libsignal_net::env::KeyTransConfig;
use libsignal_protocol::PublicKey;

use super::RequestError;

const SEARCH_KEY_PREFIX_ACI: &[u8] = b"a";
const SEARCH_KEY_PREFIX_E164: &[u8] = b"n";
const SEARCH_KEY_PREFIX_USERNAME_HASH: &[u8] = b"u";

const MAXIMUM_ALLOWED_VERSION_DELTA: u32 = 10;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(Clone))]
#[ignore_extra_doc_attributes]
pub enum Error {
    /// Verification failed: {0}
    VerificationFailed(#[from] libsignal_keytrans::Error),
    /// Invalid response: {0}
    InvalidResponse(String),
    /// Invalid request: {0}
    InvalidRequest(&'static str),
}

#[async_trait]
pub trait LowLevelChatApi {
    async fn search(
        &self,
        aci: Versioned<&Aci>,
        aci_identity_key: &PublicKey,
        e164: Option<Versioned<&(E164, Vec<u8>)>>,
        username_hash: Option<Versioned<&UsernameHash<'_>>>,
        stored_account_data: Option<&AccountData>,
        distinguished_tree_head: &LastTreeHead,
    ) -> Result<Vec<u8>, RequestError<Error>>; // Expected to be a SearchResponse proto

    async fn distinguished(
        &self,
        last_distinguished: Option<&LastTreeHead>,
    ) -> Result<Vec<u8>, RequestError<Error>>; // Expected to be a ChatDistinguishedResponse proto

    async fn monitor(
        &self,
        aci: &Aci,
        e164: Option<&E164>,
        username_hash: Option<&UsernameHash<'_>>,
        account_data: &AccountData,
        last_distinguished_tree_head: &LastTreeHead,
    ) -> Result<Vec<u8>, RequestError<Error>>; // Expected to be a ChatMonitorResponse proto
}

// Differs from [`ChatSearchResponse`] by establishing proper optionality of fields.
pub(crate) struct TypedSearchResponse {
    pub(crate) full_tree_head: FullTreeHead,
    pub(crate) aci_search_response: CondensedTreeSearchResponse,
    pub(crate) e164_search_response: Option<CondensedTreeSearchResponse>,
    pub(crate) username_hash_search_response: Option<CondensedTreeSearchResponse>,
}

impl TypedSearchResponse {
    pub(crate) fn from_untyped(
        require_e164: bool,
        require_username_hash: bool,
        response: ChatSearchResponse,
    ) -> Result<Self, Error> {
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
    ) -> Result<Self, Error> {
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

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> MaybePartial<U> {
        MaybePartial {
            inner: f(self.inner),
            missing_fields: self.missing_fields,
        }
    }

    pub fn and_then<U>(self, f: impl FnOnce(T) -> MaybePartial<U>) -> MaybePartial<U> {
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

    pub fn into_result(self) -> Result<T, BTreeSet<AccountDataField>> {
        let Self {
            inner,
            missing_fields,
        } = self;
        if missing_fields.is_empty() {
            Ok(inner)
        } else {
            Err(missing_fields)
        }
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

#[derive(Clone)]
pub struct KeyTransparencyClient<'a> {
    pub inner: KeyTransparency,
    pub chat: &'a (dyn LowLevelChatApi + Sync),
}

pub trait UnauthenticatedChatApi {
    fn search(
        &self,
        aci: Versioned<&Aci>,
        aci_identity_key: &PublicKey,
        e164: Option<Versioned<(E164, Vec<u8>)>>,
        username_hash: Option<Versioned<UsernameHash<'_>>>,
        stored_account_data: Option<AccountData>,
        distinguished_tree_head: &LastTreeHead,
    ) -> impl Future<Output = Result<MaybePartial<AccountData>, RequestError<Error>>> + Send;

    fn distinguished(
        &self,
        last_distinguished: Option<LastTreeHead>,
    ) -> impl Future<Output = Result<SearchStateUpdate, RequestError<Error>>> + Send;

    fn monitor(
        &self,
        aci: &Aci,
        e164: Option<E164>,
        username_hash: Option<UsernameHash<'_>>,
        account_data: AccountData,
        last_distinguished_tree_head: &LastTreeHead,
    ) -> impl Future<Output = Result<AccountData, RequestError<Error>>> + Send;
}

#[derive(Eq, Debug, PartialEq, Clone, Copy)]
pub enum MonitorMode {
    MonitorSelf,
    MonitorOther,
}

#[derive(Debug, Clone, PartialEq)]
struct SearchVersions {
    aci: Option<u32>,
    e164: Option<u32>,
    username_hash: Option<u32>,
}

impl SearchVersions {
    fn from_account_data(account_data: &AccountData) -> Self {
        let AccountData {
            aci,
            e164,
            username_hash,
            ..
        } = account_data;
        Self {
            aci: Some(aci.greatest_version()),
            e164: e164.as_ref().map(|x| x.greatest_version()),
            username_hash: username_hash.as_ref().map(|x| x.greatest_version()),
        }
    }

    fn subtract(&self, other: &Self) -> Self {
        fn opt_sub<T>(lhs: &T, rhs: &T, f: impl Fn(&T) -> Option<u32>) -> Option<u32> {
            Some(f(lhs)? - f(rhs)?)
        }
        Self {
            aci: opt_sub(self, other, |x| x.aci),
            e164: opt_sub(self, other, |x| x.e164),
            username_hash: opt_sub(self, other, |x| x.username_hash),
        }
    }

    fn maximum_version(&self) -> Option<u32> {
        [self.aci, self.e164, self.username_hash]
            .into_iter()
            .flatten()
            .max()
    }
}

pub async fn monitor_and_search(
    kt: &impl UnauthenticatedChatApi,
    aci: &Aci,
    aci_identity_key: &PublicKey,
    e164: Option<(E164, Vec<u8>)>,
    username_hash: Option<UsernameHash<'_>>,
    stored_account_data: AccountData,
    distinguished_tree_head: &LastTreeHead,
    mode: MonitorMode,
) -> Result<MaybePartial<AccountData>, RequestError<Error>> {
    let updated_account_data = kt
        .monitor(
            aci,
            e164.as_ref().map(|(e164, _)| *e164),
            username_hash.clone(),
            stored_account_data.clone(),
            distinguished_tree_head,
        )
        .await?;

    let stored_versions = SearchVersions::from_account_data(&stored_account_data);
    let updated_versions = SearchVersions::from_account_data(&updated_account_data);

    // Call to `monitor` guarantees that the optionality of E.164 and username hash data
    // will match between `stored_account_data` and `updated_account_data`. Meaning, they will
    // either both be Some() or both None.

    let final_account_data = match mode {
        MonitorMode::MonitorSelf => {
            // In case of self-monitoring, detecting a version change requires a fall
            // back to search-with-version for all intermediate versions of all keys.
            // It is important to only bump version of one search key at a time (aci,
            // e164, or username_hash), though, and leave others at "baseline" level.
            // The baseline is provided by search key's greatest known version from
            // stored_account_data.

            // SearchParameters that correspond to the stored_account_data, which is
            // considered to be valid.
            // Unwrapping stored versions is safe because monitor call above checks
            // the "nullability mismatch" already.
            let baseline_search_params = SearchParameters {
                aci: Versioned::new(
                    aci,
                    stored_versions.aci.expect("ACI version must be present"),
                ),
                aci_identity_key,
                e164: e164.as_ref().map(|e164| {
                    Versioned::new(e164, stored_versions.e164.expect("checked earlier"))
                }),
                username_hash: username_hash.as_ref().map(|hash| {
                    Versioned::new(
                        hash,
                        stored_versions.username_hash.expect("checked earlier"),
                    )
                }),
                stored_account_data: stored_account_data.clone(),
                distinguished_tree_head,
            };

            let version_delta = updated_versions.subtract(&stored_versions);

            if version_delta
                .maximum_version()
                .is_some_and(|max_version| max_version > MAXIMUM_ALLOWED_VERSION_DELTA)
            {
                return Err(RequestError::Other(Error::VerificationFailed(
                    libsignal_keytrans::Error::BadData("version changed by too much".to_string()),
                )));
            }

            let all_search_params = {
                let mut result = Vec::new();

                if let Some(delta) = version_delta.aci {
                    let baseline = stored_versions.aci.expect("must be present");
                    for increment in 1..=delta {
                        let mut params = baseline_search_params.clone();
                        params.aci.version = Some(baseline + increment);
                        // Don't search for other keys as an optimization
                        params.e164 = None;
                        params.username_hash = None;
                        result.push(params);
                    }
                }

                if let Some(delta) = version_delta.e164 {
                    let baseline = stored_versions.e164.expect("checked by monitor call");
                    for increment in 1..=delta {
                        let mut params = baseline_search_params.clone();
                        params
                            .e164
                            .as_mut()
                            .expect("checked by monitor call")
                            .version = Some(baseline + increment);
                        // Don't search for other keys as an optimization
                        params.username_hash = None;
                        result.push(params);
                    }
                }

                if let Some(delta) = version_delta.username_hash {
                    let baseline = stored_versions
                        .username_hash
                        .expect("checked by monitor call");
                    for increment in 1..=delta {
                        let mut params = baseline_search_params.clone();
                        params
                            .username_hash
                            .as_mut()
                            .expect("checked by monitor call")
                            .version = Some(baseline + increment);
                        // Don't search for other keys as an optimization
                        params.e164 = None;
                        result.push(params);
                    }
                }
                result
            };

            // Running the tasks sequentially instead of try_join_all to let
            // other networking tasks be scheduled to use our single connection.
            for params in all_search_params {
                search_with_params(kt, params).await?;
            }
            // If all the version specific searches succeed it is OK to accept the
            // account data monitor returned.
            updated_account_data.into()
        }
        MonitorMode::MonitorOther if updated_versions != stored_versions => {
            kt.search(
                Versioned::from(aci),
                aci_identity_key,
                e164.map(Versioned::from),
                username_hash.map(Versioned::from),
                Some(stored_account_data),
                distinguished_tree_head,
            )
            .await?
        }
        MonitorMode::MonitorOther => updated_account_data.into(),
    };
    Ok(final_account_data)
}

#[derive(Clone)]
struct SearchParameters<'a> {
    aci: Versioned<&'a Aci>,
    aci_identity_key: &'a PublicKey,
    e164: Option<Versioned<&'a (E164, Vec<u8>)>>,
    username_hash: Option<Versioned<&'a UsernameHash<'a>>>,
    stored_account_data: AccountData,
    distinguished_tree_head: &'a LastTreeHead,
}

async fn search_with_params(
    kt: &impl UnauthenticatedChatApi,
    params: SearchParameters<'_>,
) -> Result<MaybePartial<AccountData>, RequestError<Error>> {
    let SearchParameters {
        aci,
        aci_identity_key,
        e164,
        username_hash,
        stored_account_data,
        distinguished_tree_head,
    } = params;
    kt.search(
        aci,
        aci_identity_key,
        e164.map(|x| x.cloned()),
        username_hash.map(|x| x.cloned()),
        Some(stored_account_data),
        distinguished_tree_head,
    )
    .await
}

impl<'a> KeyTransparencyClient<'a> {
    pub fn new(chat: &'a (dyn LowLevelChatApi + Sync), kt_config: KeyTransConfig) -> Self {
        Self {
            inner: KeyTransparency {
                config: kt_config.into(),
            },
            chat,
        }
    }
}

impl UnauthenticatedChatApi for KeyTransparencyClient<'_> {
    async fn search(
        &self,
        aci: Versioned<&Aci>,
        aci_identity_key: &PublicKey,
        e164: Option<Versioned<(E164, Vec<u8>)>>,
        username_hash: Option<Versioned<UsernameHash<'_>>>,
        stored_account_data: Option<AccountData>,
        distinguished_tree_head: &LastTreeHead,
    ) -> Result<MaybePartial<AccountData>, RequestError<Error>> {
        let chat_search_response = self
            .chat
            .search(
                aci.clone(),
                aci_identity_key,
                e164.as_ref().map(|x| x.as_ref()),
                username_hash.as_ref().map(|x| x.as_ref()),
                stored_account_data.as_ref(),
                distinguished_tree_head,
            )
            .await
            .and_then(|proto_bytes| {
                prost::Message::decode(&proto_bytes[..]).map_err(|_| {
                    RequestError::Other(Error::InvalidResponse(
                        "invalid search response protobuf encoding".to_string(),
                    ))
                })
            })
            .and_then(|r| {
                TypedSearchResponse::from_untyped(e164.is_some(), username_hash.is_some(), r)
                    .map_err(RequestError::Other)
            })?;

        let now = SystemTime::now();

        verify_chat_search_response(
            &self.inner,
            aci,
            e164.map(|x| x.map(|(e164, _)| e164)),
            username_hash,
            stored_account_data,
            chat_search_response,
            Some(distinguished_tree_head),
            now,
        )
        .map_err(RequestError::Other)
    }

    async fn distinguished(
        &self,
        last_distinguished: Option<LastTreeHead>,
    ) -> Result<SearchStateUpdate, RequestError<Error>> {
        let ChatDistinguishedResponse {
            tree_head,
            distinguished,
        } = self
            .chat
            .distinguished(last_distinguished.as_ref())
            .await
            .and_then(|proto_bytes| {
                prost::Message::decode(&proto_bytes[..]).map_err(|_| {
                    RequestError::Other(Error::InvalidResponse(
                        "invalid distinguished response protobuf encoding".to_string(),
                    ))
                })
            })?;

        let tree_head = tree_head.ok_or_else(|| {
            RequestError::Other(Error::InvalidResponse(
                "tree head must be present".to_string(),
            ))
        })?;
        let condensed_response = distinguished.ok_or_else(|| {
            RequestError::Other(Error::InvalidResponse(
                "search response must be present".to_string(),
            ))
        })?;
        let search_response = FullSearchResponse::new(condensed_response, &tree_head);

        let slim_search_request = SlimSearchRequest::new(b"distinguished".to_vec());

        let verified_result = self
            .inner
            .verify_search(
                slim_search_request,
                search_response,
                SearchContext {
                    last_tree_head: None,
                    last_distinguished_tree_head: last_distinguished.as_ref(),
                    data: None,
                },
                false,
                SystemTime::now(),
            )
            .map_err(|e| RequestError::Other(e.into()))?;
        Ok(verified_result.state_update)
    }

    async fn monitor(
        &self,
        aci: &Aci,
        e164: Option<E164>,
        username_hash: Option<UsernameHash<'_>>,
        account_data: AccountData,
        last_distinguished_tree_head: &LastTreeHead,
    ) -> Result<AccountData, RequestError<Error>> {
        let chat_monitor_response = self
            .chat
            .monitor(
                aci,
                e164.as_ref(),
                username_hash.as_ref(),
                &account_data,
                last_distinguished_tree_head,
            )
            .await
            .and_then(|proto_bytes| {
                prost::Message::decode(&proto_bytes[..]).map_err(|_| {
                    RequestError::Other(Error::InvalidResponse(
                        "invalid monitor response protobuf encoding".to_string(),
                    ))
                })
            })
            .and_then(|r| {
                TypedMonitorResponse::from_untyped(e164.is_some(), username_hash.is_some(), r)
                    .map_err(RequestError::Other)
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
                let monitoring_data = e164_monitoring_data.ok_or(RequestError::Other(
                    Error::InvalidRequest("missing E.164 monitoring data"),
                ))?;
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
                let monitoring_data = username_hash_monitoring_data.ok_or(RequestError::Other(
                    Error::InvalidRequest("missing username hash monitoring data"),
                ))?;
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

            let verified = self
                .inner
                .verify_monitor(&monitor_request, &monitor_response, monitor_context, now)
                .map_err(|e| RequestError::Other(e.into()))?;

            let LocalStateUpdate {
                tree_head,
                tree_root,
                mut monitoring_data,
            } = verified;

            let mut take_data = move |search_key: &[u8], err_message: &'static str| {
                monitoring_data.remove(search_key).ok_or_else(|| {
                    RequestError::Other(Error::InvalidResponse(err_message.to_string()))
                })
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
    search_key: Versioned<Vec<u8>>,
    response: CondensedTreeSearchResponse,
    monitoring_data: Option<MonitoringData>,
    full_tree_head: &FullTreeHead,
    last_tree_head: Option<&LastTreeHead>,
    last_distinguished_tree_head: Option<&LastTreeHead>,
    now: SystemTime,
) -> Result<VerifiedSearchResult, Error> {
    let result = kt.verify_search(
        SlimSearchRequest {
            search_key: search_key.item,
            version: search_key.version,
        },
        FullSearchResponse::new(response, full_tree_head),
        SearchContext {
            last_tree_head,
            last_distinguished_tree_head,
            data: monitoring_data,
        },
        true,
        now,
    )?;
    Ok(result)
}

fn verify_chat_search_response(
    kt: &KeyTransparency,
    aci: Versioned<&Aci>,
    e164: Option<Versioned<E164>>,
    username_hash: Option<Versioned<UsernameHash>>,
    stored_account_data: Option<AccountData>,
    chat_search_response: TypedSearchResponse,
    last_distinguished_tree_head: Option<&LastTreeHead>,
    now: SystemTime,
) -> Result<MaybePartial<AccountData>, Error> {
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
        aci.map(|x| x.as_search_key()),
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
                        e164.map(|x| x.as_search_key()),
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
                    username_hash.map(|x| x.as_search_key()),
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

    // ACI response is guaranteed to be present, taking the last tree head from it.
    let LocalStateUpdate {
        tree_head,
        tree_root,
        monitoring_data: updated_aci_monitoring_data,
    } = aci_result.state_update;

    let updated_account_data = AccountData {
        aci: updated_aci_monitoring_data
            .ok_or_else(|| Error::InvalidResponse("ACI data is missing".to_string()))?,
        e164: e164_result.and_then(|r| r.state_update.monitoring_data),
        username_hash: username_hash_result.and_then(|r| r.state_update.monitoring_data),
        last_tree_head: (tree_head, tree_root),
    };

    Ok(MaybePartial {
        inner: updated_account_data,
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
) -> Result<MaybePartial<Option<(T, U)>>, Error> {
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

#[cfg(test)]
pub(crate) mod test_support {
    use std::time::Duration;

    use const_str::hex;
    use libsignal_keytrans::{StoredAccountData, TreeHead};
    use libsignal_net::env;
    use prost::Message as _;

    use super::*;

    pub const KEYTRANS_CONFIG_STAGING: env::KeyTransConfig = env::STAGING.keytrans_config;

    pub(crate) mod test_account {
        use std::borrow::Cow;

        use const_str::hex;
        use libsignal_core::curve::PublicKey;
        use libsignal_core::{Aci, E164};
        use nonzero_ext::nonzero;
        use uuid::Uuid;

        use super::UsernameHash;

        pub const ACI: Uuid = uuid::uuid!("90c979fd-eab4-4a08-b6da-69dedeab9b29");
        pub const ACI_IDENTITY_KEY_BYTES: &[u8] =
            &hex!("05cdcbb178067f0ddfd258bb21d006e0aa9c7ab132d9fb5e8b027de07d947f9d0c");
        pub const USERNAME_HASH: &[u8] =
            &hex!("dc711808c2cf66d5e6a33ce41f27d69d942d2e1ff4db22d39b42d2eff8d09746");
        pub const PHONE_NUMBER: E164 = E164::new(nonzero!(18005550100u64));
        pub const UNIDENTIFIED_ACCESS_KEY: &[u8] = &hex!("108d84b71be307bdf101e380a1d7f2a2");

        pub fn aci() -> Aci {
            Aci::from(ACI)
        }

        pub fn aci_identity_key() -> PublicKey {
            PublicKey::deserialize(ACI_IDENTITY_KEY_BYTES).expect("valid key bytes")
        }

        pub fn username_hash() -> UsernameHash<'static> {
            UsernameHash(Cow::Borrowed(USERNAME_HASH))
        }

        // To be used for search function
        pub fn e164_pair() -> (E164, Vec<u8>) {
            (PHONE_NUMBER, UNIDENTIFIED_ACCESS_KEY.to_vec())
        }
    }

    // Try connect/send operations to the real server this many times before failing
    pub const NETWORK_RETRY_COUNT: usize = 3;

    pub async fn retry_n<R, F, P, Fut>(n: usize, mut make_fut: F, mut should_retry: P) -> R
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = R>,
        P: FnMut(&R) -> bool,
    {
        let mut result = make_fut().await;
        for _ in 1..n {
            if !should_retry(&result) {
                break;
            }
            result = make_fut().await;
        }
        result
    }

    pub fn should_retry<T>(res: &Result<T, RequestError<Error>>) -> bool {
        matches!(res, Err(RequestError::Disconnected(_)))
    }

    pub fn make_kt(chat: &(dyn LowLevelChatApi + Sync)) -> KeyTransparencyClient<'_> {
        KeyTransparencyClient::new(chat, KEYTRANS_CONFIG_STAGING)
    }

    pub const CHAT_SEARCH_RESPONSE: &[u8] =
        include_bytes!("../../../tests/data/chat_search_response.dat");
    pub const CHAT_SEARCH_RESPONSE_VALID_AT: Duration =
        include!("../../../tests/data/chat_response_valid_at.in");

    const DISTINGUISHED_TREE_2646749_HEAD: &[u8] = &hex!(
        "08ddc5a101109ac8fdc0a2331a640a20093ee42d95502b3e81f4e604179c82c149fffb96167642b9eb81b03d6e2dd63612405e7d690bca490bf2ac11afa44192f6990a94d4c06734794e238c71e1686977b4a9d49db286e72bf6e81b3b8a7c65b818574943a0c8d485ed4be9a7b886dea1071a640a20bd1e26a0fbdbfa923486ccc9296f4227db490b4add29f5507775171ea0fb7a4e1240ca0e265ba8f7ef29ecdaeb3475177e7434ef82bfa59bc77b7c34be801165796d5ee1f9af67a8ec2cf3ff5db283b228409ea8c81d2877475b898298d4439f39051a640a201123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e755124043d3d62cd55564ccf7e95f311f1f9b30946e8979577fbb3e70906aa6e96211a436245ec1c0f791bb9b06e6b29a92a554d35cd74712866b591589d065fbf80e00"
    );
    const DISTINGUISHED_TREE_2646749_ROOT: &[u8] =
        &hex!("3d7343936b2e2b7f6e250f5c17ddd8c511428f62a8e4ffb9bcb525e89500f9a7");

    const STORED_ACCOUNT_DATA_2646789: &[u8] = &hex!(
        "0a2c0a203901c94081c4e6321e92b3e434dcaf788f5326913e7bdcab47b4fd2ae7a6848a10301a0408ffff7f2001122d0a2086052cc2a2689558e852d053c5ab411d8c3baef20171ec298e551574806ca95d1096011a0408ffff7f20011a2d0a206f55ac745ebeaf39fd5b21177c7fa692876c42678ffa1f3d58ed8fbc5ef023b910cc011a0408ffff7f200122e3020abe020885c6a10110da86fec0a2331a640a20bd1e26a0fbdbfa923486ccc9296f4227db490b4add29f5507775171ea0fb7a4e1240618471ea3986f40a215510c00e86e850ba8fa6b93e95a3dd337846bf87db82ca606490154dd0b366b2696631f1c5944806d2251805d18ca860e2ae0114d7d6031a640a201123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e7551240888394a2727dab22354fcc41eefde316fb57ebe802f549ca8a9f2d4b152c8bd67adf42564a203c96466a84c2f3d4500b2cb26ab078c3939affc24a8437e913091a640a20093ee42d95502b3e81f4e604179c82c149fffb96167642b9eb81b03d6e2dd6361240b407b7c434f0e8944c133fdf0efdf03d1c52809d4b8fce52663fb57d79c951cf91b99b78dee7d8211a35030ad87ddd025a2ea018f5ddd83bb4b4776402c0230b1220de186e87e061a4fea370946919cba4733e652c926a5bbfc6528ebcc3395ca4c4"
    );

    pub fn test_distinguished_tree() -> LastTreeHead {
        (
            TreeHead::decode(DISTINGUISHED_TREE_2646749_HEAD).expect("valid TreeHead"),
            DISTINGUISHED_TREE_2646749_ROOT
                .try_into()
                .expect("valid root size"),
        )
    }

    pub fn test_stored_account_data() -> StoredAccountData {
        StoredAccountData::decode(STORED_ACCOUNT_DATA_2646789).expect("valid stored acc data")
    }

    pub fn test_account_data() -> AccountData {
        AccountData::try_from(test_stored_account_data()).expect("valid account data")
    }
}

#[cfg(test)]
mod test {
    use std::cell::Cell;
    use std::sync::{Arc, Mutex};

    use assert_matches::assert_matches;
    use itertools::assert_equal;
    use prost::Message as _;
    use test_case::test_case;

    use super::test_support::{
        CHAT_SEARCH_RESPONSE, CHAT_SEARCH_RESPONSE_VALID_AT, KEYTRANS_CONFIG_STAGING, test_account,
        test_account_data, test_distinguished_tree,
    };
    use super::*;

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

        let kt = KeyTransparency {
            config: KEYTRANS_CONFIG_STAGING.into(),
        };

        let result = verify_chat_search_response(
            &kt,
            Versioned::from(&aci),
            e164.map(Versioned::from),
            username_hash.map(Versioned::from),
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

        let kt = KeyTransparency {
            config: KEYTRANS_CONFIG_STAGING.into(),
        };

        let result = verify_chat_search_response(
            &kt,
            Versioned::from(&aci),
            Some(Versioned::from(e164)),
            Some(Versioned::from(username_hash)),
            Some(account_data),
            search_response,
            Some(&test_distinguished_tree()),
            valid_at,
        );

        assert_matches!(result, Ok(MaybePartial {missing_fields, ..}) =>
            assert_eq!(skip.to_vec(), missing_fields.into_iter().collect::<Vec<_>>())
        );
    }

    #[derive(Default)]
    struct SearchStub {
        result: Option<Result<MaybePartial<AccountData>, RequestError<Error>>>,
        invocations: Vec<SearchVersions>,
    }

    impl SearchStub {
        fn new(res: Result<MaybePartial<AccountData>, RequestError<Error>>) -> Self {
            Self {
                result: Some(res),
                invocations: vec![],
            }
        }
    }

    struct TestKt {
        monitor: Cell<Option<Result<AccountData, RequestError<Error>>>>,
        search: Arc<Mutex<SearchStub>>,
    }

    impl TestKt {
        fn for_monitor(monitor: Result<AccountData, RequestError<Error>>) -> Self {
            Self {
                monitor: Cell::new(Some(monitor)),
                search: Arc::new(Mutex::new(Default::default())),
            }
        }

        fn new(
            monitor: Result<AccountData, RequestError<Error>>,
            search: Result<MaybePartial<AccountData>, RequestError<Error>>,
        ) -> Self {
            Self {
                monitor: Cell::new(Some(monitor)),
                search: Arc::new(Mutex::new(SearchStub::new(search))),
            }
        }
    }

    impl UnauthenticatedChatApi for TestKt {
        fn search(
            &self,
            aci: Versioned<&Aci>,
            _aci_identity_key: &PublicKey,
            e164: Option<Versioned<(E164, Vec<u8>)>>,
            username_hash: Option<Versioned<UsernameHash<'_>>>,
            _stored_account_data: Option<AccountData>,
            _distinguished_tree_head: &LastTreeHead,
        ) -> impl Future<Output = Result<MaybePartial<AccountData>, RequestError<Error>>> + Send
        {
            let mut guard = self.search.lock().expect("can lock");
            guard.invocations.push(SearchVersions {
                aci: aci.version,
                e164: e164.and_then(|x| x.version),
                username_hash: username_hash.and_then(|x| x.version),
            });

            if let Some(result) = guard.result.as_ref() {
                std::future::ready(result.clone())
            } else {
                panic!("unexpected call to search")
            }
        }

        fn distinguished(
            &self,
            _: Option<LastTreeHead>,
        ) -> impl Future<Output = Result<SearchStateUpdate, RequestError<Error>>> {
            // not used in the tests
            unreachable!();
            #[allow(unreachable_code)] // without this, `impl Future` gets confused
            std::future::pending()
        }

        fn monitor(
            &self,
            _aci: &Aci,
            _e164: Option<E164>,
            _username_hash: Option<UsernameHash<'_>>,
            _account_data: AccountData,
            _last_distinguished_tree_head: &LastTreeHead,
        ) -> impl Future<Output = Result<AccountData, RequestError<Error>>> + Send {
            let result = self.monitor.take().expect("unexpected call to monitor");
            std::future::ready(result)
        }
    }

    #[tokio::test]
    async fn monitor_and_search_monitor_error_is_returned() {
        let kt = TestKt::for_monitor(Err(RequestError::Unexpected {
            log_safe: "pass through unexpected error".to_owned(),
        }));
        let result = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            test_account_data(),
            &test_distinguished_tree(),
            MonitorMode::MonitorOther,
        )
        .await;
        assert_matches!(
            result,
            Err(RequestError::Unexpected { log_safe: msg }) if msg == "pass through unexpected error"
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
            MonitorMode::MonitorOther,
        )
        .await
        .expect("monitor should succeed");
        assert_eq!(actual, monitor_result.into());
    }

    #[derive(Clone, Copy)]
    enum BumpVersionFor {
        Aci,
        E164,
        UsernameHash,
    }

    trait Bumpable {
        fn apply(&mut self, bump: BumpVersionFor);
    }

    impl Bumpable for AccountData {
        fn apply(&mut self, bump: BumpVersionFor) {
            let subject = match bump {
                BumpVersionFor::Aci => &mut self.aci,
                BumpVersionFor::E164 => self.e164.as_mut().unwrap(),
                BumpVersionFor::UsernameHash => self.username_hash.as_mut().unwrap(),
            };
            // inserting a newer version of the subject
            let max_version = subject.greatest_version();
            subject.ptrs.insert(u64::MAX, max_version + 1);
        }
    }

    impl Bumpable for SearchVersions {
        fn apply(&mut self, bump: BumpVersionFor) {
            let subject = match bump {
                BumpVersionFor::Aci => &mut self.aci,
                BumpVersionFor::E164 => &mut self.e164,
                BumpVersionFor::UsernameHash => &mut self.username_hash,
            };
            if let Some(v) = subject.as_mut() {
                *v += 1;
            } else {
                *subject = Some(1);
            }
        }
    }

    #[tokio::test]
    #[test_case(BumpVersionFor::Aci; "newer Aci")]
    #[test_case(BumpVersionFor::E164; "newer E.164")]
    #[test_case(BumpVersionFor::UsernameHash; "newer username hash")]
    async fn monitor_and_search_e164_changed(bump: BumpVersionFor) {
        let mut monitor_result = test_account_data();
        monitor_result.apply(bump);

        let kt = TestKt::new(
            Ok(monitor_result.clone()),
            Err(RequestError::Unexpected {
                log_safe: "pass through unexpected error".to_owned(),
            }),
        );

        let result = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            test_account_data(),
            &test_distinguished_tree(),
            MonitorMode::MonitorOther,
        )
        .await;

        // monitor invocation should have succeeded, and search
        // should have been invoked returning our custom error
        assert_matches!(
            result,
            Err(RequestError::Unexpected { log_safe: msg }) if msg == "pass through unexpected error"
        );
    }

    #[tokio::test]
    async fn monitor_and_search_self_monitor_fall_back_on_version_change() {
        let mut monitor_result = test_account_data();
        monitor_result.apply(BumpVersionFor::Aci);
        monitor_result.apply(BumpVersionFor::E164);
        monitor_result.apply(BumpVersionFor::E164);
        monitor_result.apply(BumpVersionFor::UsernameHash);
        monitor_result.apply(BumpVersionFor::UsernameHash);
        monitor_result.apply(BumpVersionFor::UsernameHash);

        let kt = TestKt::new(Ok(monitor_result.clone()), Ok(test_account_data().into()));

        let result = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            Some(test_account::e164_pair()),
            Some(test_account::username_hash()),
            test_account_data(),
            &test_distinguished_tree(),
            MonitorMode::MonitorSelf,
        )
        .await;

        assert_matches!(result, Ok(actual) => {
            // The final result after all the search-with-versions succeed
            // should be what monitor originally returned.
            assert_eq!(actual.inner, monitor_result);
        });

        assert_matches!(
            kt.search.lock().expect("can lock").invocations[..],
            [
                SearchVersions {
                    aci: Some(1),
                    e164: None,
                    username_hash: None,
                },
                SearchVersions {
                    aci: Some(0),
                    e164: Some(1),
                    username_hash: None,
                },
                SearchVersions {
                    aci: Some(0),
                    e164: Some(2),
                    username_hash: None,
                },
                SearchVersions {
                    aci: Some(0),
                    e164: None,
                    username_hash: Some(1)
                },
                SearchVersions {
                    aci: Some(0),
                    e164: None,
                    username_hash: Some(2)
                },
                SearchVersions {
                    aci: Some(0),
                    e164: None,
                    username_hash: Some(3)
                },
            ]
        );
    }

    #[tokio::test]
    #[test_case(BumpVersionFor::Aci; "newer Aci")]
    #[test_case(BumpVersionFor::E164; "newer E.164")]
    #[test_case(BumpVersionFor::UsernameHash; "newer username hash")]
    async fn monitor_and_search_self_monitor_fall_back_search_with_version_failure(
        bump: BumpVersionFor,
    ) {
        let mut monitor_result = test_account_data();
        monitor_result.apply(bump);

        let kt = TestKt::new(
            Ok(monitor_result.clone()),
            Err(RequestError::Unexpected {
                log_safe: "search with version failed".to_string(),
            }),
        );

        let result = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            Some(test_account::e164_pair()),
            Some(test_account::username_hash()),
            test_account_data(),
            &test_distinguished_tree(),
            MonitorMode::MonitorSelf,
        )
        .await;

        assert_matches!(result, Err(RequestError::Unexpected { .. }));

        let mut expected_versions = SearchVersions {
            // ACI is required, so we will have to search for it always.
            aci: Some(0),
            e164: None,
            username_hash: None,
        };
        expected_versions.apply(bump);

        assert_equal(
            kt.search.lock().expect("can lock").invocations.clone(),
            [expected_versions],
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

        let kt = TestKt::new(
            Ok(monitor_result.clone()),
            Ok(search_result_account_data.clone().into()),
        );

        let updated_account_data = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            test_account_data(),
            &test_distinguished_tree(),
            MonitorMode::MonitorOther,
        )
        .await
        .expect("both monitor and search should have succeeded");

        assert_eq!(
            search_result_account_data,
            updated_account_data.into_inner()
        );
    }

    #[tokio::test]
    #[test_case(BumpVersionFor::Aci; "newer Aci")]
    #[test_case(BumpVersionFor::E164; "newer E.164")]
    #[test_case(BumpVersionFor::UsernameHash; "newer username hash")]
    async fn monitor_and_search_self_monitor_version_jump_too_big(bump: BumpVersionFor) {
        let mut monitor_result = test_account_data();
        for _ in 0..MAXIMUM_ALLOWED_VERSION_DELTA + 1 {
            monitor_result.apply(bump);
        }

        let kt = TestKt::for_monitor(Ok(monitor_result));

        let result = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            Some(test_account::e164_pair()),
            Some(test_account::username_hash()),
            test_account_data(),
            &test_distinguished_tree(),
            MonitorMode::MonitorSelf,
        )
        .await;

        assert_matches!(
            result,
            Err(RequestError::Other(Error::VerificationFailed(_)))
        );
    }
}
