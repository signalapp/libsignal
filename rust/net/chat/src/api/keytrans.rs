//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod maybe_partial;
mod monitor_and_search;
mod verify_ext;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::time::SystemTime;

use async_trait::async_trait;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{
    AccountData, ChatDistinguishedResponse, ChatMonitorResponse, ChatSearchResponse,
    CondensedTreeSearchResponse, FullSearchResponse, FullTreeHead, KeyTransparency, LastTreeHead,
    LocalStateUpdate, MonitorContext, MonitorKey, MonitorProof, MonitorRequest, MonitorResponse,
    SearchContext, SearchStateUpdate, SlimSearchRequest,
};
use libsignal_net::env::KeyTransConfig;
use libsignal_protocol::PublicKey;
pub use maybe_partial::{AccountDataField, MaybePartial};
pub use monitor_and_search::{MonitorMode, check as monitor_and_search};
use verify_ext::KeyTransparencyVerifyExt as _;

use super::RequestError;

const SEARCH_KEY_PREFIX_ACI: &[u8] = b"a";
const SEARCH_KEY_PREFIX_E164: &[u8] = b"n";
const SEARCH_KEY_PREFIX_USERNAME_HASH: &[u8] = b"u";

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
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<&(E164, Vec<u8>)>,
        username_hash: Option<&UsernameHash<'_>>,
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
    pub(crate) fn from_untyped(response: ChatSearchResponse) -> Result<Self, Error> {
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

impl<T: SearchKey> SearchKey for &T {
    fn as_search_key(&self) -> Vec<u8> {
        (*self).as_search_key()
    }
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
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<(E164, Vec<u8>)>,
        username_hash: Option<UsernameHash<'_>>,
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
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<(E164, Vec<u8>)>,
        username_hash: Option<UsernameHash<'_>>,
        stored_account_data: Option<AccountData>,
        distinguished_tree_head: &LastTreeHead,
    ) -> Result<MaybePartial<AccountData>, RequestError<Error>> {
        let chat_search_response = self
            .chat
            .search(
                aci,
                aci_identity_key,
                e164.as_ref(),
                username_hash.as_ref(),
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
            .and_then(|r| TypedSearchResponse::from_untyped(r).map_err(RequestError::Other))?;

        let now = SystemTime::now();

        let e164_search_key = e164.as_ref().map(|(x, _)| x.as_search_key());
        let username_hash_search_key = username_hash.as_ref().map(SearchKey::as_search_key);

        let mut account_data = self
            .inner
            .verify_chat_search_response(
                aci,
                e164.map(|(e164, _)| e164),
                username_hash,
                stored_account_data,
                chat_search_response,
                Some(distinguished_tree_head),
                now,
            )
            .map_err(RequestError::Other)?;

        // Preserve search keys in account data
        account_data.inner.aci.search_key = aci.as_search_key();
        if let Some(stored) = account_data.inner.e164.as_mut() {
            stored.search_key = e164_search_key.unwrap_or_default();
        }
        if let Some(stored) = account_data.inner.username_hash.as_mut() {
            stored.search_key = username_hash_search_key.unwrap_or_default();
        }
        Ok(account_data)
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
                proofs.push(
                    chat_monitor_response
                        .e164
                        .expect("checked in TypedMonitorResponse::from_untyped"),
                );
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
                proofs.push(
                    chat_monitor_response
                        .username_hash
                        .expect("checked in TypedMonitorResponse::from_untyped"),
                );
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
                monitoring_data
                    .remove(search_key)
                    .map(|mut d| {
                        d.search_key = search_key.to_vec();
                        d
                    })
                    .ok_or_else(|| {
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
                last_tree_head: LastTreeHead(tree_head, tree_root),
            }
        };

        Ok(updated_account_data)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::Cell;
    use std::time::Duration;

    use assert_matches::assert_matches;
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

    const DISTINGUISHED_TREE_48419053_HEAD: &[u8] = &hex!(
        "08eda18b1710efcdb4cec4331a640a20bd1e26a0fbdbfa923486ccc9296f4227db490b4add29f5507775171ea0fb7a4e12409e2954d37dad743d4eb2209309ee5ba85ed72a2fb7c39b34158270bc9954ead0e61cb418c548373955e99592c82506e9188ab6c960f8b2d8b6b864197165ca0d1a640a201123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e7551240fa9f4b8c4fe55a16c559d6da4d974cdf7e6957cb31a1a55dbaf9e4f715cbefc40d273a1bfde5b77b2eb2731a298b454a44bba41557f2b9f87c6eec4f3623ca041a640a20093ee42d95502b3e81f4e604179c82c149fffb96167642b9eb81b03d6e2dd6361240e9cee1ed1a8d5d1026cac0ac7101a608b131fa592f6d26505cde31c111c450afad61ca7d685924438ebc8e12bf1c3632b6161334e10c9e3ad72b7931cb6f0504"
    );
    const DISTINGUISHED_TREE_48419053_ROOT: &[u8] =
        &hex!("9bc6752695ec310be8eca0257becbfa5ca8daeceac318989e764e8b7c7fb1608");

    const STORED_ACCOUNT_DATA_48419073: &[u8] = &hex!(
        "0a400a203901c94081c4e6321e92b3e434dcaf788f5326913e7bdcab47b4fd2ae7a6848a10301a0508ffffff0f20012a116190c979fdeab44a08b6da69dedeab9b29123d0a2086052cc2a2689558e852d053c5ab411d8c3baef20171ec298e551574806ca95d1096011a0508ffffff0f20012a0d6e2b31383030353535303130301a510a206f55ac745ebeaf39fd5b21177c7fa692876c42678ffa1f3d58ed8fbc5ef023b910cc011a0508ffffff0f20012a2175dc711808c2cf66d5e6a33ce41f27d69d942d2e1ff4db22d39b42d2eff8d0974622ea020abe020881a28b171096edb4cec4331a640a20bd1e26a0fbdbfa923486ccc9296f4227db490b4add29f5507775171ea0fb7a4e12407c1136788cda4543f6cdf9154b40a5fdaab6eb44ff3c350ed8595c975f48db40f86b78f2f7684dcb4f3c36e2f1491ae1c08aa3665bdcaa0c8492b913c37b0d0e1a640a201123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e7551240ec504259cfba1b31665abe005f8ded7096090d505ae39a4cad456b57f58307be8cb2cd5d74eb3eeb77a9387f22601595286f4bfe6fb6e49cc70d4834d84f21041a640a20093ee42d95502b3e81f4e604179c82c149fffb96167642b9eb81b03d6e2dd636124013c9a37acb164f9b2bc022e69ff621bcc0012dfab38ef56638f4bd9eafd855cda6eb5dcc17ffde2ba306589284861177e035dce98fe781ae59d58c59a39643091220967878356efab797d8945d7e523da0ac943237e7a6a246bb03a1c174486f0bea18f5fab4cec433"
    );

    pub fn test_distinguished_tree() -> LastTreeHead {
        LastTreeHead(
            TreeHead::decode(DISTINGUISHED_TREE_48419053_HEAD).expect("valid TreeHead"),
            DISTINGUISHED_TREE_48419053_ROOT
                .try_into()
                .expect("valid root size"),
        )
    }

    pub fn test_stored_account_data() -> StoredAccountData {
        StoredAccountData::decode(STORED_ACCOUNT_DATA_48419073).expect("valid stored acc data")
    }

    pub fn test_account_data() -> AccountData {
        AccountData::try_from(test_stored_account_data()).expect("valid account data")
    }

    #[derive(Debug, Clone)]
    pub struct OwnedParameters {
        pub aci: Aci,
        pub e164: Option<(E164, Vec<u8>)>,
        pub username_hash_bytes: Option<Vec<u8>>,
    }

    #[derive(Default)]
    pub struct SearchStub {
        pub result: Option<Result<MaybePartial<AccountData>, RequestError<Error>>>,
        pub invocations: Vec<OwnedParameters>,
    }

    impl SearchStub {
        fn new(res: Option<Result<MaybePartial<AccountData>, RequestError<Error>>>) -> Self {
            Self {
                result: res,
                invocations: vec![],
            }
        }
    }

    pub struct TestKt {
        pub monitor: Cell<Option<Result<AccountData, RequestError<Error>>>>,
        pub search: Cell<SearchStub>,
    }

    impl TestKt {
        pub fn for_monitor(monitor: Result<AccountData, RequestError<Error>>) -> Self {
            Self::new(Some(monitor), None)
        }

        pub fn for_search(search: Result<MaybePartial<AccountData>, RequestError<Error>>) -> Self {
            Self::new(None, Some(search))
        }

        pub fn new(
            monitor: Option<Result<AccountData, RequestError<Error>>>,
            search: Option<Result<MaybePartial<AccountData>, RequestError<Error>>>,
        ) -> Self {
            Self {
                monitor: Cell::new(monitor),
                search: Cell::new(SearchStub::new(search)),
            }
        }

        pub fn expected_error() -> RequestError<Error> {
            RequestError::Unexpected {
                log_safe: "test error".to_string(),
            }
        }

        pub fn assert_expected_error<T: Debug>(result: Result<T, RequestError<Error>>) {
            assert_matches!(result, Err(RequestError::Unexpected { log_safe }) if log_safe == "test error")
        }
    }

    impl UnauthenticatedChatApi for TestKt {
        fn search(
            &self,
            aci: &Aci,
            _aci_identity_key: &PublicKey,
            e164: Option<(E164, Vec<u8>)>,
            username_hash: Option<UsernameHash<'_>>,
            _stored_account_data: Option<AccountData>,
            _distinguished_tree_head: &LastTreeHead,
        ) -> impl Future<Output = Result<MaybePartial<AccountData>, RequestError<Error>>> + Send
        {
            let mut search_stub = self.search.take();

            search_stub.invocations.push(OwnedParameters {
                aci: *aci,
                e164,
                username_hash_bytes: username_hash.map(|x| x.as_ref().to_vec()),
            });

            let result = search_stub
                .result
                .as_ref()
                .expect("unexpected call to search")
                .clone();
            self.search.set(search_stub);
            std::future::ready(result.clone())
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
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
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
        TypedSearchResponse::from_untyped(chat_search_response)
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

        let result = kt.verify_chat_search_response(
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

        let result = kt.verify_chat_search_response(
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
}
