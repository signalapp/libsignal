//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::prelude::{
    Engine as _, BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE_NO_PAD,
};
use http::header::{ACCEPT, CONTENT_TYPE};
use http::uri::PathAndQuery;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{
    AccountData, ChatDistinguishedResponse, ChatSearchResponse, CondensedTreeSearchResponse,
    FullSearchResponse, FullTreeHead, KeyTransparency, LastTreeHead, LocalStateUpdate,
    MonitoringData, SearchContext, SearchStateUpdate, SlimSearchRequest, StoredAccountData,
    StoredMonitoringData, StoredTreeHead, VerifiedSearchResult,
};
use libsignal_protocol::{IdentityKey, PublicKey};
use prost::{DecodeError, Message};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::chat::{self, Chat, ChatServiceWithDebugInfo};

const SEARCH_PATH: &str = "/v1/key-transparency/search";
const DISTINGUISHED_PATH: &str = "/v1/key-transparency/distinguished";
// const MONITOR_PATH: &str = "/v1/key-transparency/monitor";

const MIME_TYPE: &str = "application/json";

fn common_headers() -> http::HeaderMap {
    http::HeaderMap::from_iter([
        (CONTENT_TYPE, http::HeaderValue::from_static(MIME_TYPE)),
        (ACCEPT, http::HeaderValue::from_static(MIME_TYPE)),
    ])
}

#[derive(Debug, Error, displaydoc::Display)]
pub enum Error {
    /// Chat request failed: {0}
    ChatServiceError(#[from] chat::ChatServiceError),
    /// Bad status code: {0}
    RequestFailed(http::StatusCode),
    /// Verification failed: {0}
    VerificationFailed(#[from] libsignal_keytrans::Error),
    /// Invalid response: {0}
    InvalidResponse(&'static str),
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
    serialized_response: Option<String>,
}

impl TryFrom<chat::Response> for RawChatSerializedResponse {
    type Error = Error;

    fn try_from(response: chat::Response) -> Result<Self> {
        let body = response
            .body
            .ok_or(Error::InvalidResponse("missing body"))?;
        serde_json::from_slice(&body).map_err(|_| Error::InvalidResponse("invalid JSON"))
    }
}

// Differs from [`ChatSearchResponse`] by establishing proper optionality of fields.
struct TypedChatSearchResponse {
    full_tree_head: FullTreeHead,
    aci_search_response: CondensedTreeSearchResponse,
    e164_search_response: Option<CondensedTreeSearchResponse>,
    username_hash_search_response: Option<CondensedTreeSearchResponse>,
}

impl TryFrom<RawChatSerializedResponse> for TypedChatSearchResponse {
    type Error = Error;

    fn try_from(raw: RawChatSerializedResponse) -> Result<Self> {
        let ChatSearchResponse {
            tree_head,
            aci,
            e164,
            username_hash,
        } = raw
            .serialized_response
            .ok_or(Error::InvalidResponse("serializedResponse is missing"))
            .and_then(decode_response)?;

        let tree_head = tree_head.ok_or(Error::InvalidResponse("must contain the tree head"))?;

        let aci_search_response = aci.ok_or(Error::InvalidResponse(
            "must contain the ACI search response",
        ))?;

        Ok(Self {
            full_tree_head: tree_head,
            aci_search_response,
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
        .map_err(|_| Error::InvalidResponse("invalid base64"))?;

    R::decode(proto_bytes.as_slice())
        .map_err(|_| Error::InvalidResponse("invalid search response protobuf encoding"))
}

// 0x00 is the current version prefix
const SEARCH_VALUE_PREFIX: u8 = 0x00;

/// A safe-to-use wrapper around the values returned by KT server.
///
/// The KT server stores values prefixed with an extra "version" byte, that needs
/// to be stripped.
///
/// SearchValue validates the prefix upon construction from raw bytes, and
/// provides acces to the actual underlying value via its payload method.
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
            Err(Error::InvalidResponse("bad value format"))
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
        Aci::parse_from_service_id_binary(value.payload()).ok_or(Error::InvalidResponse("bad ACI"))
    }
}

impl TryFrom<SearchValue<'_>> for IdentityKey {
    type Error = Error;

    fn try_from(value: SearchValue) -> std::result::Result<Self, Self::Error> {
        IdentityKey::decode(value.payload()).map_err(|_| Error::InvalidResponse("bad identity key"))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawChatDistinguishedRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    last_tree_head_size: Option<u64>,
}

impl From<RawChatDistinguishedRequest> for chat::Request {
    fn from(request: RawChatDistinguishedRequest) -> Self {
        Self {
            method: http::Method::GET,
            body: Some(serde_json::to_vec(&request).unwrap().into_boxed_slice()),
            headers: common_headers(),
            path: PathAndQuery::from_static(DISTINGUISHED_PATH),
        }
    }
}

impl TryFrom<RawChatSerializedResponse> for ChatDistinguishedResponse {
    type Error = Error;

    fn try_from(raw: RawChatSerializedResponse) -> Result<Self> {
        raw.serialized_response
            .ok_or(Error::InvalidResponse("required field is missing"))
            .and_then(decode_response)
    }
}

type AnyChat = Chat<
    Arc<dyn ChatServiceWithDebugInfo + Send + Sync>,
    Arc<dyn ChatServiceWithDebugInfo + Send + Sync>,
>;

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
    pub chat: &'a AnyChat,
    pub config: Config,
}

#[derive(Debug, Clone, Default)]
pub struct ChatSearchContext {
    pub account_data: Option<StoredAccountData>,
    pub distinguished_tree_head_size: u64,
}

impl ChatSearchContext {
    fn make_raw_request(
        &self,
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<&(E164, Vec<u8>)>,
        username_hash: Option<&UsernameHash>,
    ) -> RawChatSearchRequest {
        fn get_tree_size(account_data: &StoredAccountData) -> Option<u64> {
            let stored = account_data.last_tree_head.as_ref()?;
            let head = stored.tree_head.as_ref()?;
            Some(head.tree_size)
        }
        RawChatSearchRequest {
            aci: aci.service_id_string(),
            aci_identity_key: BASE64_STANDARD.encode(aci_identity_key.serialize()),
            e164: e164.map(|x| x.0.to_string()),
            username_hash: username_hash.map(|x| BASE64_URL_SAFE_NO_PAD.encode(x.as_ref())),
            unidentified_access_key: e164.map(|x| BASE64_STANDARD.encode(&x.1)),
            last_tree_head_size: self.account_data.as_ref().and_then(get_tree_size),
            distinguished_tree_head_size: self.distinguished_tree_head_size,
        }
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

impl<'a> Kt<'a> {
    async fn send(&self, request: chat::Request) -> Result<chat::Response> {
        log::debug!(
            "{}",
            &String::from_utf8(request.clone().body.unwrap().to_vec()).unwrap()
        );
        let response = self
            .chat
            .send_unauthenticated(request, self.config.chat_timeout)
            .await?;
        log::debug!("{:?}", &response);
        if !response.status.is_success() {
            Err(Error::RequestFailed(response.status))
        } else {
            Ok(response)
        }
    }

    pub async fn search(
        &self,
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<(E164, Vec<u8>)>,
        username_hash: Option<UsernameHash<'a>>,
        context: ChatSearchContext,
    ) -> Result<SearchResult> {
        let raw_request =
            context.make_raw_request(aci, aci_identity_key, e164.as_ref(), username_hash.as_ref());
        let response = self.send(raw_request.into()).await?;

        let chat_search_response = RawChatSerializedResponse::try_from(response)
            .and_then(TypedChatSearchResponse::try_from)?;

        let ChatSearchContext {
            account_data: stored_account_data,
            distinguished_tree_head_size: _,
        } = context;

        let account_data = stored_account_data.map(AccountData::try_from).transpose()?;
        let now = SystemTime::now();

        // TODO: this could be a `validate` on the TypedSearchResponse, but then what to accept as the "expected" arguments?
        if e164.is_some() != chat_search_response.e164_search_response.is_some()
            || username_hash.is_some()
                != chat_search_response.username_hash_search_response.is_some()
        {
            return Err(Error::InvalidResponse(
                "request/response optionality mismatch",
            ));
        }

        let (
            aci_monitoring_data,
            e164_monitoring_data,
            username_hash_monitoring_data,
            stored_last_tree_head,
        ) = match account_data {
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

        let aci_result = self.do_verify_search(
            aci.as_search_key(),
            chat_search_response.aci_search_response,
            aci_monitoring_data,
            &chat_search_response.full_tree_head,
            stored_last_tree_head.as_ref(),
            now,
        )?;
        let e164_result = e164
            .map(|(e164, _)| {
                self.do_verify_search(
                    e164.as_search_key(),
                    chat_search_response
                        .e164_search_response
                        .expect("e164 response must be present"),
                    e164_monitoring_data,
                    &chat_search_response.full_tree_head,
                    stored_last_tree_head.as_ref(),
                    now,
                )
            })
            .transpose()?;
        let username_hash_result = username_hash
            .map(|username_hash| {
                self.do_verify_search(
                    username_hash.as_search_key(),
                    chat_search_response
                        .username_hash_search_response
                        .expect("username hash response must be present"),
                    username_hash_monitoring_data,
                    &chat_search_response.full_tree_head,
                    stored_last_tree_head.as_ref(),
                    now,
                )
            })
            .transpose()?;

        if !aci_result.are_all_roots_equal([e164_result.as_ref(), username_hash_result.as_ref()]) {
            return Err(Error::InvalidResponse("mismatching tree roots"));
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

        Ok(SearchResult {
            aci_identity_key: identity_key,
            aci_for_e164,
            aci_for_username_hash,
            timestamp: now,
            account_data: updated_account_data,
        })
    }

    pub async fn distinguished(
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
            .and_then(ChatDistinguishedResponse::try_from)?;

        let tree_head = tree_head.ok_or(Error::InvalidResponse("tree head must be present"))?;
        let condensed_response =
            distinguished.ok_or(Error::InvalidResponse("search response must be present"))?;
        let search_response = FullSearchResponse::new(condensed_response, &tree_head);

        let slim_search_request = SlimSearchRequest::new(b"distinguished".to_vec());

        let verified_result = self.inner.verify_search(
            slim_search_request,
            search_response,
            SearchContext {
                last_tree_head: last_distinguished.as_ref(),
                ..Default::default()
            },
            false,
            SystemTime::now(),
        )?;
        Ok(verified_result.state_update)
    }

    fn do_verify_search(
        &self,
        search_key: Vec<u8>,
        response: CondensedTreeSearchResponse,
        monitoring_data: Option<MonitoringData>,
        full_tree_head: &FullTreeHead,
        last_tree_head: Option<&LastTreeHead>,
        now: SystemTime,
    ) -> Result<VerifiedSearchResult> {
        let result = self.inner.verify_search(
            SlimSearchRequest::new(search_key),
            FullSearchResponse::new(response, full_tree_head),
            SearchContext {
                last_tree_head,
                data: monitoring_data.map(MonitoringData::from),
            },
            true,
            now,
        )?;
        Ok(result)
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

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use hex_literal::hex;
    use libsignal_keytrans::{DeploymentMode, PublicConfig, VerifyingKey, VrfPublicKey};
    use test_case::test_case;

    use super::*;
    use crate::auth::Auth;
    use crate::env;

    mod test_account {
        use hex_literal::hex;
        use libsignal_core::E164;
        use nonzero_ext::nonzero;
        use uuid::Uuid;

        pub const ACI: Uuid = uuid::uuid!("90c979fd-eab4-4a08-b6da-69dedeab9b29");
        pub const ACI_IDENTITY_KEY_BYTES: &[u8] =
            &hex!("05d0e797ec91a4bce0e88959c419e96eb4fdabbb3dc688965584c966dc24195609");
        pub const USERNAME_HASH: &[u8] =
            &hex!("d237a4b83b463ca7da58d4a16bf6a3ba104506eb412b235eb603ea10f467c655");
        pub const PHONE_NUMBER: E164 = E164::new(nonzero!(18005550100u64));
        pub const UNIDENTIFIED_ACCESS_KEY: &[u8] = &hex!("fdc7951d1507268daf1834b74d23b76c");
    }

    const SIGNING_KEY: &[u8; 32] =
        &hex!("12a21ad60d5a3978e19a3b0baa8c35c55a20e10d45f39e5cb34bf6e1b3cce432");
    const VRF_KEY: &[u8; 32] =
        &hex!("1e71563470c1b8a6e0aadf280b6aa96f8ad064674e69b80292ee46d1ab655fcf");
    const AUDITOR_KEY: &[u8; 32] =
        &hex!("1123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e755");

    fn make_kt(chat: &AnyChat) -> Kt {
        let signature_key =
            VerifyingKey::from_bytes(SIGNING_KEY).expect("valid signature key material");
        let vrf_key = VrfPublicKey::try_from(*VRF_KEY).expect("valid vrf key material");
        let auditor_key =
            VerifyingKey::from_bytes(AUDITOR_KEY).expect("valid auditor key material");
        let inner = KeyTransparency {
            config: PublicConfig {
                mode: DeploymentMode::ThirdPartyAuditing(auditor_key),
                signature_key,
                vrf_key,
            },
        };
        Kt {
            inner,
            chat,
            config: Default::default(),
        }
    }

    async fn make_chat() -> AnyChat {
        use crate::chat::test_support::simple_chat_service;
        let chat = simple_chat_service(
            &env::STAGING,
            Auth::default(),
            vec![env::STAGING
                .chat_domain_config
                .connect
                .direct_connection_params()],
        );
        chat.connect_unauthenticated()
            .await
            .expect("can connect to chat");
        chat
    }

    #[tokio::test]
    #[test_case(false, false; "ACI")]
    #[test_case(false, true; "ACI + E164")]
    #[test_case(true, true; "ACI + E164 + Username Hash")]
    async fn search_permutations_integration_test(use_e164: bool, use_username_hash: bool) {
        if std::env::var("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_err() {
            println!("SKIPPED: running integration tests is not enabled");
            return;
        }
        let chat = make_chat().await;
        let kt = make_kt(&chat);

        let aci = Aci::from(test_account::ACI);
        let aci_identity_key =
            PublicKey::deserialize(test_account::ACI_IDENTITY_KEY_BYTES).expect("valid key bytes");

        let e164 = (
            test_account::PHONE_NUMBER,
            test_account::UNIDENTIFIED_ACCESS_KEY.to_vec(),
        );

        let username_hash = UsernameHash(Cow::Borrowed(test_account::USERNAME_HASH));
        let distinguished_tree_head_size = kt
            .distinguished(None)
            .await
            .expect("can get distinguished tree")
            .tree_head
            .tree_size;

        let result = kt
            .search(
                &aci,
                &aci_identity_key,
                use_e164.then_some(e164),
                use_username_hash.then_some(username_hash),
                ChatSearchContext {
                    account_data: None,
                    distinguished_tree_head_size,
                },
            )
            .await;

        assert_matches!(result, Ok(_), "Failed to get search result");
        let result = result.unwrap();

        assert_eq!(
            &hex::encode(test_account::ACI_IDENTITY_KEY_BYTES),
            &hex::encode(result.aci_identity_key.serialize())
        );
    }

    #[tokio::test]
    async fn distinguished_integration_test() {
        if std::env::var("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_err() {
            println!("SKIPPED: running integration tests is not enabled");
            return;
        }
        let chat = make_chat().await;
        let kt = make_kt(&chat);

        let result = kt.distinguished(None).await;
        assert_matches!(result, Ok( LocalStateUpdate {tree_head, ..}) => assert_ne!(tree_head.tree_size, 0));
    }
}
