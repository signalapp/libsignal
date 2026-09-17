//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;

use async_trait::async_trait;
use base64::prelude::{
    BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE_NO_PAD, Engine as _,
};
use http::header::ACCEPT;
use http::uri::PathAndQuery;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{AccountData, LastTreeHead};
use libsignal_net::chat;
use libsignal_net_grpc::proto::chat::services;
use libsignal_protocol::PublicKey;
use serde::{Deserialize, Serialize};

use super::{CONTENT_TYPE_JSON, CustomError, TryIntoResponse as _, WsConnection};
use crate::api::keytrans::*;
use crate::api::{AllowRateLimitChallenges, RequestError, Unauth};
use crate::grpc::keytrans::KtOverGrpc;
use crate::logging::DebugAsStrOrBytes;

const SEARCH_PATH: &str = "/v1/key-transparency/search";
const DISTINGUISHED_PATH: &str = "/v1/key-transparency/distinguished";
const MONITOR_PATH: &str = "/v1/key-transparency/monitor";

/// Key transparency requests are unauthenticated and thus cannot have challenges.
///
/// This is a free constant rather than an associated one (like the other services) because the KT
/// implementation uses `dyn`, which isn't compatible with associated constants.
const ALLOW_RATE_LIMIT_CHALLENGES: AllowRateLimitChallenges = AllowRateLimitChallenges::No;

fn common_headers() -> http::HeaderMap {
    http::HeaderMap::from_iter([CONTENT_TYPE_JSON, (ACCEPT, CONTENT_TYPE_JSON.1)])
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
            e164: e164.as_ref().map(|x| x.0.as_chat_value()),
            username_hash: username_hash.as_ref().map(|x| x.as_chat_value()),
            unidentified_access_key: e164.as_ref().map(|x| BASE64_STANDARD.encode(&x.1)),
            last_tree_head_size,
            distinguished_tree_head_size,
        }
    }
}

impl From<RawChatSearchRequest> for chat::Request {
    fn from(request: RawChatSearchRequest) -> Self {
        Self {
            method: http::Method::POST,
            body: Some(
                serde_json::to_vec(&request)
                    .expect("can convert to JSON")
                    .into(),
            ),
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
            body: Some(
                serde_json::to_vec(&request)
                    .expect("can convert to JSON")
                    .into(),
            ),
            headers: common_headers(),
            path: PathAndQuery::from_static(MONITOR_PATH),
        }
    }
}

impl RawChatMonitorRequest {
    fn new(
        aci: &Aci,
        e164: Option<E164>,
        username_hash: Option<&UsernameHash<'_>>,
        account_data: &AccountData,
        distinguished_tree_head_size: u64,
    ) -> Result<Self, Error> {
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
                    account_data
                        .e164
                        .as_ref()
                        .expect("checked above")
                        .latest_log_position(),
                    &account_data.e164.as_ref().expect("checked above").index,
                )
            }),
            username_hash: username_hash.as_ref().map(|unh| {
                ValueMonitor::for_username_hash(
                    unh,
                    account_data
                        .username_hash
                        .as_ref()
                        .expect("checked above")
                        .latest_log_position(),
                    &account_data
                        .username_hash
                        .as_ref()
                        .expect("checked above")
                        .index,
                )
            }),
            last_non_distinguished_tree_head_size,
            last_distinguished_tree_head_size: distinguished_tree_head_size,
        })
    }
}

impl<T: WsConnection> Unauth<T> {
    async fn send_kt_request(
        &self,
        request: chat::Request,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        log::debug!("{}", request.path.as_str());
        log::debug!(
            "{:?}",
            DebugAsStrOrBytes(request.body.as_deref().unwrap_or_default())
        );
        // All KT requests keep identifying information out of the path+query, so it's okay to log
        // it. The Distinguished request does include the tree size, but that only reveals when the
        // client last fetched the tree, which would be in logs anyway.
        let response = self
            .0
            .send("kt", &request.path.to_string(), request)
            .await?;
        log::debug!(
            "{} {:?}, headers: {:?}, body: {}",
            response.status,
            response.message,
            response.headers,
            hex::encode({
                let body_slice = response.body.as_deref().unwrap_or_default();
                &body_slice[..body_slice.len().min(1024)]
            })
        );
        let response: RawChatSerializedResponse = response.try_into_response().map_err(|e| {
            e.into_request_error(ALLOW_RATE_LIMIT_CHALLENGES, CustomError::no_custom_handling)
        })?;
        BASE64_STANDARD_NO_PAD
            .decode(&response.serialized_response)
            .map_err(|_| RequestError::Other(Error::InvalidResponse("invalid base64".to_string())))
    }
}

/// The gRPC request name *all three* KT methods look up, not just `search`.
fn kt_grpc_message() -> &'static str {
    services::KeyTransparencyQueryService::SearchV2.into()
}

#[async_trait]
impl<T: WsConnection> LowLevelChatApi for Unauth<T> {
    async fn search(
        &self,
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<&(E164, Vec<u8>)>,
        username_hash: Option<&UsernameHash<'_>>,
        stored_account_data: Option<&AccountData>,
        distinguished_tree_head: &LastTreeHead,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        if let Some(grpc) = self.grpc_service_to_use_instead(kt_grpc_message()) {
            return KtOverGrpc(grpc)
                .search(
                    aci,
                    aci_identity_key,
                    e164,
                    username_hash,
                    stored_account_data,
                    distinguished_tree_head,
                )
                .await;
        }

        let raw_request = RawChatSearchRequest::new(
            aci,
            aci_identity_key,
            e164,
            username_hash,
            stored_account_data.map(|acc_data| acc_data.last_tree_head.0.tree_size),
            distinguished_tree_head.0.tree_size,
        );
        self.send_kt_request(raw_request.into()).await
    }

    async fn distinguished(
        &self,
        last_distinguished: Option<&LastTreeHead>,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        if let Some(grpc) = self.grpc_service_to_use_instead(kt_grpc_message()) {
            return KtOverGrpc(grpc).distinguished(last_distinguished).await;
        }

        let distinguished_size =
            last_distinguished.map(|last_tree_head| last_tree_head.0.tree_size);

        let raw_request = RawChatDistinguishedRequest {
            last_tree_head_size: distinguished_size,
        };
        self.send_kt_request(raw_request.into()).await
    }

    async fn monitor(
        &self,
        aci: &Aci,
        e164: Option<&E164>,
        username_hash: Option<&UsernameHash<'_>>,
        account_data: &AccountData,
        last_distinguished_tree_head: &LastTreeHead,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        if let Some(grpc) = self.grpc_service_to_use_instead(kt_grpc_message()) {
            return KtOverGrpc(grpc)
                .monitor(
                    aci,
                    e164,
                    username_hash,
                    account_data,
                    last_distinguished_tree_head,
                )
                .await;
        }

        let raw_request = RawChatMonitorRequest::new(
            aci,
            e164.cloned(),
            username_hash,
            account_data,
            last_distinguished_tree_head.0.tree_size,
        )
        .map_err(RequestError::Other)?;
        self.send_kt_request(raw_request.into()).await
    }
}

#[cfg(test)]
mod grpc_dispatch_test {
    use futures_util::FutureExt as _;
    use prost::Message as _;

    use super::test_support::test_distinguished_tree;
    use super::*;

    // The opposite of the dispatch tests in [`crate::grpc::keytrans`].
    #[test]
    fn distinguished_dispatches_to_ws() {
        let payload = libsignal_keytrans::ChatDistinguishedResponse {
            tree_head: None,
            distinguished: None,
        }
        .encode_to_vec();
        let body = serde_json::json!({
            "serializedResponse": BASE64_STANDARD_NO_PAD.encode(&payload),
        });

        let chat = Unauth(crate::ws::testutil::ProduceResponse(chat::Response {
            status: http::StatusCode::OK,
            message: None,
            headers: common_headers(),
            body: Some(serde_json::to_vec(&body).expect("can serialize").into()),
        }));

        let result = chat
            .distinguished(Some(&test_distinguished_tree()))
            .now_or_never()
            .expect("sync")
            .expect("success");

        assert_eq!(result, payload);
    }
}

#[cfg(test)]
mod test_support {
    use std::time::SystemTime;

    use libsignal_keytrans::ChatSearchResponse;
    use prost::Message as _;

    use super::*;
    pub use crate::api::keytrans::test_support::*;

    #[allow(dead_code)]
    // This function automates the collection of the test data.
    //
    // In particular, the constants that start with:
    // - DISTINGUISHED_TREE_
    // - STORED_ACCOUNT_DATA_
    //
    // In order to collect the test data:
    // - Uncomment the #[tokio::test] line
    // - Execute the test as `cargo test --package libsignal-net-chat --all-features collect_test_data -- --nocapture`
    // - Follow the prompts
    // - Replace the "const" definitions in the code with the ones printed out by the test.
    // - Copy the "chat_search_response.dat" file to "rust/net/tests/data/" replacing the existing one.
    //
    // #[tokio::test]
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
        println!("Size: {}", result.tree_head.tree_size);
        println!(
            "const DISTINGUISHED_TREE_{}_HEAD: &[u8] = &hex!(\"{}\");",
            distinguished_tree_size,
            hex::encode(result.tree_head.encode_to_vec())
        );
        println!(
            "const DISTINGUISHED_TREE_{}_ROOT: &[u8] = &hex!(\"{}\");",
            distinguished_tree_size,
            hex::encode(result.tree_root)
        );

        let distinguished_tree = LastTreeHead(result.tree_head, result.tree_root);

        prompt("Now advance the tree (and press ENTER)");

        let aci = Aci::from(test_account::ACI);
        let aci_identity_key =
            PublicKey::deserialize(test_account::ACI_IDENTITY_KEY_BYTES).expect("valid key bytes");
        let e164 = (
            test_account::PHONE_NUMBER,
            test_account::UNIDENTIFIED_ACCESS_KEY.to_vec(),
        );
        let username_hash = UsernameHash::from_slice(test_account::USERNAME_HASH);

        println!("Requesting account data...");

        let account_data = kt
            .search(
                &aci,
                &aci_identity_key,
                Some(e164.clone()),
                Some(username_hash.clone()),
                None,
                &distinguished_tree,
            )
            .await
            .expect("can perform search")
            .inner;

        let last_tree_size = account_data.clone().last_tree_head.0.tree_size;

        assert_ne!(
            distinguished_tree_size, last_tree_size,
            "The tree did not advance!"
        );

        {
            let stored_account_data = account_data
                .clone()
                .into_stored(
                    aci.as_search_key(),
                    Some(test_account::PHONE_NUMBER.as_search_key()),
                    Some(username_hash.as_search_key()),
                    SystemTime::now(),
                )
                .encode_to_vec();
            println!("Stored account data:");
            println!(
                "const STORED_ACCOUNT_DATA_{}: &[u8] = &hex!(\"{}\");",
                last_tree_size,
                hex::encode(stored_account_data)
            );
        }

        prompt("Now advance the tree. Yes, again! (and press ENTER)");

        let raw_request = RawChatSearchRequest::new(
            &aci,
            &aci_identity_key,
            Some(&e164),
            Some(&username_hash),
            Some(account_data.last_tree_head.0.tree_size),
            distinguished_tree.0.tree_size,
        );
        let response_bytes = chat
            .send_kt_request(raw_request.into())
            .await
            .expect("can send raw search request");

        {
            let search_response = ChatSearchResponse::decode(response_bytes.as_ref())
                .map_err(|_| Error::InvalidResponse("bad protobuf".to_string()))
                .and_then(TypedSearchResponse::from_untyped)
                .expect("valid search response");

            let tree_size = search_response.full_tree_head.tree_head.unwrap().tree_size;
            assert_ne!(last_tree_size, tree_size, "The tree did not advance!");
        }

        println!(
            "Update the net/tests/data/chat_response_valid_at.in file to: `Duration::from_secs({})`",
            SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs()
        );

        const PATH: &str = "/tmp/chat_search_response.dat";
        println!("Response written to '{PATH}'");
        std::fs::write(PATH, &response_bytes).unwrap()
    }
}
