//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::cmp::Ordering;

use assert_matches::assert_matches;
use async_trait::async_trait;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{AccountData, LastTreeHead, LocalStateUpdate};
use libsignal_net::chat::{ChatConnection, GrpcBody};
use libsignal_net::infra::http_client::Http2Client;
use libsignal_protocol::{IdentityKeyPair, PublicKey};
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use test_case::test_case;

use crate::api::keytrans::test_support::{
    NETWORK_RETRY_COUNT, make_chat, make_kt, retry_n, should_retry, test_account,
    test_account_data, test_distinguished_tree,
};
use crate::api::keytrans::{Error, LowLevelChatApi, UnauthenticatedChatApi as _, UsernameHash};
use crate::api::{RequestError, Unauth};
use crate::grpc::keytrans::KtOverGrpc;

fn kt_integration_enabled() -> bool {
    let run_nonhermetic = std::env::var_os("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_some();
    let ignore_tests = std::env::var_os("LIBSIGNAL_TESTING_IGNORE_KT_TESTS").is_some();
    run_nonhermetic && !ignore_tests
}

#[derive(Copy, Clone, Debug)]
enum Transport {
    Ws,
    Grpc,
}

impl Transport {
    fn permission_denied_message(self) -> &'static str {
        match self {
            Transport::Ws => "unexpected response status 403 Forbidden",
            Transport::Grpc => "key transparency permission denied",
        }
    }
}

/// A connection to send key transparency requests over, either way.
///
/// The `ChatConnection` is held even in the gRPC case. `shared_h2_connection` hands out a cloned
/// handle to a connection the `ChatConnection` owns, so keeping the owner alive avoids depending on
/// what happens to that connection when it drops.
struct AnyTransport {
    chat: Unauth<ChatConnection>,
    grpc: Option<KtOverGrpc<Http2Client<GrpcBody>>>,
}

impl AnyTransport {
    async fn new(transport: Transport) -> AnyTransport {
        let chat = make_chat().await;
        let grpc = match transport {
            Transport::Ws => None,
            Transport::Grpc => Some(KtOverGrpc(
                chat.0
                    .shared_h2_connection()
                    .expect("chat connection provides HTTP/2"),
            )),
        };
        AnyTransport { chat, grpc }
    }
}

/// Sends over whichever implementation this `AnyTransport` was built for.
///
/// Written out rather than generated so that adding a method to [`LowLevelChatApi`] forces a
/// decision here too.
#[async_trait]
impl LowLevelChatApi for AnyTransport {
    async fn search(
        &self,
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<&(E164, Vec<u8>)>,
        username_hash: Option<&UsernameHash<'_>>,
        stored_account_data: Option<&AccountData>,
        distinguished_tree_head: &LastTreeHead,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        match &self.grpc {
            Some(grpc) => {
                grpc.search(
                    aci,
                    aci_identity_key,
                    e164,
                    username_hash,
                    stored_account_data,
                    distinguished_tree_head,
                )
                .await
            }
            None => {
                self.chat
                    .search(
                        aci,
                        aci_identity_key,
                        e164,
                        username_hash,
                        stored_account_data,
                        distinguished_tree_head,
                    )
                    .await
            }
        }
    }

    async fn distinguished(
        &self,
        last_distinguished: Option<&LastTreeHead>,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        match &self.grpc {
            Some(grpc) => grpc.distinguished(last_distinguished).await,
            None => self.chat.distinguished(last_distinguished).await,
        }
    }

    async fn monitor(
        &self,
        aci: &Aci,
        e164: Option<&E164>,
        username_hash: Option<&UsernameHash<'_>>,
        account_data: &AccountData,
        last_distinguished_tree_head: &LastTreeHead,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        match &self.grpc {
            Some(grpc) => {
                grpc.monitor(
                    aci,
                    e164,
                    username_hash,
                    account_data,
                    last_distinguished_tree_head,
                )
                .await
            }
            None => {
                self.chat
                    .monitor(
                        aci,
                        e164,
                        username_hash,
                        account_data,
                        last_distinguished_tree_head,
                    )
                    .await
            }
        }
    }
}

#[tokio::test]
#[test_case(Transport::Ws, false, false; "ws: ACI")]
#[test_case(Transport::Ws, true, false; "ws: ACI + E164")]
#[test_case(Transport::Ws, false, true; "ws: ACI + Username Hash")]
#[test_case(Transport::Ws, true, true; "ws: ACI + E164 + Username Hash")]
#[test_case(Transport::Grpc, false, false; "grpc: ACI")]
#[test_case(Transport::Grpc, true, false; "grpc: ACI + E164")]
#[test_case(Transport::Grpc, false, true; "grpc: ACI + Username Hash")]
#[test_case(Transport::Grpc, true, true; "grpc: ACI + E164 + Username Hash")]
async fn search_permutations_integration_test(
    transport: Transport,
    use_e164: bool,
    use_username_hash: bool,
) {
    if !kt_integration_enabled() {
        println!("SKIPPED: running integration tests is not enabled");
        return;
    }
    retry_n(
        NETWORK_RETRY_COUNT,
        || async {
            let sender = AnyTransport::new(transport).await;
            let kt = make_kt(&sender);

            let aci = test_account::aci();
            let aci_identity_key = test_account::aci_identity_key();
            let e164 = (
                test_account::PHONE_NUMBER,
                test_account::UNIDENTIFIED_ACCESS_KEY.to_vec(),
            );
            let username_hash = test_account::username_hash();

            let known_account_data = test_account_data();

            kt.search(
                &aci,
                &aci_identity_key,
                use_e164.then_some(e164),
                use_username_hash.then_some(username_hash),
                Some(known_account_data),
                &test_distinguished_tree(),
            )
            .await
        },
        should_retry,
    )
    .await
    .expect("can search");
}

#[tokio::test]
#[test_case(Transport::Ws; "websocket")]
#[test_case(Transport::Grpc; "grpc")]
async fn search_with_version_integration_test(transport: Transport) {
    if !kt_integration_enabled() {
        println!("SKIPPED: running integration tests is not enabled");
        return;
    }
    retry_n(
        NETWORK_RETRY_COUNT,
        || async {
            let sender = AnyTransport::new(transport).await;
            let kt = make_kt(&sender);

            kt.search(
                &test_account::aci(),
                &test_account::aci_identity_key(),
                Some(test_account::e164_pair()),
                Some(test_account::username_hash()),
                None,
                &test_distinguished_tree(),
            )
            .await
        },
        should_retry,
    )
    .await
    .expect("can search with version");
}

#[tokio::test]
#[test_case(Transport::Ws, false; "ws: unknown_distinguished")]
#[test_case(Transport::Ws, true; "ws: known_distinguished")]
#[test_case(Transport::Grpc, false; "grpc: unknown_distinguished")]
#[test_case(Transport::Grpc, true; "grpc: known_distinguished")]
async fn distinguished_integration_test(transport: Transport, have_last_distinguished: bool) {
    if !kt_integration_enabled() {
        println!("SKIPPED: running integration tests is not enabled");
        return;
    }

    let result = retry_n(
        NETWORK_RETRY_COUNT,
        || async {
            let sender = AnyTransport::new(transport).await;
            let kt = make_kt(&sender);

            kt.distinguished(have_last_distinguished.then_some(test_distinguished_tree()))
                .await
        },
        should_retry,
    )
    .await;

    assert_matches!(result, Ok( LocalStateUpdate {tree_head, ..}) => assert_ne!(tree_head.tree_size, 0));
}

#[tokio::test]
#[test_case(Transport::Ws, false, false; "ws: ACI")]
#[test_case(Transport::Ws, true, false; "ws: ACI + E164")]
#[test_case(Transport::Ws, false, true; "ws: ACI + Username Hash")]
#[test_case(Transport::Ws, true, true; "ws: ACI + E164 + Username Hash")]
#[test_case(Transport::Grpc, false, false; "grpc: ACI")]
#[test_case(Transport::Grpc, true, false; "grpc: ACI + E164")]
#[test_case(Transport::Grpc, false, true; "grpc: ACI + Username Hash")]
#[test_case(Transport::Grpc, true, true; "grpc: ACI + E164 + Username Hash")]
async fn monitor_permutations_integration_test(
    transport: Transport,
    use_e164: bool,
    use_username_hash: bool,
) {
    if !kt_integration_enabled() {
        println!("SKIPPED: running integration tests is not enabled");
        return;
    }

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

    let updated_account_data = retry_n(
        NETWORK_RETRY_COUNT,
        || async {
            let sender = AnyTransport::new(transport).await;
            let kt = make_kt(&sender);

            kt.monitor(
                &aci,
                use_e164.then_some(e164),
                use_username_hash.then_some(username_hash.clone()),
                account_data.clone(),
                &test_distinguished_tree(),
            )
            .await
        },
        should_retry,
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

/// Searches for `aci`/`aci_identity_key` over `transport` and asserts the server refused.
async fn assert_search_permission_denied(
    transport: Transport,
    aci: &Aci,
    aci_identity_key: &PublicKey,
) {
    let sender = AnyTransport::new(transport).await;
    let result = make_kt(&sender)
        .search(
            aci,
            aci_identity_key,
            None,
            None,
            None,
            &test_distinguished_tree(),
        )
        .await;

    assert_matches!(
        result,
        Err(RequestError::Unexpected { log_safe: msg })
            if msg == transport.permission_denied_message()
    );
}

#[tokio::test]
#[test_case(Transport::Ws; "websocket")]
#[test_case(Transport::Grpc; "grpc")]
async fn search_with_wrong_identity_key_integration(transport: Transport) {
    if !kt_integration_enabled() {
        println!("SKIPPED: running integration tests is not enabled");
        return;
    }

    let wrong_identity_key = {
        let mut rng = OsRng.unwrap_err();
        let key_pair = IdentityKeyPair::generate(&mut rng);
        *key_pair.public_key()
    };

    assert_search_permission_denied(transport, &test_account::aci(), &wrong_identity_key).await;
}

#[tokio::test]
#[test_case(Transport::Ws; "websocket")]
#[test_case(Transport::Grpc; "grpc")]
async fn search_for_account_that_isnt(transport: Transport) {
    if !kt_integration_enabled() {
        println!("SKIPPED: running integration tests is not enabled");
        return;
    }

    let aci = Aci::from(uuid::uuid!("00000000-0000-0000-0000-000000000000"));

    assert_search_permission_denied(transport, &aci, &test_account::aci_identity_key()).await;
}
