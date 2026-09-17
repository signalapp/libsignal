//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{AccountData, LastTreeHead};
use libsignal_net_grpc::proto::kt_query::key_transparency_query_service_client::KeyTransparencyQueryServiceClient;
use libsignal_net_grpc::proto::kt_query::{
    AciMonitorRequest, ConsistencyParameters, DistinguishedRequest, E164MonitorRequest,
    E164SearchRequest, MonitorRequest, MonitorResponseV2, SearchRequest, SearchResponseV2,
    UsernameHashMonitorRequest, monitor_response_v2, search_response_v2,
};
use libsignal_protocol::PublicKey;
use prost::Message as _;

use crate::api::RequestError;
use crate::api::keytrans::{Error, LowLevelChatApi, UsernameHash, resolve_monitor};
use crate::grpc::{GrpcServiceProvider, log_and_send};

// Matches the log tag the websocket implementation uses, so KT requests stay
// greppable across the transport switch.
const LOG_TAG: &str = "kt";

/// Provides the gRPC implementation of [`LowLevelChatApi`].
///
/// This is a dedicated wrapper rather than [`crate::api::Unauth`], which is what the
/// other gRPC services use. `LowLevelChatApi` has no transport marker parameter
/// (it is used as a `dyn` by [`crate::api::keytrans::KeyTransparencyClient`]), so a
/// second blanket impl on `Unauth` would overlap with the [`crate::ws::WsConnection`].
pub struct KtOverGrpc<P>(pub P);

impl<P: GrpcServiceProvider> KtOverGrpc<P> {
    fn client(&self) -> KeyTransparencyQueryServiceClient<P::Service> {
        KeyTransparencyQueryServiceClient::new(self.0.service())
    }
}

// The server declined to answer because the request did not carry the right set of
// data, e.g. an ACI paired with the wrong identity key.
//
// The websocket mechanism for it would be a 403 HTTP status code, which turns
// into `RequestError::Unexpected`. This way we keep the behavior consistent
// between transports (only the actual error message differs).
fn permission_denied<T>() -> Result<T, RequestError<Error>> {
    Err(RequestError::Unexpected {
        log_safe: "key transparency permission denied".to_owned(),
    })
}

// Unreachable from a correct server, but the protobuf `oneof` is optional.
// Deliberately worded differently from [`permission_denied`] so a server bug is
// distinguishable from a legitimate denial in logs.
fn missing_response<T>() -> Result<T, RequestError<Error>> {
    Err(RequestError::Unexpected {
        log_safe: "key transparency response had no response field".to_owned(),
    })
}

#[async_trait]
impl<P: GrpcServiceProvider> LowLevelChatApi for KtOverGrpc<P> {
    async fn search(
        &self,
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<&(E164, Vec<u8>)>,
        username_hash: Option<&UsernameHash<'_>>,
        stored_account_data: Option<&AccountData>,
        distinguished_tree_head: &LastTreeHead,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        let request = SearchRequest {
            aci: aci.service_id_binary(),
            aci_identity_key: aci_identity_key.serialize().into_vec(),
            username_hash: username_hash.map(|hash| hash.as_ref().to_vec()),
            e164_search_request: e164.map(|(e164, unidentified_access_key)| E164SearchRequest {
                e164: Some(e164.to_string()),
                unidentified_access_key: unidentified_access_key.clone(),
            }),
            consistency: Some(ConsistencyParameters {
                last: stored_account_data.map(|data| data.last_tree_head.0.tree_size),
                distinguished: distinguished_tree_head.0.tree_size,
            }),
        };

        let mut client = self.client();
        let SearchResponseV2 { response } =
            log_and_send(LOG_TAG, "search", || client.search_v2(request))
                .await?
                .into_inner();

        match response {
            Some(search_response_v2::Response::SearchResponse(inner)) => Ok(inner.encode_to_vec()),
            Some(search_response_v2::Response::PermissionDenied(_)) => permission_denied(),
            None => missing_response(),
        }
    }

    async fn distinguished(
        &self,
        last_distinguished: Option<&LastTreeHead>,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        let request = DistinguishedRequest {
            last: last_distinguished.map(|tree_head| tree_head.0.tree_size),
        };

        let mut client = self.client();
        let response = log_and_send(LOG_TAG, "distinguished", || {
            client.distinguished_v2(request)
        })
        .await?
        .into_inner();

        Ok(response.encode_to_vec())
    }

    async fn monitor(
        &self,
        aci: &Aci,
        e164: Option<&E164>,
        username_hash: Option<&UsernameHash<'_>>,
        account_data: &AccountData,
        last_distinguished_tree_head: &LastTreeHead,
    ) -> Result<Vec<u8>, RequestError<Error>> {
        let e164 =
            resolve_monitor(e164, account_data.e164.as_ref()).map_err(RequestError::Other)?;
        let username_hash = resolve_monitor(username_hash, account_data.username_hash.as_ref())
            .map_err(RequestError::Other)?;

        let request = MonitorRequest {
            aci: Some(AciMonitorRequest {
                aci: aci.service_id_binary(),
                entry_position: account_data.aci.latest_log_position(),
                commitment_index: account_data.aci.index.to_vec(),
            }),
            username_hash: username_hash.map(|monitor| UsernameHashMonitorRequest {
                username_hash: monitor.value.as_ref().to_vec(),
                entry_position: monitor.entry_position,
                commitment_index: monitor.commitment_index.to_vec(),
            }),
            e164: e164.map(|monitor| E164MonitorRequest {
                e164: monitor.value.to_string(),
                entry_position: monitor.entry_position,
                commitment_index: monitor.commitment_index.to_vec(),
            }),
            consistency: Some(ConsistencyParameters {
                last: Some(account_data.last_tree_head.0.tree_size),
                distinguished: last_distinguished_tree_head.0.tree_size,
            }),
        };

        let mut client = self.client();
        let MonitorResponseV2 { response } =
            log_and_send(LOG_TAG, "monitor", || client.monitor_v2(request))
                .await?
                .into_inner();

        match response {
            Some(monitor_response_v2::Response::MonitorResponse(inner)) => {
                Ok(inner.encode_to_vec())
            }
            Some(monitor_response_v2::Response::PermissionDenied(_)) => permission_denied(),
            None => missing_response(),
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use futures_util::FutureExt as _;
    use libsignal_net_grpc::proto::chat::services;
    use libsignal_net_grpc::proto::kt_query;
    use test_case::{test_case, test_matrix};

    use super::*;
    use crate::api::Unauth;
    use crate::api::keytrans::test_support::{
        test_account, test_account_data, test_distinguished_tree,
    };
    use crate::grpc::testutil::{GrpcOverrideRequestValidator, RequestValidator, err, ok, req};

    const SEARCH_PATH: &str = "/kt_query.KeyTransparencyQueryService/SearchV2";
    const DISTINGUISHED_PATH: &str = "/kt_query.KeyTransparencyQueryService/DistinguishedV2";
    const MONITOR_PATH: &str = "/kt_query.KeyTransparencyQueryService/MonitorV2";

    fn expected_search_request(
        use_e164: bool,
        use_username_hash: bool,
        last: Option<u64>,
    ) -> SearchRequest {
        SearchRequest {
            aci: test_account::ACI.as_bytes().to_vec(),
            aci_identity_key: test_account::ACI_IDENTITY_KEY_BYTES.to_vec(),
            username_hash: use_username_hash.then(|| test_account::USERNAME_HASH.to_vec()),
            e164_search_request: use_e164.then(|| E164SearchRequest {
                e164: Some("+18005550100".to_owned()),
                unidentified_access_key: test_account::UNIDENTIFIED_ACCESS_KEY.to_vec(),
            }),
            consistency: Some(ConsistencyParameters {
                last,
                distinguished: test_distinguished_tree().0.tree_size,
            }),
        }
    }

    #[test_matrix([false, true], [false, true], [false, true])]
    fn search_builds_valid_request(
        use_e164: bool,
        use_username_hash: bool,
        has_stored_account_data: bool,
    ) {
        let e164_pair = test_account::e164_pair();
        let username_hash = test_account::username_hash();
        let account_data = test_account_data();

        let expected_last =
            has_stored_account_data.then_some(account_data.last_tree_head.0.tree_size);

        let validator = RequestValidator {
            expected: req(
                SEARCH_PATH,
                expected_search_request(use_e164, use_username_hash, expected_last),
            ),
            // Response content is irrelevant, as long as it's a success.
            response: ok(SearchResponseV2 {
                response: Some(search_response_v2::Response::SearchResponse(
                    Default::default(),
                )),
            }),
        };

        KtOverGrpc(&validator)
            .search(
                &test_account::aci(),
                &test_account::aci_identity_key(),
                use_e164.then_some(&e164_pair),
                use_username_hash.then_some(&username_hash),
                has_stored_account_data.then_some(&account_data),
                &test_distinguished_tree(),
            )
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    #[test_case(false; "no previous distinguished tree")]
    #[test_case(true; "with previous distinguished tree")]
    fn distinguished_builds_valid_request(with_previous_tree: bool) {
        let tree = test_distinguished_tree();
        let expected_last = with_previous_tree.then_some(tree.0.tree_size);

        let validator = RequestValidator {
            expected: req(
                DISTINGUISHED_PATH,
                DistinguishedRequest {
                    last: expected_last,
                },
            ),
            response: ok(kt_query::DistinguishedResponse::default()),
        };

        KtOverGrpc(&validator)
            .distinguished(with_previous_tree.then_some(&tree))
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    // Choice whether to monitor a field is made based on what's in the account
    // data, just like in the actual implementation.
    fn expected_monitor_request(
        account_data: &AccountData,
        distinguished_tree: &LastTreeHead,
    ) -> MonitorRequest {
        MonitorRequest {
            aci: Some(AciMonitorRequest {
                aci: test_account::ACI.as_bytes().to_vec(),
                entry_position: account_data.aci.latest_log_position(),
                commitment_index: account_data.aci.index.to_vec(),
            }),
            username_hash: account_data.username_hash.as_ref().map(|stored| {
                UsernameHashMonitorRequest {
                    username_hash: test_account::USERNAME_HASH.to_vec(),
                    entry_position: stored.latest_log_position(),
                    commitment_index: stored.index.to_vec(),
                }
            }),
            e164: account_data.e164.as_ref().map(|stored| E164MonitorRequest {
                e164: "+18005550100".to_owned(),
                entry_position: stored.latest_log_position(),
                commitment_index: stored.index.to_vec(),
            }),
            consistency: Some(ConsistencyParameters {
                // Always present for monitor, unlike search.
                last: Some(account_data.last_tree_head.0.tree_size),
                distinguished: distinguished_tree.0.tree_size,
            }),
        }
    }

    #[test_matrix([false, true], [false, true])]
    fn monitor_builds_valid_request(use_e164: bool, use_username_hash: bool) {
        let mut account_data = test_account_data();
        if !use_e164 {
            account_data.e164 = None;
        }
        if !use_username_hash {
            account_data.username_hash = None;
        }

        let validator = RequestValidator {
            expected: req(
                MONITOR_PATH,
                expected_monitor_request(&account_data, &test_distinguished_tree()),
            ),
            // Response content is irrelevant, as long as it's a success.
            response: ok(MonitorResponseV2 {
                response: Some(monitor_response_v2::Response::MonitorResponse(
                    Default::default(),
                )),
            }),
        };

        let username_hash = test_account::username_hash();
        KtOverGrpc(&validator)
            .monitor(
                &test_account::aci(),
                use_e164.then_some(&test_account::PHONE_NUMBER),
                use_username_hash.then_some(&username_hash),
                &account_data,
                &test_distinguished_tree(),
            )
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    #[test_case(true, false; "asked for e164 that is not stored")]
    #[test_case(false, true; "asked for username hash that is not stored")]
    fn monitor_rejects_account_data_mismatch(use_e164: bool, use_username_hash: bool) {
        let mut account_data = test_account_data();
        account_data.e164 = None;
        account_data.username_hash = None;

        let username_hash = test_account::username_hash();
        let result = KtOverGrpc(&crate::grpc::testutil::UnreachableValidator)
            .monitor(
                &test_account::aci(),
                use_e164.then_some(&test_account::PHONE_NUMBER),
                use_username_hash.then_some(&username_hash),
                &account_data,
                &test_distinguished_tree(),
            )
            .now_or_never()
            .expect("sync")
            .expect_err("should reject");

        assert_matches!(
            result,
            RequestError::Other(Error::InvalidRequest(msg))
                if msg == "account data does not match the monitor request"
        );
    }

    // `LowLevelChatApi` methods return encoded protobuf, which the caller decodes as
    // `libsignal_keytrans::ChatSearchResponse`. Those bytes have to be the `SearchResponse` from
    // inside the `oneof`, not the `SearchResponseV2` wrapping it
    #[test]
    fn search_returns_inner_response() {
        let inner = make_search_response();
        let validator = RequestValidator {
            expected: req(SEARCH_PATH, expected_search_request(false, false, None)),
            response: ok(SearchResponseV2 {
                response: Some(search_response_v2::Response::SearchResponse(inner.clone())),
            }),
        };
        assert_eq!(
            simple_search(&validator).expect("success"),
            inner.encode_to_vec()
        );
    }

    #[test]
    fn monitor_returns_inner_response() {
        let account_data = test_account_data();
        let inner = make_monitor_response();
        let validator = RequestValidator {
            expected: req(
                MONITOR_PATH,
                expected_monitor_request(&account_data, &test_distinguished_tree()),
            ),
            response: ok(MonitorResponseV2 {
                response: Some(monitor_response_v2::Response::MonitorResponse(
                    inner.clone(),
                )),
            }),
        };

        let username_hash = test_account::username_hash();
        let result = KtOverGrpc(&validator)
            .monitor(
                &test_account::aci(),
                Some(&test_account::PHONE_NUMBER),
                Some(&username_hash),
                &account_data,
                &test_distinguished_tree(),
            )
            .now_or_never()
            .expect("sync")
            .expect("success");

        assert_eq!(result, inner.encode_to_vec());
    }

    // One remote config key gates all three methods, so each one has to consult it.
    // `GrpcOverrideRequestValidator` panics if the websocket is used at all, and asserts the
    // override name it was handed matches.

    fn override_validator(
        expected: http::Request<Vec<u8>>,
        response: http::Response<libsignal_net::chat::fake::BodyWithTrailers>,
    ) -> GrpcOverrideRequestValidator<RequestValidator<libsignal_net::chat::fake::BodyWithTrailers>>
    {
        GrpcOverrideRequestValidator {
            message: services::KeyTransparencyQueryService::SearchV2.into(),
            validator: RequestValidator { expected, response },
        }
    }

    #[test]
    fn search_dispatches_to_grpc() {
        let validator = override_validator(
            req(SEARCH_PATH, expected_search_request(false, false, None)),
            ok(SearchResponseV2 {
                response: Some(search_response_v2::Response::SearchResponse(
                    Default::default(),
                )),
            }),
        );

        Unauth(&validator)
            .search(
                &test_account::aci(),
                &test_account::aci_identity_key(),
                None,
                None,
                None,
                &test_distinguished_tree(),
            )
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    #[test]
    fn distinguished_dispatches_to_grpc() {
        let tree = test_distinguished_tree();
        let validator = override_validator(
            req(
                DISTINGUISHED_PATH,
                DistinguishedRequest {
                    last: Some(tree.0.tree_size),
                },
            ),
            ok(kt_query::DistinguishedResponse::default()),
        );

        Unauth(&validator)
            .distinguished(Some(&tree))
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    #[test]
    fn monitor_dispatches_to_grpc() {
        let account_data = test_account_data();
        let tree = test_distinguished_tree();
        let validator = override_validator(
            req(MONITOR_PATH, expected_monitor_request(&account_data, &tree)),
            ok(MonitorResponseV2 {
                response: Some(monitor_response_v2::Response::MonitorResponse(
                    Default::default(),
                )),
            }),
        );

        let username_hash = test_account::username_hash();
        Unauth(&validator)
            .monitor(
                &test_account::aci(),
                Some(&test_account::PHONE_NUMBER),
                Some(&username_hash),
                &account_data,
                &tree,
            )
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    #[test]
    fn search_permission_denied() {
        let validator = RequestValidator {
            expected: req(SEARCH_PATH, expected_search_request(false, false, None)),
            response: ok(SearchResponseV2 {
                response: Some(search_response_v2::Response::PermissionDenied(
                    kt_query::PermissionDenied {},
                )),
            }),
        };
        assert_matches!(
            simple_search(&validator),
            Err(RequestError::Unexpected { log_safe })
                if log_safe == "key transparency permission denied"
        );
    }

    // An unset `oneof` cannot come from a correct server, but it is representable
    // on the wire, so we must handle it.
    #[test]
    fn search_missing_response_field() {
        let validator = RequestValidator {
            expected: req(SEARCH_PATH, expected_search_request(false, false, None)),
            response: ok(SearchResponseV2 { response: None }),
        };
        assert_matches!(
            simple_search(&validator),
            Err(RequestError::Unexpected { log_safe })
                if log_safe == "key transparency response had no response field"
        );
    }

    #[test]
    fn search_maps_transport_error() {
        let validator = RequestValidator {
            expected: req(SEARCH_PATH, expected_search_request(false, false, None)),
            response: err(tonic::Code::DeadlineExceeded),
        };
        assert_matches!(simple_search(&validator), Err(RequestError::Timeout));
    }

    fn simple_search<T>(validator: &RequestValidator<T>) -> Result<Vec<u8>, RequestError<Error>>
    where
        for<'a> &'a RequestValidator<T>: GrpcServiceProvider,
    {
        KtOverGrpc(validator)
            .search(
                &test_account::aci(),
                &test_account::aci_identity_key(),
                None,
                None,
                None,
                &test_distinguished_tree(),
            )
            .now_or_never()
            .expect("sync")
    }

    fn make_full_tree_head() -> kt_query::FullTreeHead {
        kt_query::FullTreeHead {
            tree_head: Some(kt_query::TreeHead {
                tree_size: 111_000,
                timestamp: 1234567890,
                signatures: vec![kt_query::Signature {
                    auditor_public_key: vec![1, 2, 3],
                    signature: vec![4, 5, 6],
                }],
            }),
            last: vec![vec![7, 8], vec![9]],
            distinguished: vec![vec![10, 11]],
            full_auditor_tree_heads: vec![kt_query::FullAuditorTreeHead {
                tree_head: Some(kt_query::AuditorTreeHead {
                    tree_size: 222_000,
                    timestamp: 987654321,
                    signature: vec![12, 13],
                }),
                root_value: Some(vec![14, 15]),
                consistency: vec![vec![16], vec![17, 18]],
                public_key: vec![19, 20],
            }],
        }
    }

    trait WithTag {
        fn with_tag(tag: u32) -> Self;
    }

    trait Untag {
        fn get_tag(&self) -> u32;
    }

    impl WithTag for kt_query::CondensedTreeSearchResponse {
        fn with_tag(tag: u32) -> Self {
            Self {
                vrf_proof: vec![21, 22],
                search: Some(kt_query::SearchProof {
                    pos: u64::from(tag),
                    steps: vec![kt_query::ProofStep {
                        prefix: Some(kt_query::PrefixSearchResult {
                            proof: vec![vec![23], vec![24, 25]],
                            counter: tag,
                        }),
                        commitment: vec![26, 27],
                    }],
                    inclusion: vec![vec![28], vec![29, 30]],
                }),
                opening: vec![31, 32],
                value: Some(kt_query::UpdateValue {
                    value: vec![33, 34],
                }),
            }
        }
    }

    impl Untag for libsignal_keytrans::CondensedTreeSearchResponse {
        fn get_tag(&self) -> u32 {
            self.search
                .as_ref()
                .expect("search proof")
                .steps
                .first()
                .expect("one step")
                .prefix
                .as_ref()
                .expect("prefix")
                .counter
        }
    }

    impl WithTag for kt_query::MonitorProof {
        fn with_tag(tag: u32) -> Self {
            Self {
                steps: vec![kt_query::ProofStep {
                    prefix: Some(kt_query::PrefixSearchResult {
                        proof: vec![vec![35, 36]],
                        counter: tag,
                    }),
                    commitment: vec![37],
                }],
            }
        }
    }

    impl Untag for libsignal_keytrans::MonitorProof {
        fn get_tag(&self) -> u32 {
            self.steps
                .first()
                .expect("one step")
                .prefix
                .as_ref()
                .expect("prefix")
                .counter
        }
    }

    const ACI_TAG: u32 = 111;
    const E164_TAG: u32 = 222;
    const USERNAME_HASH_TAG: u32 = 333;

    fn make_search_response() -> kt_query::SearchResponse {
        kt_query::SearchResponse {
            tree_head: Some(make_full_tree_head()),
            aci: Some(kt_query::CondensedTreeSearchResponse::with_tag(ACI_TAG)),
            e164: Some(kt_query::CondensedTreeSearchResponse::with_tag(E164_TAG)),
            username_hash: Some(kt_query::CondensedTreeSearchResponse::with_tag(
                USERNAME_HASH_TAG,
            )),
        }
    }

    fn make_monitor_response() -> kt_query::MonitorResponse {
        kt_query::MonitorResponse {
            tree_head: Some(make_full_tree_head()),
            aci: Some(kt_query::MonitorProof::with_tag(ACI_TAG)),
            username_hash: Some(kt_query::MonitorProof::with_tag(USERNAME_HASH_TAG)),
            e164: Some(kt_query::MonitorProof::with_tag(E164_TAG)),
            inclusion: vec![vec![38], vec![39, 40]],
        }
    }

    // The whole design rests on `kt_query` response messages being wire-identical to the
    // `libsignal_keytrans` ones the verifying client decodes, since this transport re-encodes the
    // former and hands the bytes to the latter. Nothing in the type system checks that, and one
    // message pair does not even share a name (`PrefixSearchResult` vs `PrefixProof`), so assert
    // it directly.
    //
    // Re-encoding after the cross-decode is what makes this strict: prost drops unknown fields, so
    // a diverged field number shows up as a byte mismatch rather than passing silently.
    #[test]
    fn search_response_is_wire_compatible_with_keytrans() {
        let bytes = make_search_response().encode_to_vec();
        let decoded = libsignal_keytrans::ChatSearchResponse::decode(&bytes[..])
            .expect("decodes as the keytrans message");

        // Guard against a vacuous pass: two messages that both decoded to nothing would also
        // compare equal. Check the nested fields actually arrived, and that each landed in the
        // field it was written to rather than a same-typed neighbor.
        let tree_head = decoded.tree_head.as_ref().expect("tree head decoded");
        assert_eq!(
            tree_head.tree_head.as_ref().expect("inner head").tree_size,
            111_000
        );
        assert_eq!(tree_head.full_auditor_tree_heads.len(), 1);
        assert_eq!(
            decoded.aci.as_ref().expect("aci decoded").get_tag(),
            ACI_TAG
        );
        assert_eq!(
            decoded.e164.as_ref().expect("e164 decoded").get_tag(),
            E164_TAG
        );
        assert_eq!(
            decoded
                .username_hash
                .as_ref()
                .expect("username hash decoded")
                .get_tag(),
            USERNAME_HASH_TAG
        );

        assert_eq!(bytes, decoded.encode_to_vec());
    }

    #[test]
    fn distinguished_response_is_wire_compatible_with_keytrans() {
        let bytes = kt_query::DistinguishedResponse {
            tree_head: Some(make_full_tree_head()),
            distinguished: Some(kt_query::CondensedTreeSearchResponse::with_tag(ACI_TAG)),
        }
        .encode_to_vec();
        let decoded = libsignal_keytrans::ChatDistinguishedResponse::decode(&bytes[..])
            .expect("decodes as the keytrans message");

        assert!(decoded.tree_head.is_some());
        let distinguished = decoded
            .distinguished
            .as_ref()
            .expect("distinguished decoded");
        assert_eq!(distinguished.opening, vec![31, 32]);

        assert_eq!(bytes, decoded.encode_to_vec());
    }

    #[test]
    fn monitor_response_is_wire_compatible_with_keytrans() {
        let bytes = make_monitor_response().encode_to_vec();
        let decoded = libsignal_keytrans::ChatMonitorResponse::decode(&bytes[..])
            .expect("decodes as the keytrans message");

        assert!(decoded.tree_head.is_some());
        // Field 3 is username_hash and field 4 is e164 in both protos. Crossing those two would
        // still round-trip byte-identically, so check the tags rather than just `is_some`.
        assert_eq!(decoded.aci.as_ref().expect("aci proof").get_tag(), ACI_TAG);
        assert_eq!(
            decoded
                .username_hash
                .as_ref()
                .expect("username hash proof")
                .get_tag(),
            USERNAME_HASH_TAG
        );
        assert_eq!(
            decoded.e164.as_ref().expect("e164 proof").get_tag(),
            E164_TAG
        );
        assert_eq!(decoded.inclusion, vec![vec![38], vec![39, 40]]);

        assert_eq!(bytes, decoded.encode_to_vec());
    }
}
