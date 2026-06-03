//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use libsignal_core::curve::PublicKey;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{
    AccountData, CondensedTreeSearchResponse, FullSearchResponse, FullTreeHead, KeyTransparency,
    LastTreeHead, LocalStateUpdate, MonitoringData, SearchContext, SlimSearchRequest,
    VerifiedSearchResult,
};
use subtle::ConstantTimeEq as _;

use super::{AccountDataField, Error, MaybePartial, SearchKey, TypedSearchResponse, UsernameHash};

pub(super) trait KeyTransparencyVerifyExt {
    #[expect(clippy::too_many_arguments)]
    fn verify_single_search_response(
        &self,
        search_key: Vec<u8>,
        expected_value: &[u8],
        response: CondensedTreeSearchResponse,
        monitoring_data: Option<MonitoringData>,
        full_tree_head: &FullTreeHead,
        last_tree_head: Option<&LastTreeHead>,
        last_distinguished_tree_head: Option<&LastTreeHead>,
        now: SystemTime,
    ) -> Result<VerifiedSearchResult, Error>;

    #[expect(clippy::too_many_arguments)]
    fn verify_chat_search_response(
        &self,
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<E164>,
        username_hash: Option<UsernameHash>,
        stored_account_data: Option<AccountData>,
        chat_search_response: TypedSearchResponse,
        last_distinguished_tree_head: Option<&LastTreeHead>,
        now: SystemTime,
    ) -> Result<MaybePartial<AccountData>, Error>;
}

impl KeyTransparencyVerifyExt for KeyTransparency {
    fn verify_single_search_response(
        &self,
        search_key: Vec<u8>,
        expected_value: &[u8],
        response: CondensedTreeSearchResponse,
        monitoring_data: Option<MonitoringData>,
        full_tree_head: &FullTreeHead,
        last_tree_head: Option<&LastTreeHead>,
        last_distinguished_tree_head: Option<&LastTreeHead>,
        now: SystemTime,
    ) -> Result<VerifiedSearchResult, Error> {
        let result = self.verify_search(
            SlimSearchRequest {
                search_key,
                version: None,
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
        SearchValue(&result.value).check_equal(expected_value)?;
        Ok(result)
    }

    fn verify_chat_search_response(
        &self,
        aci: &Aci,
        aci_identity_key: &PublicKey,
        e164: Option<E164>,
        username_hash: Option<UsernameHash>,
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

        let aci_result = self.verify_single_search_response(
            aci.as_search_key(),
            aci_identity_key.serialize().as_ref(),
            aci_search_response,
            aci_monitoring_data,
            &full_tree_head,
            stored_last_tree_head.as_ref(),
            last_distinguished_tree_head,
            now,
        )?;

        let e164_result =
            match_optional_fields(e164, e164_search_response, AccountDataField::E164)?
                .map(|non_partial| {
                    non_partial
                        .map(|(e164, e164_search_response)| {
                            self.verify_single_search_response(
                                e164.as_search_key(),
                                aci.service_id_binary().as_slice(),
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
                    self.verify_single_search_response(
                        username_hash.as_search_key(),
                        aci.service_id_binary().as_slice(),
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
            last_tree_head: LastTreeHead(tree_head, tree_root),
        };

        Ok(MaybePartial {
            inner: updated_account_data,
            missing_fields,
        })
    }
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

struct SearchValue<T>(T);

impl<T: AsRef<[u8]>> SearchValue<T> {
    const VERSION: u8 = 0;

    fn as_bytes(&self) -> Option<&[u8]> {
        self.0
            .as_ref()
            .split_first()
            .filter(|(version, _)| **version == Self::VERSION)
            .map(|(_, value)| value)
    }

    pub fn check_equal(self, expected: &[u8]) -> Result<(), Error> {
        self.as_bytes()
            .filter(|returned| bool::from(returned.ct_eq(expected)))
            .map(|_| ())
            .ok_or_else(|| {
                libsignal_keytrans::Error::VerificationFailed("unexpected search value".to_string())
                    .into()
            })
    }
}
