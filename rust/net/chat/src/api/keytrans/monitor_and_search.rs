//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::curve::PublicKey;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{AccountData, LastTreeHead, MonitoringData};

use crate::api::RequestError;
use crate::api::keytrans::maybe_partial::MaybePartial;
use crate::api::keytrans::{
    AccountDataField, Error, SearchKey, UnauthenticatedChatApi, UsernameHash,
};

#[derive(Eq, Debug, PartialEq, Clone, Copy)]
pub enum MonitorMode {
    MonitorSelf,
    MonitorOther,
}

/// The main entry point to the module.
pub async fn check(
    kt: &impl UnauthenticatedChatApi,
    aci: &Aci,
    aci_identity_key: &PublicKey,
    e164: Option<(E164, Vec<u8>)>,
    username_hash: Option<UsernameHash<'_>>,
    stored_account_data: AccountData,
    distinguished_tree_head: &LastTreeHead,
    mode: MonitorMode,
) -> Result<MaybePartial<AccountData>, RequestError<Error>> {
    let action = Action::plan(
        aci,
        e164.as_ref(),
        username_hash.as_ref(),
        stored_account_data,
    );

    action
        .execute(kt, aci_identity_key, distinguished_tree_head, mode)
        .await
}

#[cfg_attr(test, derive(Debug, Clone))]
struct Parameters<'a> {
    pub aci: &'a Aci,
    pub e164: Option<&'a (E164, Vec<u8>)>,
    pub username_hash: Option<&'a UsernameHash<'a>>,
}

impl<'a> Parameters<'a> {
    /// Merge optional keys by preferring `other` over `self`.
    /// This is order-sensitive: `a.merge_with(b)` != `b.merge_with(a)`.
    /// `aci` is always taken from `self`.
    fn merge_with(self, other: Parameters<'a>) -> Self {
        debug_assert_eq!(self.aci, other.aci);
        Self {
            aci: self.aci,
            e164: other.e164.or(self.e164),
            username_hash: other.username_hash.or(self.username_hash),
        }
    }
}

#[cfg_attr(test, derive(Debug))]
enum Action<'a> {
    SearchOnly(Parameters<'a>),
    MonitorThenSearch {
        monitor_parameters: Parameters<'a>,
        search_parameters: Parameters<'a>,
        account_data: Box<AccountData>,
    },
}

#[cfg_attr(test, derive(Debug))]
enum PostMonitorAction<'a> {
    None,
    Search {
        parameters: Parameters<'a>,
        // Whether version has changed is important for the construction of the
        // resulting account data. In particular, its ACI field.
        // ACI is a required field for search, so we cannot _not_ send it.
        // At the same time we don't want to use the search result for ACI, if
        // it was successfully monitored and the value version did not change.
        version_change_detected: VersionChanged,
    },
}

#[derive(Debug, Clone, PartialEq)]
struct SearchVersions {
    aci: Option<u32>,
    e164: Option<u32>,
    username_hash: Option<u32>,
}

#[derive(Debug)]
struct VersionDecreased;

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

    fn try_subtract(&self, other: &Self) -> Result<Self, VersionDecreased> {
        fn opt_sub<T>(
            lhs: &T,
            rhs: &T,
            f: impl Fn(&T) -> Option<u32>,
        ) -> Result<Option<u32>, VersionDecreased> {
            if let Some(lhs) = f(lhs)
                && let Some(rhs) = f(rhs)
            {
                if rhs > lhs {
                    return Err(VersionDecreased);
                }
                Ok(Some(lhs - rhs))
            } else {
                Ok(None)
            }
        }

        Ok(Self {
            aci: opt_sub(self, other, |x| x.aci)?,
            e164: opt_sub(self, other, |x| x.e164)?,
            username_hash: opt_sub(self, other, |x| x.username_hash)?,
        })
    }

    fn maximum_version(&self) -> Option<u32> {
        [self.aci, self.e164, self.username_hash]
            .into_iter()
            .flatten()
            .max()
    }
}

impl<'a> Action<'a> {
    /// Plans the top-level, pre-monitor action for monitor_and_search main function (see `check`).
    ///
    /// - If the stored ACI search key does not match the requested ACI, returns `SearchOnly`
    ///   and ignores stored mappings.
    /// - Otherwise returns `MonitorThenSearch`, splitting optional keys between:
    ///   - `monitor_parameters` for mappings that are unchanged and should be monitored.
    ///   - `search_parameters` for mappings that are new, changed, or need re-fetch.
    /// - For dropped/changed optional mappings, clears the corresponding stored monitoring data.
    pub fn plan(
        aci: &'a Aci,
        e164: Option<&'a (E164, Vec<u8>)>,
        username_hash: Option<&'a UsernameHash<'a>>,
        mut stored_account_data: AccountData,
    ) -> Self {
        let AccountData {
            aci: stored_aci,
            e164: stored_e164,
            username_hash: stored_username_hash,
            last_tree_head: _,
        } = &mut stored_account_data;

        // ACI
        {
            if stored_aci.search_key != aci.as_search_key() {
                // This means the clients either passed a totally new ACI
                // or we did not have the ACI search key stored to begin with.
                // Either way, this is considered a dramatic enough scenario
                // to warrant ignoring the stored data and starting from the search.
                return Action::SearchOnly(Parameters {
                    aci,
                    e164,
                    username_hash,
                });
            }
        }

        // Past this line we need to keep monitoring for at least the ACI mapping.

        let mut monitor_parameters = Parameters {
            aci,
            e164: None,
            username_hash: None,
        };
        let mut search_parameters = Parameters {
            // Technically we don't need to search for ACI,
            // but it is a required parameter.
            aci,
            e164: None,
            username_hash: None,
        };

        select_monitor_or_search_for(
            stored_e164,
            e164,
            &mut monitor_parameters.e164,
            &mut search_parameters.e164,
        );
        select_monitor_or_search_for(
            stored_username_hash,
            username_hash,
            &mut monitor_parameters.username_hash,
            &mut search_parameters.username_hash,
        );

        Action::MonitorThenSearch {
            monitor_parameters,
            search_parameters,
            account_data: Box::new(stored_account_data),
        }
    }

    pub async fn execute(
        self,
        kt: &impl UnauthenticatedChatApi,
        aci_identity_key: &PublicKey,
        distinguished_tree_head: &LastTreeHead,
        mode: MonitorMode,
    ) -> Result<MaybePartial<AccountData>, RequestError<Error>> {
        match self {
            Action::SearchOnly(Parameters {
                aci,
                e164,
                username_hash,
            }) => {
                kt.search(
                    aci,
                    aci_identity_key,
                    e164.cloned(),
                    username_hash.cloned(),
                    // Effectively wiping out stored account data
                    None,
                    distinguished_tree_head,
                )
                .await
            }
            Action::MonitorThenSearch {
                monitor_parameters,
                search_parameters,
                account_data,
            } => {
                monitor_then_search(
                    kt,
                    monitor_parameters,
                    search_parameters,
                    *account_data,
                    aci_identity_key,
                    distinguished_tree_head,
                    mode,
                )
                .await
            }
        }
    }
}

// Used in `modify_parameters` to allow the ACI+identity key pair to act like ACI
impl<A: SearchKey, B> SearchKey for (A, B) {
    fn as_search_key(&self) -> Vec<u8> {
        self.0.as_search_key()
    }
}

/// Decides whether to monitor or search for an optional field based on the
/// search key values of the monitoring data for that field and the one being
/// requested by the caller.
///
/// If the requested search key matches the one being stored, the field will
/// be monitored and its stored data will not be changed. in all other cases
/// the monitoring data is dropped, and it will be included in the search request.
fn select_monitor_or_search_for<'a, T: SearchKey>(
    stored_data: &mut Option<MonitoringData>,
    requested: Option<&'a T>,
    monitor_parameter: &mut Option<&'a T>,
    search_parameter: &mut Option<&'a T>,
) {
    let stored_key = stored_data.as_ref().map(|x| &x.search_key);
    let requested_key = requested.as_ref().map(SearchKey::as_search_key);

    if let Some(before) = stored_key
        && let Some(after) = requested_key.as_ref()
        && before == after
    {
        *monitor_parameter = requested;
        *search_parameter = None;
        // stored value remains unchanged
    } else {
        *monitor_parameter = None;
        *search_parameter = requested;
        *stored_data = None;
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
enum VersionChanged {
    No,
    Yes,
}

impl From<bool> for VersionChanged {
    fn from(value: bool) -> Self {
        if value { Self::Yes } else { Self::No }
    }
}

impl From<VersionChanged> for bool {
    fn from(value: VersionChanged) -> Self {
        matches!(value, VersionChanged::Yes)
    }
}

impl<'a> PostMonitorAction<'a> {
    /// Plans the post-monitor action.
    ///
    /// - `MonitorSelf` + version change => `Err`.
    /// - `MonitorOther` + version change => `Search` with merged parameters,
    ///   preferring optional keys from `search_parameters` while falling back
    ///   to `monitor_parameters`.
    /// - No version change
    ///   * `search_parameters` contains optional keys => `Search`.
    ///   *  otherwise => `None`. Monitor is all that was needed.
    fn plan(
        monitor_parameters: Parameters<'a>,
        search_parameters: Parameters<'a>,
        mode: MonitorMode,
        any_version_changed: VersionChanged,
    ) -> Result<Self, RequestError<Error>> {
        // Optional fields should either be monitored or searched for, never both.
        debug_assert!(!(search_parameters.e164.is_some() && monitor_parameters.e164.is_some()));
        debug_assert!(
            !(search_parameters.username_hash.is_some()
                && monitor_parameters.username_hash.is_some())
        );

        match (mode, any_version_changed) {
            (MonitorMode::MonitorSelf, VersionChanged::Yes) => Err(RequestError::Other(
                libsignal_keytrans::Error::VerificationFailed(
                    "version change detected while self-monitoring".to_string(),
                )
                .into(),
            )),
            (_, VersionChanged::Yes) => Ok(PostMonitorAction::Search {
                // Merging of the parameters here covers the case where, for example,
                // we have monitoring data for E.164 mapping, and its version
                // has changed, while the caller at the same time wants to monitor
                // the username hash as well.
                // Without this merge the username hash will not be searched for.
                parameters: monitor_parameters.merge_with(search_parameters),
                version_change_detected: VersionChanged::Yes,
            }),
            (_, VersionChanged::No) => {
                // Even if the monitored versions have not changed, we still may need to perform a search
                // for mappings we were not monitoring previously.
                let should_search =
                    search_parameters.e164.is_some() || search_parameters.username_hash.is_some();
                Ok(if should_search {
                    PostMonitorAction::Search {
                        parameters: search_parameters,
                        version_change_detected: VersionChanged::No,
                    }
                } else {
                    PostMonitorAction::None
                })
            }
        }
    }

    async fn execute(
        self,
        kt: &impl UnauthenticatedChatApi,
        aci_identity_key: &PublicKey,
        distinguished_tree_head: &LastTreeHead,
        account_data: AccountData,
    ) -> Result<MaybePartial<AccountData>, RequestError<Error>> {
        match self {
            PostMonitorAction::None => Ok(account_data.into()),
            PostMonitorAction::Search {
                parameters:
                    Parameters {
                        aci,
                        e164,
                        username_hash,
                    },
                version_change_detected,
            } => {
                let mut search_account_data = kt
                    .search(
                        aci,
                        aci_identity_key,
                        e164.cloned(),
                        username_hash.cloned(),
                        Some(account_data.clone()),
                        distinguished_tree_head,
                    )
                    .await?
                    .map(|post_search_account_data| {
                        merge_account_data(
                            account_data,
                            post_search_account_data,
                            // Preserving the ACI monitoring data only if no version changes detected
                            matches!(version_change_detected, VersionChanged::No),
                        )
                    });

                // If the monitor detects a version change, but the following
                // search does not return the field, it means monitor detected a
                // tombstone, and we don't need to monitor this field further.
                if version_change_detected.into() {
                    remove_missing(&mut search_account_data);
                }

                Ok(search_account_data)
            }
        }
    }
}

/// Removes monitoring data for the fields listed as missing.
fn remove_missing(partial_account_data: &mut MaybePartial<AccountData>) {
    let MaybePartial {
        inner,
        missing_fields,
    } = partial_account_data;
    for field in missing_fields.iter() {
        log::debug!("Version change: untracking {:?}", &field);
        match field {
            AccountDataField::E164 => inner.e164 = None,
            AccountDataField::UsernameHash => inner.username_hash = None,
        }
    }
    missing_fields.clear();
}

/// Merges two instances of AccountData.
///
/// - Values for optional fields are preserved unless `later` contains non-`None`.
/// - Preservation of an ACI value is controlled by `preserve_aci`.
///
/// Should be used to combine the account data instances obtain from monitor
/// (`earlier`) followed by search (`later`).
fn merge_account_data(
    mut earlier: AccountData,
    later: AccountData,
    preserve_aci: bool,
) -> AccountData {
    if !preserve_aci {
        earlier.aci = later.aci;
    }
    // Always prefer latest tree head
    assert!(later.last_tree_head.0.tree_size >= earlier.last_tree_head.0.tree_size);
    earlier.last_tree_head = later.last_tree_head;

    // Do not overwrite "some" monitoring data with nothing.
    // But always update to latest if present.
    if later.e164.is_some() {
        earlier.e164 = later.e164;
    }
    if later.username_hash.is_some() {
        earlier.username_hash = later.username_hash;
    }
    earlier
}

async fn monitor_then_search<'a>(
    kt: &impl UnauthenticatedChatApi,
    monitor_parameters: Parameters<'a>,
    search_parameters: Parameters<'a>,
    stored_account_data: AccountData,
    aci_identity_key: &PublicKey,
    distinguished_tree_head: &LastTreeHead,
    mode: MonitorMode,
) -> Result<MaybePartial<AccountData>, RequestError<Error>> {
    let monitor_account_data = {
        let Parameters {
            aci,
            e164,
            username_hash,
        } = &monitor_parameters;
        kt.monitor(
            aci,
            e164.map(|(e164, _)| *e164),
            username_hash.cloned(),
            stored_account_data.clone(),
            distinguished_tree_head,
        )
        .await?
    };
    // Call to `monitor` guarantees that the optionality of E.164 and username hash data
    // will match between `stored_account_data` and `monitor_account_data`. Meaning, they will
    // either both be Some() or both None.
    let stored_versions = SearchVersions::from_account_data(&stored_account_data);
    let updated_versions = SearchVersions::from_account_data(&monitor_account_data);
    let version_delta = updated_versions
        .try_subtract(&stored_versions)
        .map_err(|_| {
            RequestError::Other(
                libsignal_keytrans::Error::VerificationFailed(
                    "version of the mapping decreased".to_string(),
                )
                .into(),
            )
        })?;

    let any_version_changed = version_delta.maximum_version().is_some_and(|n| n > 0);
    let post_monitor_plan = PostMonitorAction::plan(
        monitor_parameters,
        search_parameters,
        mode,
        any_version_changed.into(),
    )?;

    // Combine the stored account data and the one we just obtained from monitor.
    // Not preserving ACI data here as we do need to prefer monitor's version.
    // The effect of doing it is that the search will have the most recent
    // monitoring data that we have for optional fields even if they were not
    // included in the monitor call.
    let combined_account_data =
        merge_account_data(stored_account_data, monitor_account_data, false);
    post_monitor_plan
        .execute(
            kt,
            aci_identity_key,
            distinguished_tree_head,
            combined_account_data,
        )
        .await
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use libsignal_core::E164;
    use libsignal_keytrans::AccountData;
    use nonzero_ext::nonzero;
    use test_case::{test_case, test_matrix};

    use crate::api::RequestError;
    use crate::api::keytrans::monitor_and_search::{
        Action, Parameters, PostMonitorAction, VersionChanged, merge_account_data,
        monitor_then_search,
    };
    use crate::api::keytrans::test_support::{
        TestKt, test_account, test_account_data, test_distinguished_tree,
    };
    use crate::api::keytrans::{
        AccountDataField, Error, MaybePartial, MonitorMode, SearchKey, UsernameHash,
        monitor_and_search,
    };

    #[test]
    fn parameters_merge_with_prefers_other_optionals_and_self_aci() {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();
        let username_hash = test_account::username_hash();

        let monitor_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: Some(&username_hash),
        };
        let search_parameters = Parameters {
            aci: &aci,
            e164: Some(&e164),
            username_hash: None,
        };

        let merged = monitor_parameters.merge_with(search_parameters);
        assert_eq!(merged.aci, &aci);
        assert_eq!(merged.e164, Some(&e164));
        assert_eq!(
            merged.username_hash.map(AsRef::as_ref),
            Some(username_hash.as_ref())
        );
    }

    #[test]
    fn post_monitor_action_plan_self_version_change_is_error() {
        let aci = test_account::aci();
        let result = PostMonitorAction::plan(
            Parameters {
                aci: &aci,
                e164: None,
                username_hash: None,
            },
            Parameters {
                aci: &aci,
                e164: None,
                username_hash: None,
            },
            MonitorMode::MonitorSelf,
            VersionChanged::Yes,
        );

        assert_matches!(
            result,
            Err(RequestError::Other(Error::VerificationFailed(_)))
        );
    }

    #[test]
    fn post_monitor_action_plan_version_change_merges_parameters() {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();
        let username_hash = test_account::username_hash();
        let monitor_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: Some(&username_hash),
        };
        let search_parameters = Parameters {
            aci: &aci,
            e164: Some(&e164),
            username_hash: None,
        };

        let action = PostMonitorAction::plan(
            monitor_parameters,
            search_parameters,
            MonitorMode::MonitorOther,
            VersionChanged::Yes,
        );

        assert_matches!(
            action,
            Ok(PostMonitorAction::Search {
                parameters,
                version_change_detected: VersionChanged::Yes,
            }) => {
                assert_eq!(parameters.aci, &aci);
                assert_eq!(parameters.e164, Some(&e164));
                assert_eq!(parameters.username_hash.map(AsRef::as_ref), Some(username_hash.as_ref()));
            }
        );
    }

    #[test]
    fn post_monitor_action_plan_without_optional_search_keys() {
        let aci = test_account::aci();

        let action = PostMonitorAction::plan(
            Parameters {
                aci: &aci,
                e164: None,
                username_hash: None,
            },
            Parameters {
                aci: &aci,
                e164: None,
                username_hash: None,
            },
            MonitorMode::MonitorOther,
            VersionChanged::No,
        );
        assert_matches!(action, Ok(PostMonitorAction::None));
    }

    #[test]
    fn post_monitor_action_plan_no_version_change_uses_search_with_optional_search_keys() {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();

        let search_action = PostMonitorAction::plan(
            Parameters {
                aci: &aci,
                e164: None,
                username_hash: None,
            },
            Parameters {
                aci: &aci,
                e164: Some(&e164),
                username_hash: None,
            },
            MonitorMode::MonitorOther,
            VersionChanged::No,
        );
        assert_matches!(
            search_action,
            Ok(PostMonitorAction::Search {
                parameters,
                version_change_detected: VersionChanged::No,
            }) => {
                assert_eq!(parameters.aci, &aci);
                assert_eq!(parameters.e164, Some(&e164));
                assert!(parameters.username_hash.is_none());
            }
        );
    }

    #[tokio::test]
    async fn post_monitor_action_execute_removes_missing_fields_if_version_changed() {
        let aci = test_account::aci();
        let distinguished_tree = test_distinguished_tree();
        let monitor_returns = test_account_data();

        let search_returns = MaybePartial::new(
            test_account_data(),
            [AccountDataField::E164, AccountDataField::UsernameHash],
        );
        // Make sure the data was there before the wiping.
        assert!(search_returns.inner.e164.is_some());
        assert!(search_returns.inner.username_hash.is_some());

        let kt = TestKt::for_search(Ok(search_returns.clone()));

        let action = PostMonitorAction::Search {
            parameters: Parameters {
                aci: &aci,
                e164: None,
                username_hash: None,
            },
            version_change_detected: VersionChanged::Yes,
        };

        let result = action
            .execute(
                &kt,
                &test_account::aci_identity_key(),
                &distinguished_tree,
                monitor_returns.clone(),
            )
            .await
            .expect("search should succeed");
        assert_matches!(result, MaybePartial {inner, missing_fields} => {
            assert!(inner.e164.is_none());
            assert!(inner.username_hash.is_none());
            assert!(missing_fields.is_empty());
        });
    }

    #[tokio::test]
    async fn post_monitor_action_execute_search_err() {
        let aci = test_account::aci();
        let distinguished_tree = test_distinguished_tree();
        let monitor_returns = test_account_data();

        let kt = TestKt::for_search(Err(TestKt::expected_error()));

        let action = PostMonitorAction::Search {
            parameters: Parameters {
                aci: &aci,
                e164: None,
                username_hash: None,
            },
            version_change_detected: VersionChanged::Yes,
        };

        let result = action
            .execute(
                &kt,
                &test_account::aci_identity_key(),
                &distinguished_tree,
                monitor_returns.clone(),
            )
            .await;

        TestKt::assert_expected_error(result);
    }

    #[tokio::test]
    #[test_matrix([VersionChanged::Yes, VersionChanged::No])]
    async fn post_monitor_action_execute_respects_preserve_aci_flag(
        version_change_detected: VersionChanged,
    ) {
        let aci = test_account::aci();
        let distinguished_tree = test_distinguished_tree();
        let mut monitor_returns = test_account_data();
        monitor_returns.aci.pos = 1111;

        let mut search_returns = test_account_data();
        search_returns.aci.pos = 2222;
        let kt = TestKt::for_search(Ok(search_returns.clone().into()));

        let action = PostMonitorAction::Search {
            parameters: Parameters {
                aci: &aci,
                e164: None,
                username_hash: None,
            },
            version_change_detected,
        };

        let result = action
            .execute(
                &kt,
                &test_account::aci_identity_key(),
                &distinguished_tree,
                monitor_returns.clone(),
            )
            .await
            .expect("search should succeed");
        let expected_aci_monitoring_data = if version_change_detected.into() {
            &search_returns.aci
        } else {
            &monitor_returns.aci
        };
        assert_eq!(expected_aci_monitoring_data, &result.inner.aci);
    }

    #[tokio::test]
    async fn monitor_and_search_monitor_error_is_returned() {
        let kt = TestKt::for_monitor(Err(TestKt::expected_error()));
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
        TestKt::assert_expected_error(result);
    }

    #[tokio::test]
    async fn monitor_and_search_no_version_change_search_error_is_returned() {
        // No username hash in the stored account data...
        let stored_account_data = AccountData {
            username_hash: None,
            ..test_account_data()
        };

        let kt = TestKt::new(
            Some(Ok(stored_account_data.clone())),
            Some(Err(TestKt::expected_error())),
        );

        // ... but request to monitor username hash.
        // Should result in a call to search.
        let result = monitor_and_search(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            Some(test_account::username_hash()),
            stored_account_data,
            &test_distinguished_tree(),
            MonitorMode::MonitorOther,
        )
        .await;
        TestKt::assert_expected_error(result);
    }

    #[tokio::test]
    async fn monitor_and_search_with_version_change_search_error_is_returned() {
        let mut monitor_account_data_with_version_bump = test_account_data();
        // Bump the maximum available version of the first entry
        let entry = monitor_account_data_with_version_bump
            .aci
            .ptrs
            .iter_mut()
            .next()
            .expect("valid test data");
        *entry.1 += 1;

        let kt = TestKt::new(
            Some(Ok(monitor_account_data_with_version_bump.clone())),
            Some(Err(TestKt::expected_error())),
        );

        // Monitor will detect version change and invoke search.
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
        TestKt::assert_expected_error(result);
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

    #[test]
    fn action_plan_no_changes() {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();
        let username_hash = test_account::username_hash();
        let account_data = test_account_data();

        let action = Action::plan(
            &aci,
            Some(&e164),
            Some(&username_hash),
            account_data.clone(),
        );
        assert_matches!(action, Action::MonitorThenSearch{ monitor_parameters, search_parameters, account_data: actual_account_data} => {
            // Monitor parameters should contain all three keys
            assert_eq!(monitor_parameters.aci, &aci);
            assert_eq!(monitor_parameters.e164, Some(&e164));
            assert_eq!(monitor_parameters.username_hash.map(|x| x.as_ref()), Some(username_hash.as_ref()));

            // Search parameters should only contain the ACI (because it is required)
            // but no E.164 or username hash
            assert_eq!(search_parameters.aci, &aci);
            assert_matches!(search_parameters.e164, None);
            assert_matches!(search_parameters.username_hash, None);

            // Account data must not have been changed
            assert_eq!(*actual_account_data, account_data);

        });
    }

    #[test]
    fn action_plan_aci_change() {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();
        let username_hash = test_account::username_hash();

        // Pretend that stored account data is for a different ACI
        let account_data = {
            let mut data = test_account_data();
            data.aci.search_key = vec![];
            data
        };

        let action = Action::plan(&aci, Some(&e164), Some(&username_hash), account_data);
        assert_matches!(action, Action::SearchOnly(_));
    }

    enum FieldUpdate {
        // Neither parameter nor stored account data has the value.
        Unset,
        // No stored data but parameter is present (e.g. we just learned about the username hash).
        Introduced,
        // Stored data is present, but parameter is none (e.g. we lost the E.164).
        Dropped,
        // Both stored data and parameter are present, but search key values are different.
        Changed,
        // Both stored data and parameter are present, and their values match.
        Unchanged,
    }

    #[test_matrix(
        [FieldUpdate::Unset, FieldUpdate::Introduced, FieldUpdate::Dropped, FieldUpdate::Changed, FieldUpdate::Unchanged],
        [FieldUpdate::Unset, FieldUpdate::Introduced, FieldUpdate::Dropped, FieldUpdate::Changed, FieldUpdate::Unchanged]
    )]
    fn action_plan_optional_fields(e164_update: FieldUpdate, username_hash_update: FieldUpdate) {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();
        let updated_e164 = E164::new(nonzero!(18005550199u64));
        // make sure the new E.164 is actually different
        assert_ne!(updated_e164, e164.0);
        let username_hash = test_account::username_hash();
        let updated_username_hash = UsernameHash::from_slice(&[42]);

        let mut e164_parameter = Some(e164.clone());
        let mut username_hash_parameter = Some(username_hash.clone());
        let mut account_data = test_account_data();

        match e164_update {
            FieldUpdate::Unset => {
                account_data.e164 = None;
                e164_parameter = None;
            }
            FieldUpdate::Introduced => {
                account_data.e164 = None;
            }
            FieldUpdate::Dropped => {
                e164_parameter = None;
            }
            FieldUpdate::Changed => {
                let mut new_e164 = test_account::e164_pair();
                new_e164.0 = updated_e164;
                e164_parameter = Some(new_e164);
            }
            FieldUpdate::Unchanged => {}
        }

        match username_hash_update {
            FieldUpdate::Unset => {
                account_data.username_hash = None;
                username_hash_parameter = None;
            }
            FieldUpdate::Introduced => {
                account_data.username_hash = None;
            }
            FieldUpdate::Dropped => {
                username_hash_parameter = None;
            }
            FieldUpdate::Changed => {
                username_hash_parameter = Some(updated_username_hash.clone());
            }
            FieldUpdate::Unchanged => {}
        }

        let action = Action::plan(
            &aci,
            e164_parameter.as_ref(),
            username_hash_parameter.as_ref(),
            account_data,
        );
        assert_matches!(action, Action::MonitorThenSearch{ monitor_parameters, search_parameters, account_data } => {
            {
                let AccountData {
                    aci: data_aci,
                    e164: data_e164,
                    username_hash: data_username_hash,
                    last_tree_head: _,
                } = *account_data;
                let Parameters {
                    aci: monitor_aci,
                    e164: monitor_e164,
                    username_hash: monitor_username_hash,
                } = monitor_parameters;
                assert_eq!(&aci, monitor_aci);
                assert_eq!(&aci.as_search_key(), &data_aci.search_key);

                // E.164 and username hash should only be present in monitor request
                // and account data if our knowledge of them hasn't changed.
                // Every other update requires a new search.
                match e164_update {
                    FieldUpdate::Unset |
                    FieldUpdate::Introduced |
                    FieldUpdate::Dropped |
                    FieldUpdate::Changed => {
                        assert_eq!(monitor_e164, None);
                        assert_eq!(data_e164.as_ref(), None);
                    }
                    FieldUpdate::Unchanged => {
                        assert_matches!(monitor_e164, Some(x) => assert_eq!(x, &e164));
                        assert_matches!(&data_e164, Some(x) => assert_eq!(&e164.0.as_search_key(), &x.search_key));
                    }
                }
                match username_hash_update {
                    FieldUpdate::Unset |
                    FieldUpdate::Introduced |
                    FieldUpdate::Dropped |
                    FieldUpdate::Changed => {
                        assert_matches!(monitor_username_hash, None);
                        assert_eq!(data_username_hash, None);
                    }
                    FieldUpdate::Unchanged => {
                        assert_eq!(monitor_username_hash.map(AsRef::as_ref), Some(username_hash.as_ref()));
                        assert_matches!(&data_username_hash, Some(x) => assert_eq!(&username_hash.as_search_key(), &x.search_key));
                    }
                }
            }
            {
                let Parameters {
                    aci: search_aci,
                    e164: search_e164,
                    username_hash: search_username_hash,
                } = search_parameters;
                assert_eq!(&aci, search_aci);

                // Search only uses the tree size field from account data,
                // so we don't need to check what keys are present.
                match e164_update {
                    FieldUpdate::Unset |
                    FieldUpdate::Dropped |
                    FieldUpdate::Unchanged => {
                        assert_eq!(search_e164, None);
                    }
                    FieldUpdate::Introduced => {
                        assert_eq!(search_e164.map(|x| &x.0), Some(&e164.0));
                    }
                    FieldUpdate::Changed => {
                        assert_eq!(search_e164.map(|x| &x.0), Some(&updated_e164));
                    }
                }
                match username_hash_update {
                    FieldUpdate::Unset |
                    FieldUpdate::Dropped |
                    FieldUpdate::Unchanged => {
                        assert_eq!(search_username_hash.map(AsRef::as_ref), None);
                    }
                    FieldUpdate::Introduced => {
                        assert_eq!(search_username_hash.map(AsRef::as_ref), Some(username_hash.as_ref()));
                    }
                    FieldUpdate::Changed => {
                        assert_eq!(search_username_hash.map(AsRef::as_ref), Some(updated_username_hash.as_ref()));
                    }
                }
            }
        });
    }

    #[tokio::test]
    #[test_matrix([false, true])]
    async fn action_execute_search_only(success: bool) {
        let search_result = if success {
            Ok(test_account_data().into())
        } else {
            Err(TestKt::expected_error())
        };
        let kt = TestKt::for_search(search_result);
        let aci = test_account::aci();
        let action = Action::SearchOnly(Parameters {
            aci: &aci,
            e164: None,
            username_hash: None,
        });

        let result = action
            .execute(
                &kt,
                &test_account::aci_identity_key(),
                &test_distinguished_tree(),
                MonitorMode::MonitorOther,
            )
            .await;
        assert_eq!(result.is_ok(), success);
        if !success {
            TestKt::assert_expected_error(result)
        }
    }

    #[tokio::test]
    async fn action_execute_monitor_only() {
        // The only time we don't perform search following monitor
        // is when neither the parameters (search keys) nor versions returned
        // by monitor change.
        let kt = TestKt::for_monitor(Ok(test_account_data()));

        let aci = test_account::aci();
        let e164_pair = test_account::e164_pair();
        let username_hash = test_account::username_hash();
        let action = Action::MonitorThenSearch {
            monitor_parameters: Parameters {
                aci: &aci,
                e164: Some(&e164_pair),
                username_hash: Some(&username_hash),
            },
            // Search parameters are irrelevant for this test.
            search_parameters: Parameters {
                aci: &aci,
                e164: None,
                username_hash: None,
            },
            account_data: Box::new(test_account_data()),
        };

        let result = action
            .execute(
                &kt,
                &test_account::aci_identity_key(),
                &test_distinguished_tree(),
                MonitorMode::MonitorOther,
            )
            .await;
        assert_matches!(result, Ok(_));
    }

    #[tokio::test]
    async fn monitor_then_search_monitor_err() {
        let aci = test_account::aci();

        let kt = TestKt::for_monitor(Err(TestKt::expected_error()));

        let monitor_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: None,
        };

        let search_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: None,
        };

        let result = monitor_then_search(
            &kt,
            monitor_parameters,
            search_parameters,
            test_account_data(),
            &test_account::aci_identity_key(),
            &test_distinguished_tree(),
            MonitorMode::MonitorOther,
        )
        .await;

        TestKt::assert_expected_error(result);
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

    #[tokio::test]
    #[test_case(BumpVersionFor::Aci; "newer Aci")]
    #[test_case(BumpVersionFor::E164; "newer E.164")]
    #[test_case(BumpVersionFor::UsernameHash; "newer username hash")]
    async fn monitor_then_search_version_change_should_search_for_other(bump: BumpVersionFor) {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();
        let username_hash = test_account::username_hash();

        let mut monitor_result = test_account_data();
        monitor_result.apply(bump);

        let kt = TestKt::new(
            Some(Ok(monitor_result.clone())),
            Some(Ok(test_account_data().into())),
        );

        let monitor_parameters = Parameters {
            aci: &aci,
            e164: Some(&e164),
            username_hash: Some(&username_hash),
        };

        let search_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: None,
        };

        let result = monitor_then_search(
            &kt,
            monitor_parameters.clone(),
            search_parameters,
            test_account_data(),
            &test_account::aci_identity_key(),
            &test_distinguished_tree(),
            MonitorMode::MonitorOther,
        )
        .await;

        assert_matches!(
            result,
            Ok(MaybePartial {inner, missing_fields: _}) if inner == test_account_data()
        );

        let invocations = kt.search.take().invocations;
        let invocation = assert_matches!(&invocations[..], [invocation] => invocation);

        // In case of version change we perform a single search using monitor parameters
        assert_eq!(&invocation.aci, monitor_parameters.aci);
        assert_eq!(&invocation.e164.as_ref(), &monitor_parameters.e164);
        assert_eq!(
            &invocation.username_hash_bytes,
            &monitor_parameters
                .username_hash
                .map(|x| x.as_ref().to_vec())
        );
    }

    #[tokio::test]
    #[test_case(BumpVersionFor::Aci; "newer Aci")]
    #[test_case(BumpVersionFor::E164; "newer E.164")]
    #[test_case(BumpVersionFor::UsernameHash; "newer username hash")]
    async fn monitor_then_search_version_change_should_fail_for_self(bump: BumpVersionFor) {
        let aci = test_account::aci();
        let mut monitor_result = test_account_data();
        monitor_result.apply(bump);

        let kt = TestKt::for_monitor(Ok(monitor_result.clone()));

        let monitor_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: None,
        };

        let search_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: None,
        };

        let result = monitor_then_search(
            &kt,
            monitor_parameters,
            search_parameters,
            test_account_data(),
            &test_account::aci_identity_key(),
            &test_distinguished_tree(),
            MonitorMode::MonitorSelf,
        )
        .await;

        assert_matches!(
            result,
            Err(RequestError::Other(Error::VerificationFailed(_)))
        );
    }

    #[tokio::test]
    #[test_matrix([MonitorMode::MonitorSelf, MonitorMode::MonitorOther])]
    async fn monitor_then_search_updated_e164(mode: MonitorMode) {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();

        let mut monitor_returns = test_account_data();
        monitor_returns.aci.pos = 1111;
        monitor_returns.e164 = None;
        monitor_returns.username_hash = None;

        let mut search_returns = test_account_data();
        search_returns.aci.pos = 2222;
        search_returns.username_hash = None;

        let kt = TestKt::new(
            Some(Ok(monitor_returns.clone())),
            Some(Ok(search_returns.clone().into())),
        );

        let monitor_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: None,
        };

        let search_parameters = Parameters {
            aci: &aci,
            e164: Some(&e164),
            username_hash: None,
        };

        let stored_account_data = test_account_data();

        let result = monitor_then_search(
            &kt,
            monitor_parameters,
            search_parameters.clone(),
            stored_account_data,
            &test_account::aci_identity_key(),
            &test_distinguished_tree(),
            mode,
        )
        .await;

        let invocations = kt.search.take().invocations;
        let invocation = assert_matches!(&invocations[..], [invocation] => invocation);

        assert_eq!(&invocation.aci, search_parameters.aci);
        assert_eq!(&invocation.e164.as_ref(), &search_parameters.e164);
        assert!(invocation.username_hash_bytes.is_none());

        assert_matches!(result, Ok(MaybePartial { inner, missing_fields }) => {
            // Importantly, despite having done a new search for ACI as well
            // we should have retained the ACI result from an earlier monitor.
            assert_eq!(inner.aci, monitor_returns.aci);
            assert!(missing_fields.is_empty());
        });
    }

    #[tokio::test]
    async fn monitor_then_search_version_change_and_new_field() {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();

        // Stored data has no E.164 (newly introduced key scenario).
        let mut stored = test_account_data();
        stored.e164 = None;

        // Monitor result bumps ACI version so any_version_changed=true.
        let mut monitor_result = stored.clone();
        monitor_result.apply(BumpVersionFor::Aci);

        // Search response includes E.164 mapping.
        let search_result = test_account_data();
        let kt = TestKt::new(
            Some(Ok(monitor_result)),
            Some(Ok(search_result.clone().into())),
        );

        let monitor_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: None,
        };
        let search_parameters = Parameters {
            aci: &aci,
            e164: Some(&e164), // newly requested key must survive version-bump path
            username_hash: None,
        };

        let result = monitor_then_search(
            &kt,
            monitor_parameters,
            search_parameters.clone(),
            stored,
            &test_account::aci_identity_key(),
            &test_distinguished_tree(),
            MonitorMode::MonitorOther,
        )
        .await;

        let invocations = kt.search.take().invocations;
        let invocation = assert_matches!(&invocations[..], [inv] => inv);

        assert_eq!(&invocation.e164.as_ref(), &search_parameters.e164);

        assert_matches!(result, Ok(MaybePartial { inner, missing_fields }) => {
            assert!(inner.e164.is_some());
            assert!(missing_fields.is_empty());
        });
    }

    #[tokio::test]
    async fn monitor_then_search_passes_stored_account_data_to_search() {
        let aci = test_account::aci();

        let mut stored = test_account_data();
        stored.aci.pos = 1111;
        stored.e164.as_mut().unwrap().pos = 1111;
        stored.username_hash.as_mut().unwrap().pos = 1111;
        stored.last_tree_head.0.tree_size = 1111;

        let mut monitor_result = stored.clone();
        monitor_result.aci.pos = 2222;
        monitor_result.e164 = None;
        monitor_result.username_hash.as_mut().unwrap().pos = 2222;
        monitor_result.last_tree_head.0.tree_size = 2222;

        // The way the test is set up, it will not trigger search after monitor.
        let kt = TestKt::for_monitor(Ok(monitor_result));

        let monitor_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: None,
        };
        let search_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: None,
        };

        let result = monitor_then_search(
            &kt,
            monitor_parameters,
            search_parameters.clone(),
            stored,
            &test_account::aci_identity_key(),
            &test_distinguished_tree(),
            MonitorMode::MonitorOther,
        )
        .await;

        assert_matches!(result, Ok(MaybePartial { inner, missing_fields: _ }) => {
            // ACI, username hash, and tree size should be taken from monitor result
            assert_eq!(inner.aci.pos, 2222);
            assert_eq!(inner.username_hash.expect("missing username hash").pos, 2222);
            assert_eq!(inner.last_tree_head.0.tree_size, 2222);
            // but the monitor did not return anything for E.164, therefore it
            // should be inherited from the original stored account data.
            assert_eq!(inner.e164.expect("missing E.164").pos, 1111);
        });
    }

    #[tokio::test]
    async fn monitor_then_search_learned_username_hash_preserves_monitored_e164() {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();
        let username_hash = test_account::username_hash();

        // We already know ACI+E.164, but do not yet track username hash.
        let mut stored = test_account_data();
        stored.username_hash = None;

        let monitor_result = stored.clone();

        // Search response for newly learned username hash omits E.164.
        let mut search_result = test_account_data();
        search_result.e164 = None;

        let kt = TestKt::new(
            Some(Ok(monitor_result.clone())),
            Some(Ok(search_result.clone().into())),
        );

        let monitor_parameters = Parameters {
            aci: &aci,
            e164: Some(&e164),
            username_hash: None,
        };
        let search_parameters = Parameters {
            aci: &aci,
            e164: None,
            username_hash: Some(&username_hash),
        };

        let result = monitor_then_search(
            &kt,
            monitor_parameters,
            search_parameters.clone(),
            stored,
            &test_account::aci_identity_key(),
            &test_distinguished_tree(),
            MonitorMode::MonitorOther,
        )
        .await;

        let invocations = kt.search.take().invocations;
        let invocation = assert_matches!(&invocations[..], [inv] => inv);
        assert!(invocation.e164.is_none());
        assert_eq!(
            invocation.username_hash_bytes.as_deref(),
            search_parameters.username_hash.map(AsRef::as_ref)
        );
        assert_matches!(result, Ok(MaybePartial {inner, missing_fields }) => {
            assert_eq!(&inner.e164, &monitor_result.e164);
            assert_eq!(&inner.username_hash, &search_result.username_hash);
            assert!(missing_fields.is_empty());
        });
    }

    #[test_matrix([true, false])]
    fn merge_account_data_preserves_or_overwrites_aci_based_on_flag(preserve_aci: bool) {
        let mut earlier = test_account_data();
        earlier.aci.pos = 1111;

        let mut later = test_account_data();
        later.aci.pos = 2222;

        let preserved = merge_account_data(earlier.clone(), later.clone(), preserve_aci);
        let expected = if preserve_aci { &earlier } else { &later };
        assert_eq!(preserved.aci.pos, expected.aci.pos);
    }

    #[test]
    fn merge_account_data_does_not_replace_some_with_none() {
        let earlier = test_account_data();
        let mut later = test_account_data();
        later.e164 = None;
        later.username_hash = None;

        let merged = merge_account_data(earlier.clone(), later, true);
        assert_eq!(merged.e164, earlier.e164);
        assert_eq!(merged.username_hash, earlier.username_hash);
    }

    #[test]
    fn merge_account_data_uses_later_optional() {
        let mut earlier = test_account_data();
        earlier.e164 = None;
        earlier.username_hash = None;

        let later = test_account_data();

        let merged = merge_account_data(earlier, later.clone(), true);
        assert_eq!(merged.e164, later.e164);
        assert_eq!(merged.username_hash, later.username_hash);
    }

    #[test]
    fn merge_account_data_prefers_latest_tree_head() {
        let mut earlier = test_account_data();
        earlier.last_tree_head.0.tree_size = 1111;

        let mut later = test_account_data();
        later.last_tree_head.0.tree_size = 2222;

        let merged = merge_account_data(earlier, later.clone(), true);
        assert_eq!(merged.username_hash, later.username_hash);
    }
}
