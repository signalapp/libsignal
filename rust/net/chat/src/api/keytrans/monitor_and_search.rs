//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::ControlFlow;
use std::time::{Duration, SystemTime};

use libsignal_core::curve::PublicKey;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{
    AccountData, LastTreeHead, LocalStateUpdate, MonitoringData, StoredTreeHead,
};

use crate::api::RequestError;
use crate::api::keytrans::maybe_partial::MaybePartial;
use crate::api::keytrans::{
    AccountDataField, CheckMode, Error, SearchKey, UnauthenticatedChatApi, UsernameHash,
};

const MAX_DISTINGUISHED_TREE_AGE: Duration =
    Duration::from_secs(7 * 24 * 60 * 60 /* one week */);

/// The main entry point to the module.
pub async fn check(
    kt: &impl UnauthenticatedChatApi,
    aci: &Aci,
    aci_identity_key: &PublicKey,
    e164: Option<(E164, Vec<u8>)>,
    username_hash: Option<UsernameHash<'_>>,
    stored_account_data: Option<AccountData>,
    distinguished_tree_head: Option<TreeHeadWithTimestamp>,
    mode: CheckMode,
) -> Result<(MaybePartial<AccountData>, LastTreeHead), RequestError<Error>> {
    let distinguished_tree_head =
        update_distinguished_if_needed(kt, distinguished_tree_head).await?;
    let action = Action::plan(
        aci,
        e164.as_ref(),
        username_hash.as_ref(),
        stored_account_data,
    );

    let result = action
        .execute(kt, aci_identity_key, &distinguished_tree_head, mode)
        .await?;

    Ok((result, distinguished_tree_head))
}

fn is_too_old(stored_at_ms: u64) -> bool {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("valid SystemTime")
        .saturating_sub(Duration::from_millis(stored_at_ms))
        > MAX_DISTINGUISHED_TREE_AGE
}

fn select_baseline_tree_head(
    tree_head: Option<TreeHeadWithTimestamp>,
) -> ControlFlow<LastTreeHead, Option<LastTreeHead>> {
    match tree_head {
        None => ControlFlow::Continue(None),
        // Not recent enough to be used for search/monitor but a fine
        // baseline for refresh.
        Some(timed_head) if is_too_old(timed_head.stored_at_ms) => {
            ControlFlow::Continue(Some(timed_head.tree_head))
        }
        Some(timed_head) => ControlFlow::Break(timed_head.tree_head),
    }
}

async fn update_distinguished_if_needed(
    kt: &impl UnauthenticatedChatApi,
    tree_head: Option<TreeHeadWithTimestamp>,
) -> Result<LastTreeHead, RequestError<Error>> {
    let tree_head = match select_baseline_tree_head(tree_head) {
        ControlFlow::Break(tree_head) => return Ok(tree_head),
        ControlFlow::Continue(baseline) => baseline,
    };
    let LocalStateUpdate {
        tree_head,
        tree_root,
        monitoring_data: _,
    } = kt.distinguished(tree_head).await?;

    Ok(LastTreeHead(tree_head, tree_root))
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Clone)]
pub struct TreeHeadWithTimestamp {
    pub tree_head: LastTreeHead,
    pub stored_at_ms: u64,
}

impl TreeHeadWithTimestamp {
    pub fn from_stored(stored: StoredTreeHead) -> Option<Self> {
        Some(Self {
            stored_at_ms: stored.stored_at_ms,
            tree_head: stored.into_last_tree_head()?,
        })
    }
}

/// A more ergonomic search for the clients.
///
/// The problem with search especially for self is PNP. Client always knows
/// user's E.164 regardless of the PNP discoverability, however the chat server
/// will only return the response for E.164 if it is discoverable, and we treat
/// missing fields as an error (see keytrans bridging).
///
/// For contact-check it is fine, we cannot verify that the phone number
/// client thinks is associated with the account is indeed associated with it,
/// but for self-check it makes it unnecessarily more complicated for clients
/// to conditionally provide the E.164 to the search API.
///
/// Note that we do not modify the stored account data in any way, it is
/// important to keep it as is for when phone number discovery is on again.
///
/// Because local changes may take some time to be reflected in the key
/// transparency log, it is possible that even though it is known locally that
/// discoverability is off, search may still return a valid result for E.164.
/// Therefore, the choice is made to request it and ignore the missing field
/// afterward, as opposed to not requesting it in the first place.
async fn modal_search(
    kt: &impl UnauthenticatedChatApi,
    aci: &Aci,
    aci_identity_key: &PublicKey,
    e164: Option<(E164, Vec<u8>)>,
    username_hash: Option<UsernameHash<'_>>,
    stored_account_data: Option<AccountData>,
    distinguished_tree_head: &LastTreeHead,
    mode: CheckMode,
) -> Result<MaybePartial<AccountData>, RequestError<Error>> {
    let mut maybe_partial = kt
        .search(
            aci,
            aci_identity_key,
            e164,
            username_hash,
            stored_account_data,
            distinguished_tree_head,
        )
        .await?;

    if matches!(
        mode,
        CheckMode::SelfCheck {
            is_e164_discoverable: false
        }
    ) && maybe_partial
        .missing_fields
        .contains(&AccountDataField::E164)
    {
        // Phone number discoverability is off. We should not treat it as error.
        maybe_partial.missing_fields.remove(&AccountDataField::E164);
    }

    Ok(maybe_partial)
}

#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
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

#[cfg_attr(test, derive(Debug, PartialEq))]
enum Action<'a> {
    SearchOnly(Parameters<'a>),
    MonitorThenSearch {
        monitor_parameters: Parameters<'a>,
        search_parameters: Parameters<'a>,
        account_data: Box<AccountData>,
    },
}

#[cfg_attr(test, derive(Debug, PartialEq))]
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
    /// - If the stored data is missing or stored ACI search key does not match the requested ACI,
    ///   returns `SearchOnly` and ignores stored mappings.
    /// - Otherwise returns `MonitorThenSearch`, splitting optional keys between:
    ///   - `monitor_parameters` for mappings that are unchanged and should be monitored.
    ///   - `search_parameters` for mappings that are new, changed, or need re-fetch.
    /// - For dropped/changed optional mappings, clears the corresponding stored monitoring data.
    pub fn plan(
        aci: &'a Aci,
        e164: Option<&'a (E164, Vec<u8>)>,
        username_hash: Option<&'a UsernameHash<'a>>,
        stored_account_data: Option<AccountData>,
    ) -> Self {
        let Some(mut stored_account_data) = stored_account_data.filter(|stored| {
            // ACI is present in the stored data and is the same ACI being
            // requested, meaning we can proceed with monitor.
            stored.aci.search_key == aci.as_search_key()
        }) else {
            // Either there is no stored data meaning we should perform an
            // initial search, or the requested ACI is different from the one
            // stored, also resulting in a "fresh start".
            return Action::SearchOnly(Parameters {
                aci,
                e164,
                username_hash,
            });
        };

        let AccountData {
            aci: _,
            e164: stored_e164,
            username_hash: stored_username_hash,
            last_tree_head: _,
        } = &mut stored_account_data;

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
        mode: CheckMode,
    ) -> Result<MaybePartial<AccountData>, RequestError<Error>> {
        match self {
            Action::SearchOnly(Parameters {
                aci,
                e164,
                username_hash,
            }) => {
                modal_search(
                    kt,
                    aci,
                    aci_identity_key,
                    e164.cloned(),
                    username_hash.cloned(),
                    // Intentionally ignoring the stored data even if it was available.
                    None,
                    distinguished_tree_head,
                    mode,
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
#[cfg_attr(test, derive(Debug, PartialEq))]
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
        mode: CheckMode,
        any_version_changed: VersionChanged,
    ) -> Result<Self, RequestError<Error>> {
        // Optional fields should either be monitored or searched for, never both.
        debug_assert!(!(search_parameters.e164.is_some() && monitor_parameters.e164.is_some()));
        debug_assert!(
            !(search_parameters.username_hash.is_some()
                && monitor_parameters.username_hash.is_some())
        );

        match (mode, any_version_changed) {
            (CheckMode::SelfCheck { .. }, VersionChanged::Yes) => Err(RequestError::Other(
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
        mode: CheckMode,
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
                let mut search_account_data = modal_search(
                    kt,
                    aci,
                    aci_identity_key,
                    e164.cloned(),
                    username_hash.cloned(),
                    Some(account_data.clone()),
                    distinguished_tree_head,
                    mode,
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
///
/// Importantly, we do not clear the flag that the field is missing.
/// If we did that, then on the next check the same field will be requested as
/// previously unknown, and search will return the missing field eventually
/// resulting in check failure.
///
/// Keeping the missing fields therefore avoids this inconsistency, by making
/// both current and following check fail (provided the log itself does not
/// change).
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
    mode: CheckMode,
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
            mode,
        )
        .await
}

#[cfg(test)]
mod test {
    use std::ops::ControlFlow;
    use std::time::SystemTime;

    use assert_matches::assert_matches;
    use futures_util::FutureExt;
    use libsignal_core::E164;
    use libsignal_keytrans::AccountData;
    use nonzero_ext::nonzero;
    use test_case::{test_case, test_matrix};

    use super::{
        Action, Parameters, PostMonitorAction, TreeHeadWithTimestamp, VersionChanged, check,
        is_too_old, merge_account_data, modal_search, monitor_then_search,
        select_baseline_tree_head,
    };
    use crate::api::RequestError;
    use crate::api::keytrans::test_support::{
        OwnedParameters, TestKt, test_account, test_account_data, test_distinguished_tree,
    };
    use crate::api::keytrans::{AccountDataField, CheckMode, Error, MaybePartial, UsernameHash};

    impl<'a> PartialEq<Parameters<'a>> for OwnedParameters {
        fn eq(&self, other: &Parameters<'a>) -> bool {
            let Self {
                aci,
                e164,
                username_hash_bytes,
            } = self;
            aci == other.aci
                && e164.as_ref() == other.e164
                && username_hash_bytes.as_deref() == other.username_hash.map(AsRef::as_ref)
        }
    }

    fn recent_distinguished_tree() -> TreeHeadWithTimestamp {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("valid time")
            .as_millis()
            .try_into()
            .expect("fits in u64");
        TreeHeadWithTimestamp {
            tree_head: test_distinguished_tree(),
            stored_at_ms: now,
        }
    }

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

    #[test_matrix([true, false])]
    fn post_monitor_action_plan_self_version_change_is_error(is_e164_discoverable: bool) {
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
            CheckMode::SelfCheck {
                is_e164_discoverable,
            },
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
            CheckMode::ContactCheck,
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
            CheckMode::ContactCheck,
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
            CheckMode::ContactCheck,
            VersionChanged::No,
        )
        .expect("valid plan");

        assert_eq!(
            search_action,
            PostMonitorAction::Search {
                parameters: Parameters {
                    aci: &aci,
                    e164: Some(&e164),
                    username_hash: None,
                },
                version_change_detected: VersionChanged::No
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
                CheckMode::ContactCheck,
            )
            .await
            .expect("search should succeed");
        assert!(result.inner.e164.is_none());
        assert!(result.inner.username_hash.is_none());

        assert_eq!(result.missing_fields, search_returns.missing_fields);
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
                CheckMode::ContactCheck,
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
                CheckMode::ContactCheck,
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
    async fn check_monitor_error_is_returned() {
        let kt = TestKt::for_monitor(Err(TestKt::expected_error()));
        let result = check(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            Some(test_account_data()),
            Some(recent_distinguished_tree()),
            CheckMode::ContactCheck,
        )
        .await;
        TestKt::assert_expected_error(result);
    }

    #[tokio::test]
    async fn check_no_version_change_search_error_is_returned() {
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
        let result = check(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            Some(test_account::username_hash()),
            Some(stored_account_data),
            Some(recent_distinguished_tree()),
            CheckMode::ContactCheck,
        )
        .await;
        TestKt::assert_expected_error(result);
    }

    #[tokio::test]
    async fn check_with_version_change_search_error_is_returned() {
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
        let result = check(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            Some(test_account_data()),
            Some(recent_distinguished_tree()),
            CheckMode::ContactCheck,
        )
        .await;
        TestKt::assert_expected_error(result);
    }

    #[tokio::test]
    async fn check_no_search_needed() {
        let monitor_result = test_account_data();
        // TestKt constructed like this will panic if search is invoked
        let kt = TestKt::for_monitor(Ok(monitor_result.clone()));

        let actual = check(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            Some(test_account_data()),
            Some(recent_distinguished_tree()),
            CheckMode::ContactCheck,
        )
        .await
        .expect("monitor should succeed");
        assert_eq!(actual.0, monitor_result.into());
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
            Some(account_data.clone()),
        );
        assert_eq!(
            action,
            Action::MonitorThenSearch {
                // Monitor parameters should contain all three keys
                monitor_parameters: Parameters {
                    aci: &aci,
                    e164: Some(&e164),
                    username_hash: Some(&username_hash),
                },
                // Search parameters should only contain the ACI (because it is required)
                // but no E.164 or username hash
                search_parameters: Parameters {
                    aci: &aci,
                    e164: None,
                    username_hash: None,
                },
                // Account data must not have been changed
                account_data: Box::new(account_data),
            }
        );
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

        let action = Action::plan(&aci, Some(&e164), Some(&username_hash), Some(account_data));

        assert_eq!(
            action,
            Action::SearchOnly(Parameters {
                aci: &aci,
                e164: Some(&e164),
                username_hash: Some(&username_hash),
            })
        );
    }

    #[test]
    fn action_plan_no_stored_account_data() {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();
        let username_hash = test_account::username_hash();

        let action = Action::plan(&aci, Some(&e164), Some(&username_hash), None);

        assert_eq!(
            action,
            Action::SearchOnly(Parameters {
                aci: &aci,
                e164: Some(&e164),
                username_hash: Some(&username_hash),
            })
        );
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
        let updated_e164_pair = (updated_e164, test_account::e164_pair().1);
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
            Some(account_data),
        );

        // We start with fully populated parameters and account data
        // and then trim it down to what is actually expected to be present.
        let mut expected_monitor = Parameters {
            aci: &aci,
            e164: Some(&e164),
            username_hash: Some(&username_hash),
        };
        let mut expected_search = Parameters {
            aci: &aci,
            e164: Some(&e164),
            username_hash: Some(&username_hash),
        };
        let mut expected_account_data = test_account_data();

        // E.164 and username hash should only be present in monitor request
        // and account data if our knowledge of them hasn't changed.
        // Every other update requires a new search.
        match e164_update {
            FieldUpdate::Unset
            | FieldUpdate::Introduced
            | FieldUpdate::Dropped
            | FieldUpdate::Changed => {
                expected_monitor.e164 = None;
                expected_account_data.e164 = None;
            }
            FieldUpdate::Unchanged => {}
        }
        match username_hash_update {
            FieldUpdate::Unset
            | FieldUpdate::Introduced
            | FieldUpdate::Dropped
            | FieldUpdate::Changed => {
                expected_monitor.username_hash = None;
                expected_account_data.username_hash = None;
            }
            FieldUpdate::Unchanged => {}
        }

        // Now setting the expected parameters for search.
        match e164_update {
            FieldUpdate::Unset | FieldUpdate::Dropped | FieldUpdate::Unchanged => {
                expected_search.e164 = None;
            }
            FieldUpdate::Changed => {
                expected_search.e164 = Some(&updated_e164_pair);
            }
            FieldUpdate::Introduced => {}
        }
        match username_hash_update {
            FieldUpdate::Unset | FieldUpdate::Dropped | FieldUpdate::Unchanged => {
                expected_search.username_hash = None;
            }
            FieldUpdate::Changed => {
                expected_search.username_hash = Some(&updated_username_hash);
            }
            FieldUpdate::Introduced => {}
        }

        let expected_action = Action::MonitorThenSearch {
            monitor_parameters: expected_monitor,
            search_parameters: expected_search,
            account_data: Box::new(expected_account_data),
        };
        assert_eq!(action, expected_action);
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
                CheckMode::ContactCheck,
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

        action
            .execute(
                &kt,
                &test_account::aci_identity_key(),
                &test_distinguished_tree(),
                CheckMode::ContactCheck,
            )
            .await
            .expect("should not fail");
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
            CheckMode::ContactCheck,
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
            CheckMode::ContactCheck,
        )
        .await
        .expect("should succeed");

        assert_eq!(result.inner, test_account_data());

        let invocation = kt.search_invocation().expect("search is invoked");

        // In case of version change we perform a single search using monitor parameters
        assert_eq!(invocation, monitor_parameters);
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
            CheckMode::SelfCheck {
                is_e164_discoverable: true,
            },
        )
        .await;

        assert_matches!(
            result,
            Err(RequestError::Other(Error::VerificationFailed(_)))
        );
    }

    #[tokio::test]
    #[test_matrix([CheckMode::SelfCheck { is_e164_discoverable: true }, CheckMode::ContactCheck])]
    async fn monitor_then_search_updated_e164(mode: CheckMode) {
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
        .await
        .expect("succeeds");

        let invocation = kt.search_invocation().expect("search is invoked");

        assert_eq!(invocation, search_parameters);

        // Importantly, despite having done a new search for ACI as well
        // we should have retained the ACI result from an earlier monitor.
        assert_eq!(result.inner.aci, monitor_returns.aci);
        assert!(result.missing_fields.is_empty());
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
            CheckMode::ContactCheck,
        )
        .await
        .expect("succeeds");

        let invocation = kt.search_invocation().expect("search is invoked");

        assert_eq!(invocation, search_parameters);

        assert!(result.inner.e164.is_some());
        assert!(result.missing_fields.is_empty());
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
            CheckMode::ContactCheck,
        )
        .await
        .expect("succeeds");

        // ACI, username hash, and tree size should be taken from monitor result
        assert_eq!(result.inner.aci.pos, 2222);
        assert_eq!(
            result
                .inner
                .username_hash
                .expect("missing username hash")
                .pos,
            2222
        );
        assert_eq!(result.inner.last_tree_head.0.tree_size, 2222);
        // but the monitor did not return anything for E.164, therefore it
        // should be inherited from the original stored account data.
        assert_eq!(result.inner.e164.expect("missing E.164").pos, 1111);
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
            CheckMode::ContactCheck,
        )
        .await
        .expect("succeeds");

        let invocation = kt.search_invocation().expect("search is invoked");

        assert_eq!(invocation, search_parameters);

        assert!(result.missing_fields.is_empty());
        assert_eq!(&result.inner.e164, &monitor_result.e164);
        assert_eq!(&result.inner.username_hash, &search_result.username_hash);
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

    #[tokio::test]
    #[test_matrix([
        CheckMode::SelfCheck { is_e164_discoverable: false },
        CheckMode::SelfCheck { is_e164_discoverable: true },
        CheckMode::ContactCheck,
    ])]
    async fn modal_search_missing_e164(mode: CheckMode) {
        let aci = test_account::aci();
        let e164 = test_account::e164_pair();

        let mut search_result = MaybePartial::from(test_account_data());
        search_result.missing_fields.insert(AccountDataField::E164);

        let kt = TestKt::for_search(Ok(search_result.clone()));

        let result = modal_search(
            &kt,
            &aci,
            &test_account::aci_identity_key(),
            Some(e164.clone()),
            None,
            None,
            &test_distinguished_tree(),
            mode,
        )
        .await
        .expect("succeeds");

        let invocation = kt.search_invocation().expect("search is invoked");

        assert_eq!(
            invocation,
            Parameters {
                aci: &aci,
                e164: Some(&e164),
                username_hash: None,
            }
        );

        match mode {
            CheckMode::SelfCheck {
                is_e164_discoverable: false,
            } => {
                assert!(result.missing_fields.is_empty());
            }
            CheckMode::SelfCheck {
                is_e164_discoverable: true,
            }
            | CheckMode::ContactCheck => {
                assert!(result.missing_fields.contains(&AccountDataField::E164));
            }
        }
    }

    #[test]
    fn check_updates_distinguished_when_its_unknown() {
        let mut expected = test_distinguished_tree();
        expected.1 = [42; 32];
        let kt = TestKt::for_search(Ok(test_account_data().into()))
            .with_distinguished(Ok(expected.clone()));

        let result = check(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            None,
            None,
            CheckMode::ContactCheck,
        )
        .now_or_never()
        .expect("sync")
        .expect("check succeeds");

        // Distinguished stub has been consumed
        assert!(kt.distinguished.take().is_none());
        // Should return the most recent distinguished tree
        assert_eq!(expected, result.1);
    }

    #[test]
    fn check_does_not_update_distinguished_when_its_recent() {
        let stored_distinguished = TreeHeadWithTimestamp {
            tree_head: test_distinguished_tree(),
            stored_at_ms: now_ms() - 60 * 1000,
        };

        let mut updated_distinguished = test_distinguished_tree();
        updated_distinguished.1 = [42; 32];
        let kt = TestKt::for_search(Ok(test_account_data().into()))
            .with_distinguished(Ok(updated_distinguished));

        let result = check(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            None,
            Some(stored_distinguished.clone()),
            CheckMode::ContactCheck,
        )
        .now_or_never()
        .expect("sync")
        .expect("check succeeds");

        // Distinguished stub has not been consumed
        assert!(kt.distinguished.take().is_some());
        // Should return the most recent distinguished tree
        assert_eq!(stored_distinguished.tree_head, result.1);
    }

    #[test]
    fn check_propagates_distinguished_update_failure() {
        let kt = TestKt::for_search(Ok(test_account_data().into()))
            .with_distinguished(Err(TestKt::expected_error()));

        let result = check(
            &kt,
            &test_account::aci(),
            &test_account::aci_identity_key(),
            None,
            None,
            None,
            None,
            CheckMode::ContactCheck,
        )
        .now_or_never()
        .expect("sync");

        TestKt::assert_expected_error(result);
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("valid time")
            .as_millis()
            .try_into()
            .expect("fits in u64")
    }

    #[test_case(0 => false; "now")]
    #[test_case(6 * 24 * 60 * 60 * 1000 => false; "not quite a week ago")]
    #[test_case(2 * 7 * 24 * 60 * 60 * 1000 => true; "two weeks ago")]
    fn is_too_old_for_values_in_the_past(ms_in_the_past: u64) -> bool {
        is_too_old(now_ms() - ms_in_the_past)
    }

    #[test]
    fn is_too_old_value_in_the_future() {
        assert!(!is_too_old(now_ms() + 1));
    }

    #[test]
    fn select_baseline_tree_head_no_stored_head_continues_with_none() {
        assert_matches!(select_baseline_tree_head(None), ControlFlow::Continue(None));
    }

    #[test]
    fn select_baseline_tree_head_too_old_continues_with_tree_head() {
        let tree_head = test_distinguished_tree();
        let stored = TreeHeadWithTimestamp {
            tree_head: tree_head.clone(),
            stored_at_ms: 0,
        };
        assert_eq!(
            select_baseline_tree_head(Some(stored)),
            ControlFlow::Continue(Some(tree_head)),
        );
    }

    #[test]
    fn select_baseline_tree_head_recent_breaks_with_tree_head() {
        let recent = recent_distinguished_tree();
        let expected = recent.tree_head.clone();
        assert_eq!(
            select_baseline_tree_head(Some(recent)),
            ControlFlow::Break(expected),
        );
    }
}
