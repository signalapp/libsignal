//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;

use derive_where::derive_where;
use usernames::{Username, UsernameError};
use zkgroup::ProfileKeyBytes;

use crate::backup::method::Method;
use crate::proto::backup as proto;

#[derive_where(Debug)]
pub struct AccountData<M: Method> {
    pub profile_key: M::Value<ProfileKeyBytes>,
    pub username: M::Value<Option<usernames::Username>>,
    pub given_name: M::Value<String>,
    pub family_name: M::Value<String>,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum AccountDataError {
    /// profile key was invalid
    InvalidProfileKey,
    /// invalid username
    InvalidUsername(#[from] UsernameError),
}

impl<M: Method> TryFrom<proto::AccountData> for AccountData<M> {
    type Error = AccountDataError;
    fn try_from(proto: proto::AccountData) -> Result<Self, Self::Error> {
        let proto::AccountData {
            profileKey,
            username,
            givenName,
            familyName,
            special_fields: _,

            // TODO do something with these values.
            usernameLink: _,
            avatarUrlPath: _,
            subscriberId: _,
            subscriberCurrencyCode: _,
            subscriptionManuallyCancelled: _,
            accountSettings: _,
        } = proto;

        let profile_key = ProfileKeyBytes::try_from(profileKey)
            .map_err(|_| AccountDataError::InvalidProfileKey)?;

        let username = username.as_deref().map(Username::new).transpose()?;

        Ok(Self {
            profile_key: M::value(profile_key),
            username: M::value(username),
            given_name: M::value(givenName),
            family_name: M::value(familyName),
        })
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use crate::backup::method::ValidateOnly;

    impl proto::AccountData {
        pub(crate) fn test_data() -> Self {
            Self {
                profileKey: FAKE_PROFILE_KEY.into(),
                ..Default::default()
            }
        }
    }

    use super::*;

    const FAKE_PROFILE_KEY: ProfileKeyBytes = [0xaa; 32];

    #[test]
    fn requires_valid_profile_key() {
        let data = proto::AccountData {
            profileKey: vec![],
            ..Default::default()
        };

        assert_matches!(
            AccountData::<ValidateOnly>::try_from(data),
            Err(AccountDataError::InvalidProfileKey)
        )
    }

    #[test]
    fn rejects_invalid_username() {
        let data = proto::AccountData {
            profileKey: FAKE_PROFILE_KEY.into(),
            username: Some("invalid".to_string()),
            ..Default::default()
        };

        assert_matches!(
            AccountData::<ValidateOnly>::try_from(data),
            Err(AccountDataError::InvalidUsername(_))
        )
    }
}
