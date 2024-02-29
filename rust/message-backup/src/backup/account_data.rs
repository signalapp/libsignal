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
#[cfg_attr(test, derive_where(PartialEq;
    M::Value<ProfileKeyBytes>: PartialEq,
    M::Value<Option<usernames::Username>>: PartialEq,
    M::Value<String>: PartialEq,
    M::Value<String>: PartialEq,
    M::Value<AccountSettings>: PartialEq,
))]
pub struct AccountData<M: Method> {
    pub profile_key: M::Value<ProfileKeyBytes>,
    pub username: M::Value<Option<usernames::Username>>,
    pub given_name: M::Value<String>,
    pub family_name: M::Value<String>,
    pub account_settings: M::Value<AccountSettings>,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct AccountSettings {}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum AccountDataError {
    /// profile key was invalid
    InvalidProfileKey,
    /// invalid username
    InvalidUsername(#[from] UsernameError),
    /// no account settings found
    MissingSettings,
    /// account settings phone number sharing mode is UNKNOWN
    UnknownPhoneNumberSharingMode,
    /// username link is present without username
    UsernameLinkWithoutUsername,
}

impl<M: Method> TryFrom<proto::AccountData> for AccountData<M> {
    type Error = AccountDataError;
    fn try_from(proto: proto::AccountData) -> Result<Self, Self::Error> {
        let proto::AccountData {
            profileKey,
            username,
            givenName,
            familyName,
            accountSettings,
            usernameLink,
            special_fields: _,

            // TODO do something with these values.
            avatarUrlPath: _,
            subscriberId: _,
            subscriberCurrencyCode: _,
            subscriptionManuallyCancelled: _,
        } = proto;

        let profile_key = ProfileKeyBytes::try_from(profileKey)
            .map_err(|_| AccountDataError::InvalidProfileKey)?;

        let username = username.as_deref().map(Username::new).transpose()?;
        if let Some(proto::account_data::UsernameLink {
            color,
            special_fields: _,
            // TODO validate these fields
            entropy: _,
            serverId: _,
        }) = usernameLink.into_option()
        {
            if username.is_none() {
                return Err(AccountDataError::UsernameLinkWithoutUsername);
            }
            // The color is allowed to be unset, so no validation is necessary.
            let _: proto::account_data::username_link::Color = color.enum_value_or_default();
        }

        let account_settings = accountSettings
            .into_option()
            .ok_or(AccountDataError::MissingSettings)?
            .try_into()?;

        Ok(Self {
            profile_key: M::value(profile_key),
            username: M::value(username),
            given_name: M::value(givenName),
            family_name: M::value(familyName),
            account_settings: M::value(account_settings),
        })
    }
}

impl TryFrom<proto::account_data::AccountSettings> for AccountSettings {
    type Error = AccountDataError;

    fn try_from(value: proto::account_data::AccountSettings) -> Result<Self, Self::Error> {
        let proto::account_data::AccountSettings {
            phoneNumberSharingMode,
            readReceipts: _,
            sealedSenderIndicators: _,
            typingIndicators: _,
            noteToSelfMarkedUnread: _,
            linkPreviews: _,
            notDiscoverableByPhoneNumber: _,
            preferContactAvatars: _,
            universalExpireTimer: _,
            displayBadgesOnProfile: _,
            keepMutedChatsArchived: _,
            hasSetMyStoriesPrivacy: _,
            hasViewedOnboardingStory: _,
            storiesDisabled: _,
            storyViewReceiptsEnabled: _,
            hasSeenGroupStoryEducationSheet: _,
            hasCompletedUsernameOnboarding: _,
            special_fields: _,

            // TODO validate this field
            preferredReactionEmoji: _,
        } = value;

        if let proto::account_data::PhoneNumberSharingMode::UNKNOWN =
            phoneNumberSharingMode.enum_value_or_default()
        {
            return Err(AccountDataError::UnknownPhoneNumberSharingMode);
        };

        Ok(Self {})
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use crate::backup::method::{Store, ValidateOnly};

    use super::*;

    impl proto::AccountData {
        pub(crate) fn test_data() -> Self {
            Self {
                profileKey: FAKE_PROFILE_KEY.into(),
                accountSettings: Some(proto::account_data::AccountSettings::test_data()).into(),
                username: Some("abc.123".to_string()),
                usernameLink: Some(proto::account_data::UsernameLink {
                    color: proto::account_data::username_link::Color::BLUE.into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }
        }
    }

    impl proto::account_data::AccountSettings {
        fn test_data() -> Self {
            Self {
                phoneNumberSharingMode: proto::account_data::PhoneNumberSharingMode::EVERYBODY
                    .into(),
                ..Default::default()
            }
        }
    }

    const FAKE_PROFILE_KEY: ProfileKeyBytes = [0xaa; 32];

    #[test]
    fn valid_account_data() {
        assert_eq!(
            proto::AccountData::test_data().try_into(),
            Ok(AccountData::<Store> {
                profile_key: FAKE_PROFILE_KEY,
                username: Some(Username::new("abc.123").unwrap()),
                given_name: "".to_string(),
                family_name: "".to_string(),
                account_settings: AccountSettings {}
            })
        )
    }

    fn invalid_profile_key(target: &mut proto::AccountData) {
        target.profileKey.clear();
    }
    fn invalid_username(target: &mut proto::AccountData) {
        target.username = Some("invalid".to_string());
    }
    fn no_username(target: &mut proto::AccountData) {
        target.username = None;
        target.usernameLink = None.into();
    }
    fn no_username_link(target: &mut proto::AccountData) {
        target.usernameLink = None.into();
    }
    fn username_link_unknown_color(target: &mut proto::AccountData) {
        target.usernameLink = Some(proto::account_data::UsernameLink::default()).into();
    }
    fn username_link_without_username(target: &mut proto::AccountData) {
        target.username = None;
        target.usernameLink = Some(target.usernameLink.take().unwrap()).into();
    }
    fn no_account_settings(target: &mut proto::AccountData) {
        target.accountSettings = None.into();
    }

    #[test_case(invalid_profile_key, Err(AccountDataError::InvalidProfileKey))]
    #[test_case(
        invalid_username,
        Err(AccountDataError::InvalidUsername(UsernameError::MissingSeparator))
    )]
    #[test_case(no_username, Ok(()))]
    #[test_case(no_username_link, Ok(()))]
    #[test_case(username_link_unknown_color, Ok(()))]
    #[test_case(
        username_link_without_username,
        Err(AccountDataError::UsernameLinkWithoutUsername)
    )]
    #[test_case(no_account_settings, Err(AccountDataError::MissingSettings))]
    fn with(
        modifier: impl FnOnce(&mut proto::AccountData),
        expected: Result<(), AccountDataError>,
    ) {
        let mut data = proto::AccountData::test_data();
        modifier(&mut data);

        assert_eq!(
            AccountData::<ValidateOnly>::try_from(data).map(|_| ()),
            expected
        )
    }
}
