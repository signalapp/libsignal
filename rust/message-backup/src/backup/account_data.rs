//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::num::NonZeroU32;

use derive_where::derive_where;
use usernames::constants::USERNAME_LINK_ENTROPY_SIZE;
use usernames::{Username, UsernameError};
use uuid::Uuid;
use zkgroup::ProfileKeyBytes;

use crate::backup::chat::chat_style::{ChatStyle, ChatStyleError, CustomColorMap};
use crate::backup::method::Method;
use crate::backup::time::{Duration, ReportUnusualTimestamp};
use crate::backup::{serialize, ReferencedTypes, TryFromWith, TryIntoWith};
use crate::proto::backup as proto;

#[derive_where(Debug)]
#[derive(serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq;
    M::Value<ProfileKeyBytes>: PartialEq,
    M::Value<Option<UsernameData>>: PartialEq,
    M::Value<String>: PartialEq,
    M::Value<Option<Subscription>>: PartialEq,
    M::Value<Option<IapSubscriberData>>: PartialEq,
    AccountSettings<M>: PartialEq,
))]
pub struct AccountData<M: Method + ReferencedTypes> {
    #[serde(
        with = "hex",
        bound(serialize = "M::Value<ProfileKeyBytes>: AsRef<[u8]>")
    )]
    pub profile_key: M::Value<ProfileKeyBytes>,
    pub username: M::Value<Option<UsernameData>>,
    pub given_name: M::Value<String>,
    pub family_name: M::Value<String>,
    pub account_settings: AccountSettings<M>,
    pub avatar_url_path: M::Value<String>,
    pub donation_subscription: M::Value<Option<Subscription>>,
    pub backup_subscription: M::Value<Option<IapSubscriberData>>,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct UsernameData {
    #[serde(serialize_with = "serialize::to_string")]
    pub username: Username,
    pub link: Option<UsernameLink>,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct UsernameLink {
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub color: crate::proto::backup::account_data::username_link::Color,
    #[serde(serialize_with = "hex::serialize")]
    pub entropy: [u8; USERNAME_LINK_ENTROPY_SIZE],
    #[serde(serialize_with = "serialize::to_string")]
    pub server_id: Uuid,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Subscription {
    #[serde(with = "hex")]
    pub subscriber_id: SubscriberId,
    pub currency_code: String,
    pub manually_canceled: bool,
}

const SUBSCRIBER_ID_LENGTH: usize = 32;
type SubscriberId = [u8; SUBSCRIBER_ID_LENGTH];

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct IapSubscriberData {
    #[serde(with = "hex")]
    pub subscriber_id: SubscriberId,
    pub subscription_id: IapSubscriptionId,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum IapSubscriptionId {
    PlayStorePurchaseToken(String),
    IosAppStoreOriginalTransactionId(u64),
}

#[derive_where(Debug)]
#[derive(serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq;
    M::Value<PhoneSharing>: PartialEq,
    M::Value<Option<bool>>: PartialEq,
    M::Value<bool>: PartialEq,
    M::Value<Option<Duration>>: PartialEq,
    M::Value<Vec<String>>: PartialEq,
    M::Value<Option<ChatStyle<M>>>: PartialEq,
    M::CustomColorData: PartialEq,
))]
pub struct AccountSettings<M: Method + ReferencedTypes> {
    pub phone_number_sharing: M::Value<PhoneSharing>,
    pub read_receipts: M::Value<bool>,
    pub sealed_sender_indicators: M::Value<bool>,
    pub typing_indicators: M::Value<bool>,
    pub link_previews: M::Value<bool>,
    pub not_discoverable_by_phone_number: M::Value<bool>,
    pub prefer_contact_avatars: M::Value<bool>,
    pub display_badges_on_profile: M::Value<bool>,
    pub keep_muted_chats_archived: M::Value<bool>,
    pub has_set_my_stories_privacy: M::Value<bool>,
    pub has_viewed_onboarding_story: M::Value<bool>,
    pub stories_disabled: M::Value<bool>,
    pub story_view_receipts_enabled: M::Value<Option<bool>>,
    pub has_seen_group_story_education_sheet: M::Value<bool>,
    pub has_completed_username_onboarding: M::Value<bool>,
    pub universal_expire_timer: M::Value<Option<Duration>>,
    pub preferred_reaction_emoji: M::Value<Vec<String>>,
    pub default_chat_style: M::Value<Option<ChatStyle<M>>>,
    pub custom_chat_colors: CustomColorMap<M>,
}

#[derive(Copy, Clone, Debug, PartialEq, serde::Serialize)]
pub enum PhoneSharing {
    WithEverybody,
    WithNobody,
}

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
    /// username entropy should have been {USERNAME_LINK_ENTROPY_SIZE:?} bytes but was {0}
    BadUsernameEntropyLength(usize),
    /// username server ID should be a UUID but was {0} bytes
    BadUsernameServerIdLength(usize),
    /// subscriber currency code was present but not the ID
    SubscriberCurrencyWithoutId,
    /// chat style: {0}
    ChatStyle(#[from] ChatStyleError),
    /// donation subscription: {0}
    DonationSubscription(SubscriptionError),
    /// backups subscription: {0}
    BackupSubscription(SubscriptionError),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum SubscriptionError {
    /// subscriber ID should have {SUBSCRIBER_ID_LENGTH:?} bytes but had {0}
    InvalidSubscriberId(usize),
    /// subscriber ID was present but not the currency code
    EmptyCurrency,
    /// missing IAP subscription ID
    MissingIapSubscriptionId,
}

impl<M: Method + ReferencedTypes, C: ReportUnusualTimestamp> TryFromWith<proto::AccountData, C>
    for AccountData<M>
{
    type Error = AccountDataError;
    fn try_from_with(proto: proto::AccountData, context: &C) -> Result<Self, Self::Error> {
        let proto::AccountData {
            profileKey,
            username,
            givenName,
            familyName,
            accountSettings,
            usernameLink,
            avatarUrlPath,
            donationSubscriberData,
            backupsSubscriberData,
            special_fields: _,
        } = proto;

        let profile_key = ProfileKeyBytes::try_from(profileKey)
            .map_err(|_| AccountDataError::InvalidProfileKey)?;

        let username = match username {
            None => {
                if usernameLink.is_some() {
                    return Err(AccountDataError::UsernameLinkWithoutUsername);
                }
                None
            }
            Some(username) => Some((username, usernameLink.into_option()).try_into()?),
        };

        let account_settings = accountSettings
            .into_option()
            .ok_or(AccountDataError::MissingSettings)?
            .try_into_with(context)?;

        let donation_subscription = donationSubscriberData
            .into_option()
            .map(Subscription::try_from)
            .transpose()
            .map_err(AccountDataError::DonationSubscription)?;
        let backup_subscription = backupsSubscriberData
            .into_option()
            .map(IapSubscriberData::try_from)
            .transpose()
            .map_err(AccountDataError::BackupSubscription)?;

        Ok(Self {
            profile_key: M::value(profile_key),
            username: M::value(username),
            given_name: M::value(givenName),
            family_name: M::value(familyName),
            account_settings,
            avatar_url_path: M::value(avatarUrlPath),
            donation_subscription: M::value(donation_subscription),
            backup_subscription: M::value(backup_subscription),
        })
    }
}

impl TryFrom<proto::account_data::SubscriberData> for Subscription {
    type Error = SubscriptionError;

    fn try_from(value: proto::account_data::SubscriberData) -> Result<Self, Self::Error> {
        let proto::account_data::SubscriberData {
            subscriberId,
            currencyCode,
            manuallyCancelled,
            special_fields: _,
        } = value;
        let subscriber_id = subscriberId
            .try_into()
            .map_err(|id: Vec<u8>| SubscriptionError::InvalidSubscriberId(id.len()))?;

        if currencyCode.is_empty() {
            return Err(SubscriptionError::EmptyCurrency);
        }
        let currency_code = currencyCode;

        Ok(Subscription {
            subscriber_id,
            currency_code,
            manually_canceled: manuallyCancelled,
        })
    }
}

impl TryFrom<proto::account_data::IAPSubscriberData> for IapSubscriberData {
    type Error = SubscriptionError;

    fn try_from(value: proto::account_data::IAPSubscriberData) -> Result<Self, Self::Error> {
        let proto::account_data::IAPSubscriberData {
            subscriberId,
            iapSubscriptionId,
            special_fields: _,
        } = value;
        let subscriber_id = subscriberId
            .try_into()
            .map_err(|id: Vec<u8>| SubscriptionError::InvalidSubscriberId(id.len()))?;

        let subscription_id = {
            use proto::account_data::iapsubscriber_data::IapSubscriptionId as ProtoIapSubscriptionId;
            match iapSubscriptionId.ok_or(SubscriptionError::MissingIapSubscriptionId)? {
                ProtoIapSubscriptionId::PurchaseToken(token) => {
                    if token.is_empty() {
                        return Err(SubscriptionError::MissingIapSubscriptionId);
                    }
                    IapSubscriptionId::PlayStorePurchaseToken(token)
                }
                ProtoIapSubscriptionId::OriginalTransactionId(id) => {
                    IapSubscriptionId::IosAppStoreOriginalTransactionId(id)
                }
            }
        };

        Ok(IapSubscriberData {
            subscriber_id,
            subscription_id,
        })
    }
}

impl TryFrom<(String, Option<proto::account_data::UsernameLink>)> for UsernameData {
    type Error = AccountDataError;

    fn try_from(
        (username, username_link): (String, Option<proto::account_data::UsernameLink>),
    ) -> Result<Self, Self::Error> {
        let username = Username::new(&username)?;
        let link = username_link.map(TryInto::try_into).transpose()?;
        Ok(UsernameData { username, link })
    }
}

impl TryFrom<proto::account_data::UsernameLink> for UsernameLink {
    type Error = AccountDataError;

    fn try_from(value: proto::account_data::UsernameLink) -> Result<Self, Self::Error> {
        let proto::account_data::UsernameLink {
            color,
            entropy,
            serverId,
            special_fields: _,
        } = value;
        // The color is allowed to be unset.
        let color = color.enum_value_or_default();
        let entropy = entropy.try_into().map_err(|entropy: Vec<u8>| {
            AccountDataError::BadUsernameEntropyLength(entropy.len())
        })?;
        let server_id = serverId
            .try_into()
            .map_err(|id: Vec<u8>| AccountDataError::BadUsernameServerIdLength(id.len()))?;
        let server_id = Uuid::from_bytes(server_id);
        Ok(Self {
            color,
            entropy,
            server_id,
        })
    }
}

impl<M: Method + ReferencedTypes, C: ReportUnusualTimestamp>
    TryFromWith<proto::account_data::AccountSettings, C> for AccountSettings<M>
{
    type Error = AccountDataError;

    fn try_from_with(
        value: proto::account_data::AccountSettings,
        context: &C,
    ) -> Result<Self, Self::Error> {
        let proto::account_data::AccountSettings {
            phoneNumberSharingMode,
            readReceipts,
            sealedSenderIndicators,
            typingIndicators,
            linkPreviews,
            notDiscoverableByPhoneNumber,
            preferContactAvatars,
            displayBadgesOnProfile,
            keepMutedChatsArchived,
            hasSetMyStoriesPrivacy,
            hasViewedOnboardingStory,
            storiesDisabled,
            storyViewReceiptsEnabled,
            hasSeenGroupStoryEducationSheet,
            hasCompletedUsernameOnboarding,
            universalExpireTimerSeconds,
            preferredReactionEmoji,
            defaultChatStyle,
            customChatColors,
            special_fields: _,
        } = value;

        use proto::account_data::PhoneNumberSharingMode;
        let phone_number_sharing = match phoneNumberSharingMode.enum_value_or_default() {
            PhoneNumberSharingMode::UNKNOWN => {
                return Err(AccountDataError::UnknownPhoneNumberSharingMode)
            }
            PhoneNumberSharingMode::EVERYBODY => PhoneSharing::WithEverybody,
            PhoneNumberSharingMode::NOBODY => PhoneSharing::WithNobody,
        };

        let custom_chat_colors = customChatColors.try_into()?;

        let default_chat_style = defaultChatStyle
            .into_option()
            .map(|style| ChatStyle::try_from_proto(style, &custom_chat_colors, context))
            .transpose()?;

        let universal_expire_timer = NonZeroU32::new(universalExpireTimerSeconds)
            .map(|seconds| Duration::from_millis(1000 * u64::from(seconds.get())));

        Ok(Self {
            phone_number_sharing: M::value(phone_number_sharing),
            default_chat_style: M::value(default_chat_style),
            custom_chat_colors,
            read_receipts: M::value(readReceipts),
            sealed_sender_indicators: M::value(sealedSenderIndicators),
            typing_indicators: M::value(typingIndicators),
            link_previews: M::value(linkPreviews),
            not_discoverable_by_phone_number: M::value(notDiscoverableByPhoneNumber),
            prefer_contact_avatars: M::value(preferContactAvatars),
            display_badges_on_profile: M::value(displayBadgesOnProfile),
            keep_muted_chats_archived: M::value(keepMutedChatsArchived),
            has_set_my_stories_privacy: M::value(hasSetMyStoriesPrivacy),
            has_viewed_onboarding_story: M::value(hasViewedOnboardingStory),
            stories_disabled: M::value(storiesDisabled),
            story_view_receipts_enabled: M::value(storyViewReceiptsEnabled),
            has_seen_group_story_education_sheet: M::value(hasSeenGroupStoryEducationSheet),
            has_completed_username_onboarding: M::value(hasCompletedUsernameOnboarding),
            preferred_reaction_emoji: M::value(preferredReactionEmoji),
            universal_expire_timer: M::value(universal_expire_timer),
        })
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, LazyLock};

    use protobuf::EnumOrUnknown;
    use test_case::test_case;
    use uuid::Uuid;

    use super::*;
    use crate::backup::chat::chat_style::{BubbleColor, CustomChatColor, CustomColorId};
    use crate::backup::method::{Store, ValidateOnly};
    use crate::backup::testutil::TestContext;

    impl proto::AccountData {
        pub(crate) fn test_data() -> Self {
            Self {
                profileKey: FAKE_PROFILE_KEY.into(),
                accountSettings: Some(proto::account_data::AccountSettings::test_data()).into(),
                username: Some("abc.123".to_string()),
                usernameLink: Some(proto::account_data::UsernameLink {
                    color: proto::account_data::username_link::Color::BLUE.into(),
                    entropy: FAKE_USERNAME_LINK_ENTROPY.to_vec(),
                    serverId: FAKE_USERNAME_SERVER_ID.into_bytes().to_vec(),
                    ..Default::default()
                })
                .into(),
                backupsSubscriberData: Some(proto::account_data::IAPSubscriberData {
                    subscriberId: FAKE_SUBSCRIBER_ID.to_vec(),
                    iapSubscriptionId: Some(
                        proto::account_data::iapsubscriber_data::IapSubscriptionId::OriginalTransactionId(5)
                    ),
                    ..Default::default()
                }).into(),
                ..Default::default()
            }
        }
    }

    impl proto::account_data::AccountSettings {
        fn test_data() -> Self {
            Self {
                phoneNumberSharingMode: proto::account_data::PhoneNumberSharingMode::EVERYBODY
                    .into(),
                customChatColors: vec![proto::chat_style::CustomChatColor::test_data()],
                defaultChatStyle: Some(proto::ChatStyle {
                    bubbleColor: Some(proto::chat_style::BubbleColor::CustomColorId(
                        FAKE_CUSTOM_COLOR_ID.0,
                    )),
                    wallpaper: None,
                    dimWallpaperInDarkMode: true,
                    special_fields: Default::default(),
                })
                .into(),
                ..Default::default()
            }
        }
    }

    const FAKE_PROFILE_KEY: ProfileKeyBytes = [0xaa; 32];
    const FAKE_SUBSCRIBER_ID: SubscriberId = [55; 32];
    const FAKE_USERNAME_LINK_ENTROPY: [u8; USERNAME_LINK_ENTROPY_SIZE] = [12; 32];
    const FAKE_USERNAME_SERVER_ID: Uuid = Uuid::from_bytes([10; 16]);
    const FAKE_CUSTOM_COLOR_ID: CustomColorId = proto::chat_style::CustomChatColor::TEST_ID;
    static FAKE_CUSTOM_COLOR: LazyLock<Arc<CustomChatColor>> =
        LazyLock::new(|| Arc::new(CustomChatColor::from_proto_test_data()));

    #[test]
    fn account_data_custom_colors_ordering() {
        let with_new_id = {
            let mut data = proto::account_data::AccountSettings::test_data();
            data.customChatColors
                .push(proto::chat_style::CustomChatColor {
                    id: 12345,
                    ..proto::chat_style::CustomChatColor::test_data()
                });
            data
        };
        let with_reversed_ids = {
            let mut data = with_new_id.clone();
            data.customChatColors.reverse();
            data
        };
        let with_new_id: AccountSettings<Store> = with_new_id
            .try_into_with(&TestContext::default())
            .expect("valid settings");
        let with_reversed_ids: AccountSettings<Store> = with_reversed_ids
            .try_into_with(&TestContext::default())
            .expect("valid settings");
        assert_ne!(with_new_id, with_reversed_ids);
    }

    impl AccountData<Store> {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                profile_key: FAKE_PROFILE_KEY,
                username: Some(UsernameData {
                    username: Username::new("abc.123").unwrap(),
                    link: Some(UsernameLink {
                        color: proto::account_data::username_link::Color::BLUE,
                        entropy: FAKE_USERNAME_LINK_ENTROPY,
                        server_id: FAKE_USERNAME_SERVER_ID,
                    }),
                }),
                given_name: "".to_string(),
                family_name: "".to_string(),
                account_settings: AccountSettings {
                    phone_number_sharing: PhoneSharing::WithEverybody,
                    default_chat_style: Some(ChatStyle {
                        wallpaper: None,
                        bubble_color: BubbleColor::Custom(FAKE_CUSTOM_COLOR.clone()),
                        dim_wallpaper_in_dark_mode: true,
                    }),
                    read_receipts: false,
                    sealed_sender_indicators: false,
                    typing_indicators: false,
                    link_previews: false,
                    not_discoverable_by_phone_number: false,
                    prefer_contact_avatars: false,
                    display_badges_on_profile: false,
                    keep_muted_chats_archived: false,
                    has_set_my_stories_privacy: false,
                    has_viewed_onboarding_story: false,
                    stories_disabled: false,
                    story_view_receipts_enabled: None,
                    has_seen_group_story_education_sheet: false,
                    has_completed_username_onboarding: false,
                    universal_expire_timer: None,
                    preferred_reaction_emoji: vec![],
                    custom_chat_colors: CustomColorMap::from_proto_test_data(),
                },
                avatar_url_path: "".to_string(),
                backup_subscription: Some(IapSubscriberData {
                    subscriber_id: FAKE_SUBSCRIBER_ID,
                    subscription_id: IapSubscriptionId::IosAppStoreOriginalTransactionId(5),
                }),
                donation_subscription: None,
            }
        }
    }

    #[test]
    fn valid_account_data() {
        assert_eq!(
            proto::AccountData::test_data().try_into_with(&TestContext::default()),
            Ok(AccountData::from_proto_test_data())
        );
    }

    #[test_case(|x| x.profileKey.clear() => Err(AccountDataError::InvalidProfileKey); "invalid_profile_key")]
    #[test_case(
        |x| x.username = Some("invalid".to_string()) => Err(AccountDataError::InvalidUsername(UsernameError::MissingSeparator));
        "invalid username"
    )]
    #[test_case(|x| {
            x.username = None;
            x.usernameLink = None.into();
        } => Ok(()); "no username")]
    #[test_case(|x| x.usernameLink = None.into() => Ok(()); "no username link")]
    #[test_case(|x| x.usernameLink.as_mut().unwrap().color = EnumOrUnknown::default() => Ok(()); "username_link_unknown_color")]
    #[test_case( |x| {
            x.username = None;
            x.usernameLink = Some(x.usernameLink.take().unwrap()).into();
        } => Err(AccountDataError::UsernameLinkWithoutUsername);
        "username_link_without_username"
    )]
    #[test_case(|x| x.accountSettings = None.into() => Err(AccountDataError::MissingSettings); "no_account_settings")]
    #[test_case(|x| x.backupsSubscriberData.as_mut().unwrap().subscriberId = vec![123] =>
        Err(AccountDataError::BackupSubscription(SubscriptionError::InvalidSubscriberId(1)));
        "invalid_subscriber_id")]
    #[test_case(|x| x.backupsSubscriberData.as_mut().unwrap().subscriberId = vec![] =>
        Err(AccountDataError::BackupSubscription(SubscriptionError::InvalidSubscriberId(0)));
        "empty_subscriber_id")]
    #[test_case(|x| x.backupsSubscriberData.as_mut().unwrap().iapSubscriptionId = None =>
        Err(AccountDataError::BackupSubscription(SubscriptionError::MissingIapSubscriptionId));
        "missing_subscriber_iap_id")]
    #[test_case(|x| {
            x.backupsSubscriberData = None.into();
            x.donationSubscriberData = None.into();
        } => Ok(()); "no_subscriptions"
    )]
    #[test_case(|x| {
        x.donationSubscriberData = Some(proto::account_data::SubscriberData {
            subscriberId: FAKE_SUBSCRIBER_ID.into(),
            ..Default::default()
        }).into();
    } => Err(AccountDataError::DonationSubscription(SubscriptionError::EmptyCurrency)); "empty_subscriber_currency")]
    #[test_case(
        |x| x.accountSettings.as_mut().unwrap().customChatColors.clear() =>
        Err(AccountDataError::ChatStyle(ChatStyleError::UnknownCustomColorId(FAKE_CUSTOM_COLOR_ID.0)));
        "account_data_default_style_invalid_custom_color"
    )]
    fn with(modifier: fn(&mut proto::AccountData)) -> Result<(), AccountDataError> {
        let mut data = proto::AccountData::test_data();
        modifier(&mut data);

        AccountData::<ValidateOnly>::try_from_with(data, &TestContext::default()).map(|_| ())
    }
}
