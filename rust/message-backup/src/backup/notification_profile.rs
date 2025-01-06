//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complains about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use intmap::IntMap;
use itertools::Itertools;

use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::{DestinationKind, MinimalRecipientData};
use crate::backup::serialize::{SerializeOrder, UnorderedList};
use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampError};
use crate::backup::{Color, ColorError, TryFromWith};
use crate::proto::backup as proto;

/// Validated version of [`proto::NotificationProfile`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct NotificationProfile<Recipient> {
    name: String,
    emoji: Option<String>,
    color: Color,
    created_at: Timestamp,
    allow_all_calls: bool,
    allow_all_mentions: bool,
    enabled: bool,
    start_time: ClockTime,
    end_time: ClockTime,
    days_enabled: UnorderedList<DayOfWeek>,
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    allowed_members: UnorderedList<Recipient>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum NotificationProfileError {
    /// missing name
    MissingName,
    /// emoji is present but empty
    EmojiIsPresentButEmpty,
    /// color was not opaque (ARGB 0x{0:08X})
    ColorNotOpaque(u32),
    /// member {0:?} is unknown
    UnknownMember(RecipientId),
    /// member {0:?} appears multiple times
    DuplicateMember(RecipientId),
    /// member {0:?} is a {1:?} not a contact or group
    MemberWrongKind(RecipientId, DestinationKind),
    /// invalid 24-hour clock time {0:04}
    InvalidClockTime(u32),
    /// invalid day of week value {0}
    InvalidWeekday(i32),
    /// {0:?} appears twice in enabledDays
    DuplicateDay(DayOfWeek),
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryFromWith<proto::NotificationProfile, C> for NotificationProfile<R>
{
    type Error = NotificationProfileError;
    fn try_from_with(item: proto::NotificationProfile, context: &C) -> Result<Self, Self::Error> {
        let proto::NotificationProfile {
            name,
            emoji,
            color,
            createdAtMs,
            allowAllCalls,
            allowAllMentions,
            scheduleEnabled,
            scheduleStartTime,
            scheduleEndTime,
            scheduleDaysEnabled,
            allowedMembers,
            special_fields: _,
        } = item;

        if name.is_empty() {
            return Err(NotificationProfileError::MissingName);
        }

        if emoji.as_ref().is_some_and(|e| e.is_empty()) {
            return Err(NotificationProfileError::EmojiIsPresentButEmpty);
        }

        let color = Color::try_from(color)?;

        let created_at =
            Timestamp::from_millis(createdAtMs, "NotificationProfile.createdAtMs", context)?;

        let mut seen_members = IntMap::default();
        let allowed_members = allowedMembers
            .into_iter()
            .map(|id| {
                let id = RecipientId(id);
                if seen_members.insert(id, ()).is_some() {
                    return Err(NotificationProfileError::DuplicateMember(id));
                }
                let (recipient_data, recipient) = context
                    .lookup_pair(&id)
                    .ok_or(NotificationProfileError::UnknownMember(id))?;
                match recipient_data.as_ref() {
                    DestinationKind::Contact | DestinationKind::Group => Ok(recipient.clone()),
                    kind @ (DestinationKind::DistributionList
                    | DestinationKind::Self_
                    | DestinationKind::ReleaseNotes
                    | DestinationKind::CallLink) => {
                        Err(NotificationProfileError::MemberWrongKind(id, *kind))
                    }
                }
            })
            .try_collect()?;

        let start_time = ClockTime::try_from(scheduleStartTime)?;
        let end_time = ClockTime::try_from(scheduleEndTime)?;
        // There's no range check here; if endTime <= startTime, the profile is active through the following day.

        let mut days_enabled = vec![];
        for day in scheduleDaysEnabled {
            let day = DayOfWeek::try_from(day)?;
            // This is quadratic, but N is at most 7 in a well-formed backup.
            if days_enabled.contains(&day) {
                return Err(NotificationProfileError::DuplicateDay(day));
            }
            days_enabled.push(day);
        }

        Ok(Self {
            name,
            emoji,
            color,
            created_at,
            allow_all_calls: allowAllCalls,
            allow_all_mentions: allowAllMentions,
            enabled: scheduleEnabled,
            start_time,
            end_time,
            days_enabled: days_enabled.into(),
            allowed_members,
        })
    }
}

impl<R> SerializeOrder for NotificationProfile<R> {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.created_at.cmp(&other.created_at)
    }
}

impl From<ColorError> for NotificationProfileError {
    fn from(value: ColorError) -> Self {
        match value {
            ColorError::NotOpaque(color) => NotificationProfileError::ColorNotOpaque(color),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, serde::Serialize)]
#[serde(transparent)]
struct ClockTime(u16);

impl TryFrom<u32> for ClockTime {
    type Error = NotificationProfileError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value >= 2400 {
            return Err(NotificationProfileError::InvalidClockTime(value));
        }
        if value % 100 >= 60 {
            return Err(NotificationProfileError::InvalidClockTime(value));
        }
        Ok(Self(value.try_into().expect("checked upper bound")))
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, serde::Serialize)]
pub enum DayOfWeek {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl TryFrom<protobuf::EnumOrUnknown<proto::notification_profile::DayOfWeek>> for DayOfWeek {
    type Error = NotificationProfileError;

    fn try_from(
        value: protobuf::EnumOrUnknown<proto::notification_profile::DayOfWeek>,
    ) -> Result<Self, Self::Error> {
        match value.enum_value_or_default() {
            proto::notification_profile::DayOfWeek::UNKNOWN => {
                Err(NotificationProfileError::InvalidWeekday(value.value()))
            }
            proto::notification_profile::DayOfWeek::MONDAY => Ok(Self::Monday),
            proto::notification_profile::DayOfWeek::TUESDAY => Ok(Self::Tuesday),
            proto::notification_profile::DayOfWeek::WEDNESDAY => Ok(Self::Wednesday),
            proto::notification_profile::DayOfWeek::THURSDAY => Ok(Self::Thursday),
            proto::notification_profile::DayOfWeek::FRIDAY => Ok(Self::Friday),
            proto::notification_profile::DayOfWeek::SATURDAY => Ok(Self::Saturday),
            proto::notification_profile::DayOfWeek::SUNDAY => Ok(Self::Sunday),
        }
    }
}

impl SerializeOrder for DayOfWeek {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cmp(other)
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;
    use crate::backup::recipient::FullRecipientData;
    use crate::backup::testutil::TestContext;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;
    use crate::backup::TryIntoWith as _;

    impl proto::NotificationProfile {
        fn test_data() -> Self {
            Self {
                name: "Test".into(),
                emoji: None,
                color: 0xFFFF0000,
                createdAtMs: MillisecondsSinceEpoch::TEST_VALUE.0,
                allowAllCalls: true,
                allowAllMentions: true,
                scheduleEnabled: true,
                scheduleStartTime: 1320,
                scheduleEndTime: 1320,
                scheduleDaysEnabled: vec![
                    proto::notification_profile::DayOfWeek::WEDNESDAY.into(),
                    proto::notification_profile::DayOfWeek::MONDAY.into(),
                ],
                allowedMembers: vec![TestContext::CONTACT_ID.0],
                ..Default::default()
            }
        }
    }

    #[test]
    fn valid_notification_profile() {
        assert_eq!(
            proto::NotificationProfile::test_data().try_into_with(&TestContext::default()),
            Ok(NotificationProfile::<FullRecipientData> {
                name: "Test".into(),
                emoji: None,
                color: Color(0xFFFF0000),
                created_at: Timestamp::test_value(),
                allow_all_calls: true,
                allow_all_mentions: true,
                enabled: true,
                start_time: ClockTime(1320),
                end_time: ClockTime(1320),
                days_enabled: vec![DayOfWeek::Wednesday, DayOfWeek::Monday].into(),
                allowed_members: vec![TestContext::contact_recipient().clone()].into(),
            })
        )
    }

    #[test_case(|x| x.name = "".into() => Err(NotificationProfileError::MissingName); "empty name")]
    #[test_case(|x| x.emoji = Some("⭕️".into()) => Ok(()); "emoji allowed")]
    #[test_case(|x| x.emoji = Some("".into()) => Err(NotificationProfileError::EmojiIsPresentButEmpty); "emoji empty")]
    #[test_case(|x| x.color = 0 => Err(NotificationProfileError::ColorNotOpaque(0)); "transparent color")]
    #[test_case(|x| x.scheduleStartTime = 0 => Ok(()); "midnight is zero")]
    #[test_case(|x| x.scheduleStartTime = 2400 => Err(NotificationProfileError::InvalidClockTime(2400)); "midnight is not 2400")]
    #[test_case(|x| x.scheduleStartTime = 5000 => Err(NotificationProfileError::InvalidClockTime(5000)); "out of range completely")]
    #[test_case(|x| x.scheduleStartTime = 1170 => Err(NotificationProfileError::InvalidClockTime(1170)); "bad minutes")]
    #[test_case(|x| x.scheduleEndTime = 1170 => Err(NotificationProfileError::InvalidClockTime(1170)); "endTime is also checked")]
    #[test_case(|x| x.scheduleDaysEnabled = vec![] => Ok(()); "no days selected")]
    #[test_case(|x| {
        x.scheduleDaysEnabled = vec![
            proto::notification_profile::DayOfWeek::WEDNESDAY.into(),
            proto::notification_profile::DayOfWeek::UNKNOWN.into(),
        ];
    } => Err(NotificationProfileError::InvalidWeekday(0)); "invalid weekday")]
    #[test_case(|x| {
        x.scheduleDaysEnabled = vec![
            proto::notification_profile::DayOfWeek::WEDNESDAY.into(),
            proto::notification_profile::DayOfWeek::MONDAY.into(),
            proto::notification_profile::DayOfWeek::MONDAY.into(),
        ];
    } => Err(NotificationProfileError::DuplicateDay(DayOfWeek::Monday)); "duplicate weekday")]
    #[test_case(|x| x.allowedMembers = vec![] => Ok(()); "no member exceptions selected")]
    #[test_case(|x| x.allowedMembers = vec![TestContext::SELF_ID.0] => Err(NotificationProfileError::MemberWrongKind(TestContext::SELF_ID, DestinationKind::Self_)); "cannot include Self")]
    #[test_case(|x| x.allowedMembers = vec![TestContext::CONTACT_ID.0, TestContext::CONTACT_ID.0] => Err(NotificationProfileError::DuplicateMember(TestContext::CONTACT_ID)); "cannot include duplicates")]
    #[test_case(|x| x.allowedMembers = vec![1000] => Err(NotificationProfileError::UnknownMember(RecipientId(1000))); "unknown member")]
    #[test_case(
        |x| x.createdAtMs = MillisecondsSinceEpoch::FAR_FUTURE.0 =>
        Err(NotificationProfileError::InvalidTimestamp(TimestampError("NotificationProfile.createdAtMs", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid createdAtMs"
    )]
    fn profile(
        mutator: fn(&mut proto::NotificationProfile),
    ) -> Result<(), NotificationProfileError> {
        let mut profile = proto::NotificationProfile::test_data();
        mutator(&mut profile);

        profile
            .try_into_with(&TestContext::default())
            .map(|_: NotificationProfile<FullRecipientData>| ())
    }
}
