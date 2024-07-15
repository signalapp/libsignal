//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;

use crate::backup::frame::{RecipientId, RingerRecipientId};
use crate::backup::method::{Contains, Lookup, LookupPair};
use crate::backup::recipient::DestinationKind;
use crate::backup::time::Timestamp;
use crate::backup::TryFromWith;
use crate::proto::backup as proto;

/// Validated version of [`proto::AdHocCall`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct AdHocCall<Recipient> {
    pub id: CallId,
    pub timestamp: Timestamp,
    pub recipient: Recipient,
}

/// Validated version of [`proto::IndividualCall`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct IndividualCall {
    pub id: Option<CallId>,
    pub call_type: CallType,
    pub state: IndividualCallState,
    pub outgoing: bool,
    pub started_at: Timestamp,
}

/// Validated version of [`proto::GroupCall`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct GroupCall<Recipient> {
    pub id: Option<CallId>,
    pub state: GroupCallState,
    pub started_call_recipient: Option<Recipient>,
    pub started_at: Timestamp,
    pub ended_at: Timestamp,
}

/// An identifier for a call.
///
/// This is not referenced as a foreign key from elsewhere in a backup, but
/// corresponds to shared state across conversation members for a given call.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, serde::Serialize)]
pub struct CallId(u64);

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum CallError {
    /// call starter {0:?} not found,
    UnknownCallStarter(RecipientId),
    /// no record for ringer {0:?}
    NoRingerRecipient(RingerRecipientId),
    /// no record for ad-hoc {0:?}
    NoAdHocRecipient(RecipientId),
    /// ad-hoc recipient {0:?} is not a call link
    InvalidAdHocRecipient(RecipientId),
    /// call type is UNKNOWN_TYPE
    UnknownType,
    /// call state is UNKNOWN_STATE
    UnknownState,
    /// call direction is UNKNOWN_DIRECTION
    UnknownDirection,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum CallLinkError {
    /// call link restrictions is UNKNOWN
    UnknownRestrictions,
    /// expected {CALL_LINK_ADMIN_KEY_LEN:?}-byte admin key, found {0} bytes
    InvalidAdminKey(usize),
    /// expected {CALL_LINK_ROOT_KEY_LEN:?}-byte root key, found {0} bytes
    InvalidRootKey(usize),
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum CallType {
    Audio,
    Video,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum IndividualCallState {
    Accepted,
    NotAccepted,
    MissedByNotificationProfile,
    Missed,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum GroupCallState {
    /// No ring
    Generic,
    /// No ring, joined
    Joined,
    /// Incoming ring currently ongoing
    Ringing,
    /// Incoming ring, accepted
    Accepted,
    /// Incoming ring, missed
    Missed,
    /// Incoming ring, declined
    Declined,
    /// Incoming ring, auto-declined
    MissedByNotificationProfile,
    /// Outgoing ring was started
    OutgoingRing,
}

const CALL_LINK_ADMIN_KEY_LEN: usize = 32;
type CallLinkAdminKey = [u8; CALL_LINK_ADMIN_KEY_LEN];

const CALL_LINK_ROOT_KEY_LEN: usize = 16;
type CallLinkRootKey = [u8; CALL_LINK_ROOT_KEY_LEN];

/// Validated version of [`proto::CallLink`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct CallLink {
    pub admin_approval: bool,
    pub root_key: CallLinkRootKey,
    pub admin_key: Option<CallLinkAdminKey>,
    pub expiration: Timestamp,
    pub name: String,
}

impl TryFrom<proto::IndividualCall> for IndividualCall {
    type Error = CallError;

    fn try_from(call: proto::IndividualCall) -> Result<Self, Self::Error> {
        let proto::IndividualCall {
            callId,
            type_,
            state,
            direction,
            startedCallTimestamp,
            special_fields: _,
        } = call;

        let outgoing = {
            use proto::individual_call::Direction;
            match direction.enum_value_or_default() {
                Direction::UNKNOWN_DIRECTION => return Err(CallError::UnknownDirection),
                Direction::INCOMING => false,
                Direction::OUTGOING => true,
            }
        };

        let call_type = {
            use proto::individual_call::Type;
            match type_.enum_value_or_default() {
                Type::UNKNOWN_TYPE => return Err(CallError::UnknownType),
                Type::AUDIO_CALL => CallType::Audio,
                Type::VIDEO_CALL => CallType::Video,
            }
        };

        let state = {
            use proto::individual_call::State;
            match state.enum_value_or_default() {
                State::UNKNOWN_STATE => return Err(CallError::UnknownState),
                State::ACCEPTED => IndividualCallState::Accepted,
                State::MISSED => IndividualCallState::Missed,
                State::NOT_ACCEPTED => IndividualCallState::NotAccepted,
                State::MISSED_NOTIFICATION_PROFILE => {
                    IndividualCallState::MissedByNotificationProfile
                }
            }
        };

        let started_at = Timestamp::from_millis(startedCallTimestamp, "Call.timestamp");
        let id = callId.map(CallId);

        Ok(Self {
            id,
            call_type,
            state,
            started_at,
            outgoing,
        })
    }
}

impl<C: Contains<RecipientId> + Lookup<RecipientId, R>, R: Clone> TryFromWith<proto::GroupCall, C>
    for GroupCall<R>
{
    type Error = CallError;

    fn try_from_with(call: proto::GroupCall, context: &C) -> Result<Self, Self::Error> {
        let proto::GroupCall {
            callId,
            state,
            startedCallTimestamp,
            ringerRecipientId,
            startedCallRecipientId,
            endedCallTimestamp,
            special_fields: _,
        } = call;

        let started_call_recipient = startedCallRecipientId
            .map(|id| {
                let id = RecipientId(id);
                context
                    .lookup(&id)
                    .ok_or(CallError::UnknownCallStarter(id))
                    .cloned()
            })
            .transpose()?;

        let ringer_recipient_id = ringerRecipientId.map(|r| RingerRecipientId(RecipientId(r)));

        if let Some(ringer_recipient_id) = ringer_recipient_id {
            if !context.contains(&ringer_recipient_id.0) {
                return Err(CallError::NoRingerRecipient(ringer_recipient_id));
            }
        }

        let state = {
            use proto::group_call::State;
            match state.enum_value_or_default() {
                State::UNKNOWN_STATE => return Err(CallError::UnknownState),
                State::MISSED => GroupCallState::Missed,
                State::GENERIC => GroupCallState::Generic,
                State::JOINED => GroupCallState::Joined,
                State::RINGING => GroupCallState::Ringing,
                State::ACCEPTED => GroupCallState::Accepted,
                State::DECLINED => GroupCallState::Declined,
                State::MISSED_NOTIFICATION_PROFILE => GroupCallState::MissedByNotificationProfile,
                State::OUTGOING_RING => GroupCallState::OutgoingRing,
            }
        };

        let started_at =
            Timestamp::from_millis(startedCallTimestamp, "GroupCall.startedCallTimestamp");
        let ended_at = Timestamp::from_millis(endedCallTimestamp, "GroupCall.endedCallTimestamp");
        let id = callId.map(CallId);

        Ok(Self {
            id,
            state,
            started_call_recipient,
            started_at,
            ended_at,
        })
    }
}

impl<C: LookupPair<RecipientId, DestinationKind, R>, R: Clone + Debug>
    TryFromWith<proto::AdHocCall, C> for AdHocCall<R>
{
    type Error = CallError;

    fn try_from_with(item: proto::AdHocCall, context: &C) -> Result<Self, Self::Error> {
        let proto::AdHocCall {
            callId,
            recipientId,
            state,
            callTimestamp,
            special_fields: _,
        } = item;

        let id = CallId(callId);

        let recipient = RecipientId(recipientId);

        let (kind, reference) = context
            .lookup_pair(&recipient)
            .ok_or(CallError::NoAdHocRecipient(recipient))?;
        let recipient = match kind {
            DestinationKind::CallLink => reference.clone(),
            DestinationKind::Contact
            | DestinationKind::DistributionList
            | DestinationKind::Group
            | DestinationKind::ReleaseNotes
            | DestinationKind::Self_ => return Err(CallError::InvalidAdHocRecipient(recipient)),
        };

        {
            use proto::ad_hoc_call::State;
            match state.enum_value_or_default() {
                State::UNKNOWN_STATE => return Err(CallError::UnknownState),
                State::GENERIC => (),
            }
        };

        let timestamp = Timestamp::from_millis(callTimestamp, "AdHocCall.startedCallTimestamp");

        Ok(Self {
            id,
            timestamp,
            recipient,
        })
    }
}

impl TryFrom<proto::CallLink> for CallLink {
    type Error = CallLinkError;

    fn try_from(value: proto::CallLink) -> Result<Self, Self::Error> {
        let proto::CallLink {
            rootKey,
            adminKey,
            name,
            restrictions,
            expirationMs,
            special_fields: _,
        } = value;

        let root_key = rootKey
            .try_into()
            .map_err(|key: Vec<u8>| CallLinkError::InvalidRootKey(key.len()))?;

        let admin_key = adminKey
            .map(|key| {
                key.try_into()
                    .map_err(|key: Vec<u8>| CallLinkError::InvalidAdminKey(key.len()))
            })
            .transpose()?;

        let admin_approval = {
            use proto::call_link::Restrictions;
            match restrictions.enum_value_or_default() {
                Restrictions::UNKNOWN => return Err(CallLinkError::UnknownRestrictions),
                Restrictions::NONE => false,
                Restrictions::ADMIN_APPROVAL => true,
            }
        };
        let expiration = Timestamp::from_millis(expirationMs, "CallLink.expirationMs");

        Ok(Self {
            root_key,
            admin_approval,
            admin_key,
            expiration,
            name,
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    use protobuf::EnumOrUnknown;
    use test_case::test_case;

    use crate::backup::method::Contains;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;
    use crate::backup::TryIntoWith as _;

    use super::*;

    impl proto::IndividualCall {
        const TEST_ID: CallId = CallId(33333);

        pub(crate) fn test_data() -> Self {
            Self {
                callId: Some(Self::TEST_ID.0),
                state: proto::individual_call::State::ACCEPTED.into(),
                type_: proto::individual_call::Type::VIDEO_CALL.into(),
                direction: proto::individual_call::Direction::OUTGOING.into(),
                startedCallTimestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                ..Default::default()
            }
        }
    }

    impl proto::GroupCall {
        pub(crate) fn test_data() -> Self {
            Self {
                callId: None,
                ringerRecipientId: Some(proto::Recipient::TEST_ID),
                state: proto::group_call::State::ACCEPTED.into(),
                startedCallTimestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                endedCallTimestamp: MillisecondsSinceEpoch::TEST_VALUE.0 + 1000,
                ..Default::default()
            }
        }
    }

    pub(crate) const TEST_CALL_LINK_RECIPIENT_ID: RecipientId = RecipientId(987654);
    pub(crate) const NONEXISTENT_RECIPIENT: RecipientId = RecipientId(9999999999999999999);

    impl proto::AdHocCall {
        const TEST_ID: u64 = 888888;

        fn test_data() -> Self {
            Self {
                callId: Self::TEST_ID,
                recipientId: TEST_CALL_LINK_RECIPIENT_ID.0,
                state: proto::ad_hoc_call::State::GENERIC.into(),
                callTimestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                ..Default::default()
            }
        }
    }

    const TEST_CALL_LINK_ROOT_KEY: CallLinkRootKey = [b'R'; 16];
    const TEST_CALL_LINK_ADMIN_KEY: CallLinkAdminKey = [b'A'; 32];
    impl proto::CallLink {
        fn test_data() -> Self {
            Self {
                rootKey: TEST_CALL_LINK_ROOT_KEY.to_vec(),
                adminKey: Some(TEST_CALL_LINK_ADMIN_KEY.to_vec()),
                restrictions: proto::call_link::Restrictions::NONE.into(),
                expirationMs: MillisecondsSinceEpoch::TEST_VALUE.0,
                ..Default::default()
            }
        }
    }

    struct TestContext;

    impl Contains<RecipientId> for TestContext {
        fn contains(&self, key: &RecipientId) -> bool {
            matches!(
                key,
                &RecipientId(proto::Recipient::TEST_ID) | &TEST_CALL_LINK_RECIPIENT_ID
            )
        }
    }

    impl Lookup<RecipientId, DestinationKind> for TestContext {
        fn lookup(&self, key: &RecipientId) -> Option<&DestinationKind> {
            match key {
                RecipientId(proto::Recipient::TEST_ID) => Some(&DestinationKind::Contact),
                &TEST_CALL_LINK_RECIPIENT_ID => Some(&DestinationKind::CallLink),
                _ => None,
            }
        }
    }

    impl LookupPair<RecipientId, DestinationKind, RecipientId> for TestContext {
        fn lookup_pair<'a>(
            &'a self,
            key: &'a RecipientId,
        ) -> Option<(&'a DestinationKind, &'a RecipientId)> {
            match key {
                RecipientId(proto::Recipient::TEST_ID) => Some((&DestinationKind::Contact, key)),
                &TEST_CALL_LINK_RECIPIENT_ID => Some((&DestinationKind::CallLink, key)),
                _ => None,
            }
        }
    }

    trait InvalidCallType {
        fn unknown_type(call: &mut Self);
    }

    trait InvalidCallState {
        fn unknown_state(call: &mut Self);
    }

    impl InvalidCallType for proto::IndividualCall {
        fn unknown_type(call: &mut Self) {
            call.type_ = EnumOrUnknown::default();
        }
    }

    impl InvalidCallState for proto::IndividualCall {
        fn unknown_state(call: &mut Self) {
            call.state = EnumOrUnknown::default();
        }
    }

    fn unknown_direction(call: &mut proto::IndividualCall) {
        call.direction = EnumOrUnknown::default();
    }

    #[test]
    fn valid_individual_call() {
        assert_eq!(
            proto::IndividualCall::test_data().try_into(),
            Ok(IndividualCall {
                id: Some(proto::IndividualCall::TEST_ID),
                call_type: CallType::Video,
                state: IndividualCallState::Accepted,
                outgoing: true,
                started_at: Timestamp::test_value(),
            })
        );
    }

    #[test_case(InvalidCallType::unknown_type, Err(CallError::UnknownType))]
    #[test_case(InvalidCallState::unknown_state, Err(CallError::UnknownState))]
    #[test_case(unknown_direction, Err(CallError::UnknownDirection))]
    fn individual_call(
        modifier: impl FnOnce(&mut proto::IndividualCall),
        expected: Result<(), CallError>,
    ) {
        let mut call = proto::IndividualCall::test_data();
        modifier(&mut call);
        assert_eq!(call.try_into().map(|_: IndividualCall| ()), expected);
    }

    fn no_ringer_id(call: &mut proto::GroupCall) {
        call.ringerRecipientId = None;
    }
    fn wrong_wringer_id(call: &mut proto::GroupCall) {
        call.ringerRecipientId = Some(NONEXISTENT_RECIPIENT.0);
    }

    impl InvalidCallState for proto::GroupCall {
        fn unknown_state(call: &mut Self) {
            call.state = EnumOrUnknown::default();
        }
    }

    #[test_case(no_ringer_id, Ok(()))]
    #[test_case(
        wrong_wringer_id,
        Err(CallError::NoRingerRecipient(RingerRecipientId(NONEXISTENT_RECIPIENT)))
    )]
    #[test_case(InvalidCallState::unknown_state, Err(CallError::UnknownState))]
    fn group_call(modifier: impl FnOnce(&mut proto::GroupCall), expected: Result<(), CallError>) {
        let mut call = proto::GroupCall::test_data();
        modifier(&mut call);
        assert_eq!(
            call.try_into_with(&TestContext).map(|_: GroupCall<_>| ()),
            expected
        );
    }

    impl InvalidCallState for proto::AdHocCall {
        fn unknown_state(call: &mut Self) {
            call.state = EnumOrUnknown::default();
        }
    }

    fn invalid_ad_hoc_recipient(call: &mut proto::AdHocCall) {
        call.recipientId = NONEXISTENT_RECIPIENT.0;
    }

    fn ad_hoc_recipient_not_call(call: &mut proto::AdHocCall) {
        call.recipientId = proto::Recipient::TEST_ID;
    }

    #[test]
    fn valid_ad_hoc_call() {
        assert_eq!(
            proto::AdHocCall::test_data().try_into_with(&TestContext),
            Ok(AdHocCall {
                id: CallId(proto::AdHocCall::TEST_ID),
                timestamp: Timestamp::test_value(),
                recipient: TEST_CALL_LINK_RECIPIENT_ID,
            })
        );
    }

    #[test_case(InvalidCallState::unknown_state, Err(CallError::UnknownState))]
    #[test_case(
        invalid_ad_hoc_recipient,
        Err(CallError::NoAdHocRecipient(NONEXISTENT_RECIPIENT))
    )]
    #[test_case(
        ad_hoc_recipient_not_call,
        Err(CallError::InvalidAdHocRecipient(RecipientId(proto::Recipient::TEST_ID)))
    )]
    fn ad_hoc_call(modifier: impl FnOnce(&mut proto::AdHocCall), expected: Result<(), CallError>) {
        let mut call = proto::AdHocCall::test_data();
        modifier(&mut call);
        assert_eq!(
            call.try_into_with(&TestContext).map(|_: AdHocCall<_>| ()),
            expected
        );
    }

    #[test]
    fn valid_call_link() {
        assert_eq!(
            proto::CallLink::test_data().try_into(),
            Ok(CallLink {
                admin_approval: false,
                root_key: TEST_CALL_LINK_ROOT_KEY,
                admin_key: Some(TEST_CALL_LINK_ADMIN_KEY),
                expiration: Timestamp::test_value(),
                name: "".to_string(),
            })
        );
    }

    fn invalid_root_key(call: &mut proto::CallLink) {
        call.rootKey = vec![123];
    }
    fn invalid_admin_key(call: &mut proto::CallLink) {
        call.adminKey = Some(vec![123])
    }
    fn no_admin_key(call: &mut proto::CallLink) {
        call.adminKey = None;
    }
    fn unknown_restrictions(call: &mut proto::CallLink) {
        call.restrictions = EnumOrUnknown::default();
    }

    #[test_case(invalid_root_key, Err(CallLinkError::InvalidRootKey(1)))]
    #[test_case(invalid_admin_key, Err(CallLinkError::InvalidAdminKey(1)))]
    #[test_case(no_admin_key, Ok(()))]
    #[test_case(unknown_restrictions, Err(CallLinkError::UnknownRestrictions))]
    fn call_link(modifier: impl FnOnce(&mut proto::CallLink), expected: Result<(), CallLinkError>) {
        let mut link = proto::CallLink::test_data();
        modifier(&mut link);
        assert_eq!(link.try_into().map(|_: CallLink| ()), expected);
    }
}
