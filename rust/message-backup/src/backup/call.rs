//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::frame::{RecipientId, RingerRecipientId};
use crate::backup::method::Contains;
use crate::backup::time::Timestamp;
use crate::backup::TryFromWith;
use crate::proto::backup as proto;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Call {
    pub call_type: CallType,
    pub state: CallState,
    pub outgoing: bool,
    pub timestamp: Timestamp,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum CallError {
    /// multiple records with the same ID
    DuplicateId,
    /// no record for {0:?}
    NoConversation(RecipientId),
    /// no record for {0:?}
    NoRingerRecipient(RingerRecipientId),
    /// call type is UNKNOWN_TYPE
    UnknownType,
    /// call state is UNKNOWN_EVENT
    UnknownState,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum CallType {
    Audio,
    Video,
    Group,
    AdHoc,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum CallState {
    Completed,
    DeclinedByUser,
    DeclinedByNotificationProfile,
    Missed,
}

impl<C: Contains<RecipientId>> TryFromWith<proto::Call, C> for Call {
    type Error = CallError;

    fn try_from_with(call: proto::Call, context: &C) -> Result<Self, Self::Error> {
        let proto::Call {
            callId: _,
            conversationRecipientId,
            type_,
            outgoing,
            ringerRecipientId,
            state,
            timestamp,
            special_fields: _,
        } = call;

        let conversation_recipient_id = RecipientId(conversationRecipientId);
        let ringer_recipient_id = ringerRecipientId.map(|r| RingerRecipientId(RecipientId(r)));

        if !context.contains(&conversation_recipient_id) {
            return Err(CallError::NoConversation(conversation_recipient_id));
        }

        if let Some(ringer_recipient_id) = ringer_recipient_id {
            if !context.contains(&ringer_recipient_id.0) {
                return Err(CallError::NoRingerRecipient(ringer_recipient_id));
            }
        }

        let call_type = {
            use proto::call::Type;
            match type_.enum_value_or_default() {
                Type::UNKNOWN_TYPE => return Err(CallError::UnknownType),
                Type::AUDIO_CALL => CallType::Audio,
                Type::VIDEO_CALL => CallType::Video,
                Type::GROUP_CALL => CallType::Group,
                Type::AD_HOC_CALL => CallType::AdHoc,
            }
        };

        let state = {
            use proto::call::State;
            match state.enum_value_or_default() {
                State::UNKNOWN_EVENT => return Err(CallError::UnknownState),
                State::COMPLETED => CallState::Completed,
                State::DECLINED_BY_USER => CallState::DeclinedByUser,
                State::DECLINED_BY_NOTIFICATION_PROFILE => CallState::DeclinedByNotificationProfile,
                State::MISSED => CallState::Missed,
            }
        };

        let timestamp = Timestamp::from_millis(timestamp, "Call.timestamp");

        Ok(Call {
            call_type,
            state,
            outgoing,
            timestamp,
        })
    }
}

#[cfg(test)]
mod test {
    use protobuf::EnumOrUnknown;
    use test_case::test_case;

    use crate::backup::time::testutil::MillisecondsSinceEpoch;
    use crate::backup::TryIntoWith as _;

    use super::*;

    impl proto::Call {
        pub(crate) const TEST_ID: u64 = 33333;
        pub(crate) fn test_data() -> Self {
            Self {
                callId: Self::TEST_ID,
                conversationRecipientId: proto::Recipient::TEST_ID,
                ringerRecipientId: Some(proto::Recipient::TEST_ID),
                outgoing: true,
                state: proto::call::State::DECLINED_BY_USER.into(),
                type_: proto::call::Type::AD_HOC_CALL.into(),
                timestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                ..Default::default()
            }
        }
    }

    struct TestContext;

    impl Contains<RecipientId> for TestContext {
        fn contains(&self, key: &RecipientId) -> bool {
            key == &RecipientId(proto::Recipient::TEST_ID)
        }
    }

    #[test]
    fn valid_call() {
        assert_eq!(
            proto::Call::test_data().try_into_with(&TestContext),
            Ok(Call {
                call_type: CallType::AdHoc,
                state: CallState::DeclinedByUser,
                outgoing: true,
                timestamp: Timestamp::test_value(),
            })
        );
    }

    fn no_ringer_id(call: &mut proto::Call) {
        call.ringerRecipientId = None;
    }
    fn wrong_wringer_id(call: &mut proto::Call) {
        call.ringerRecipientId = Some(proto::Recipient::TEST_ID + 1);
    }
    fn unknown_type(call: &mut proto::Call) {
        call.type_ = EnumOrUnknown::default();
    }
    fn unknown_state(call: &mut proto::Call) {
        call.state = EnumOrUnknown::default();
    }

    #[test_case(no_ringer_id, Ok(()))]
    #[test_case(
        wrong_wringer_id,
        Err(CallError::NoRingerRecipient(RingerRecipientId(RecipientId(proto::Recipient::TEST_ID + 1))))
    )]
    #[test_case(unknown_type, Err(CallError::UnknownType))]
    #[test_case(unknown_state, Err(CallError::UnknownState))]
    fn call(modifier: impl FnOnce(&mut proto::Call), expected: Result<(), CallError>) {
        let mut call = proto::Call::test_data();
        modifier(&mut call);
        assert_eq!(call.try_into_with(&TestContext).map(|_: Call| ()), expected);
    }
}
