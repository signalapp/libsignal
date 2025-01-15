// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::call::{GroupCall, IndividualCall};
use crate::backup::chat::group::GroupChatUpdate;
use crate::backup::chat::ChatItemError;
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::{ChatItemAuthorKind, ChatRecipientKind, MinimalRecipientData, E164};
use crate::backup::time::{Duration, ReportUnusualTimestamp};
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of [`proto::chat_update_message::Update`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum UpdateMessage<Recipient> {
    Simple(SimpleChatUpdate),
    GroupChange { updates: Vec<GroupChatUpdate> },
    ExpirationTimerChange { expires_in: Duration },
    ProfileChange { previous: String, new: String },
    ThreadMerge { previous_e164: E164 },
    SessionSwitchover { e164: E164 },
    IndividualCall(IndividualCall),
    GroupCall(GroupCall<Recipient>),
    LearnedProfileUpdate(proto::learned_profile_chat_update::PreviousName),
}

/// Validated version of [`proto::simple_chat_update::Type`].
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum SimpleChatUpdate {
    JoinedSignal,
    IdentityUpdate,
    IdentityVerified,
    IdentityDefault,
    ChangeNumber,
    EndSession,
    ChatSessionRefresh,
    BadDecrypt,
    PaymentsActivated,
    PaymentActivationRequest,
    UnsupportedProtocolMessage,
    ReleaseChannelDonationRequest,
    ReportedSpam,
    Blocked,
    Unblocked,
    MessageRequestAccepted,
}

impl<C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp, R: Clone>
    TryFromWith<proto::ChatUpdateMessage, C> for UpdateMessage<R>
{
    type Error = ChatItemError;

    fn try_from_with(item: proto::ChatUpdateMessage, context: &C) -> Result<Self, Self::Error> {
        let proto::ChatUpdateMessage {
            update,
            special_fields: _,
        } = item;

        let update = update.ok_or(ChatItemError::UpdateIsEmpty)?;

        use proto::chat_update_message::Update;
        Ok(match update {
            Update::SimpleUpdate(proto::SimpleChatUpdate {
                type_,
                special_fields: _,
            }) => UpdateMessage::Simple({
                use proto::simple_chat_update::Type;
                match type_.enum_value_or_default() {
                    Type::UNKNOWN => return Err(ChatItemError::ChatUpdateUnknown),
                    Type::JOINED_SIGNAL => SimpleChatUpdate::JoinedSignal,
                    Type::IDENTITY_UPDATE => SimpleChatUpdate::IdentityUpdate,
                    Type::IDENTITY_VERIFIED => SimpleChatUpdate::IdentityVerified,
                    Type::IDENTITY_DEFAULT => SimpleChatUpdate::IdentityDefault,
                    Type::CHANGE_NUMBER => SimpleChatUpdate::ChangeNumber,
                    Type::END_SESSION => SimpleChatUpdate::EndSession,
                    Type::CHAT_SESSION_REFRESH => SimpleChatUpdate::ChatSessionRefresh,
                    Type::BAD_DECRYPT => SimpleChatUpdate::BadDecrypt,
                    Type::PAYMENTS_ACTIVATED => SimpleChatUpdate::PaymentsActivated,
                    Type::PAYMENT_ACTIVATION_REQUEST => SimpleChatUpdate::PaymentActivationRequest,
                    Type::UNSUPPORTED_PROTOCOL_MESSAGE => {
                        SimpleChatUpdate::UnsupportedProtocolMessage
                    }
                    Type::RELEASE_CHANNEL_DONATION_REQUEST => {
                        SimpleChatUpdate::ReleaseChannelDonationRequest
                    }
                    Type::REPORTED_SPAM => SimpleChatUpdate::ReportedSpam,
                    Type::BLOCKED => SimpleChatUpdate::Blocked,
                    Type::UNBLOCKED => SimpleChatUpdate::Unblocked,
                    Type::MESSAGE_REQUEST_ACCEPTED => SimpleChatUpdate::MessageRequestAccepted,
                }
            }),
            Update::GroupChange(proto::GroupChangeChatUpdate {
                updates,
                special_fields: _,
            }) => {
                if updates.is_empty() {
                    return Err(ChatItemError::GroupChangeIsEmpty);
                }
                UpdateMessage::GroupChange {
                    updates: updates
                        .into_iter()
                        .enumerate()
                        .map(
                            |(
                                i,
                                proto::group_change_chat_update::Update {
                                    update,
                                    special_fields: _,
                                },
                            )| {
                                let update =
                                    update.ok_or(ChatItemError::GroupChangeUpdateIsEmpty(i))?;
                                GroupChatUpdate::try_from(update).map_err(ChatItemError::from)
                            },
                        )
                        .collect::<Result<_, _>>()?,
                }
            }
            Update::ExpirationTimerChange(proto::ExpirationTimerChatUpdate {
                expiresInMs,
                special_fields: _,
            }) => UpdateMessage::ExpirationTimerChange {
                expires_in: Duration::from_millis(expiresInMs),
            },
            Update::ProfileChange(proto::ProfileChangeChatUpdate {
                previousName,
                newName,
                special_fields: _,
            }) => {
                if previousName.is_empty() || newName.is_empty() {
                    return Err(ChatItemError::ProfileChangeMissingNames);
                }
                UpdateMessage::ProfileChange {
                    previous: previousName,
                    new: newName,
                }
            }
            Update::ThreadMerge(proto::ThreadMergeChatUpdate {
                previousE164,
                special_fields: _,
            }) => {
                let previous_e164 = previousE164
                    .try_into()
                    .map_err(|_| ChatItemError::InvalidE164)?;
                UpdateMessage::ThreadMerge { previous_e164 }
            }
            Update::SessionSwitchover(proto::SessionSwitchoverChatUpdate {
                e164,
                special_fields: _,
            }) => {
                let e164 = e164.try_into().map_err(|_| ChatItemError::InvalidE164)?;
                UpdateMessage::SessionSwitchover { e164 }
            }
            Update::IndividualCall(call) => {
                UpdateMessage::IndividualCall(call.try_into_with(context)?)
            }
            Update::GroupCall(call) => UpdateMessage::GroupCall(call.try_into_with(context)?),
            Update::LearnedProfileChange(proto::LearnedProfileChatUpdate {
                previousName,
                special_fields: _,
            }) => UpdateMessage::LearnedProfileUpdate(
                previousName.ok_or(ChatItemError::LearnedProfileIsEmpty)?,
            ),
        })
    }
}

impl<R> UpdateMessage<R> {
    // This could be folded into the initial creation of the message,
    // but then it wouldn't fit the TryFromWith signature (or would require a tuple).
    pub(super) fn validate_author(&self, author: &ChatItemAuthorKind) -> Result<(), ChatItemError> {
        match self {
            UpdateMessage::Simple(
                update @ (SimpleChatUpdate::JoinedSignal
                | SimpleChatUpdate::EndSession
                | SimpleChatUpdate::ChatSessionRefresh
                | SimpleChatUpdate::IdentityUpdate),
            ) => {
                // We allow Self for these, for a few reasons:
                // - "Note to Self" can have ChatSessionRefresh (and IdentityUpdate, if things go
                //   very wrong)
                // - An E164-based thread can get merged into Self if the user takes a phone number
                //   that formerly belonged to a contact.
                match author {
                    ChatItemAuthorKind::Contact { .. } | ChatItemAuthorKind::Self_ => Ok(()),
                    ChatItemAuthorKind::ReleaseNotes => {
                        Err(ChatItemError::ChatUpdateNotFromAci(*update))
                    }
                }
            }
            UpdateMessage::Simple(
                update @ (SimpleChatUpdate::IdentityDefault
                | SimpleChatUpdate::IdentityVerified
                | SimpleChatUpdate::ChangeNumber
                | SimpleChatUpdate::BadDecrypt
                | SimpleChatUpdate::UnsupportedProtocolMessage),
            ) => {
                // Similar to the above, we allow Self for these too, just not PNIs.
                if !author.is_valid_sender_account() {
                    Err(ChatItemError::ChatUpdateNotFromContact(*update))
                } else {
                    Ok(())
                }
            }
            UpdateMessage::Simple(
                update @ (SimpleChatUpdate::PaymentActivationRequest
                | SimpleChatUpdate::PaymentsActivated),
            ) => {
                if !(author.is_contact_with_aci() || matches!(author, ChatItemAuthorKind::Self_)) {
                    Err(ChatItemError::ChatUpdateNotFromAci(*update))
                } else {
                    Ok(())
                }
            }
            UpdateMessage::Simple(
                update @ (SimpleChatUpdate::ReportedSpam
                | SimpleChatUpdate::Blocked
                | SimpleChatUpdate::Unblocked
                | SimpleChatUpdate::MessageRequestAccepted),
            ) => {
                if !matches!(author, ChatItemAuthorKind::Self_) {
                    Err(ChatItemError::ChatUpdateNotFromSelf(*update))
                } else {
                    Ok(())
                }
            }
            UpdateMessage::Simple(SimpleChatUpdate::ReleaseChannelDonationRequest) => {
                if !matches!(author, ChatItemAuthorKind::ReleaseNotes) {
                    Err(ChatItemError::DonationRequestNotFromReleaseNotesRecipient)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::GroupChange { .. } => {
                // For GV2 this could be limited to ACIs only, but GV1 messages still exist.
                if !author.is_valid_sender_account() {
                    Err(ChatItemError::GroupUpdateNotFromContact)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::ExpirationTimerChange { .. } => {
                if !author.is_valid_sender_account() {
                    Err(ChatItemError::ExpirationTimerChangeNotFromContact)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::ProfileChange { .. } => {
                // Another case where this *shouldn't* happen for Self, but could if the user takes
                // a phone number that formerly belonged to a contact.
                if !author.is_valid_sender_account() {
                    Err(ChatItemError::ProfileChangeNotFromContact)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::ThreadMerge { .. } => {
                if !author.is_contact_with_aci() {
                    Err(ChatItemError::ThreadMergeNotFromAci)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::SessionSwitchover { .. } => {
                if !author.is_contact_with_aci() {
                    Err(ChatItemError::SessionSwitchoverNotFromAci)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::IndividualCall(_) | UpdateMessage::GroupCall(_) => {
                if !author.is_valid_sender_account() {
                    Err(ChatItemError::CallNotFromContact)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::LearnedProfileUpdate(_) => {
                // Another case where this *shouldn't* happen for Self, but could if the user takes
                // a phone number that formerly belonged to a contact.
                if !author.is_valid_sender_account() {
                    Err(ChatItemError::LearnedProfileUpdateNotFromContact)
                } else {
                    Ok(())
                }
            }
        }
    }

    pub(super) fn validate_chat_recipient(
        &self,
        chat: &ChatRecipientKind,
    ) -> Result<(), ChatItemError> {
        match self {
            UpdateMessage::Simple(
                update @ (SimpleChatUpdate::JoinedSignal
                | SimpleChatUpdate::EndSession
                | SimpleChatUpdate::ChatSessionRefresh
                | SimpleChatUpdate::PaymentActivationRequest
                | SimpleChatUpdate::PaymentsActivated),
            ) => {
                // We allow Self for these, for a few reasons:
                // - "Note to Self" can have ChatSessionRefresh (and IdentityUpdate, if things go
                //   very wrong)
                // - An E164-based thread can get merged into Self if the user takes a phone number
                //   that formerly belonged to a contact.
                if !chat.is_individual() {
                    Err(ChatItemError::ChatUpdateNotInContactThread(*update))
                } else {
                    Ok(())
                }
            }
            UpdateMessage::Simple(
                SimpleChatUpdate::IdentityDefault
                | SimpleChatUpdate::IdentityVerified
                | SimpleChatUpdate::IdentityUpdate
                | SimpleChatUpdate::ChangeNumber
                | SimpleChatUpdate::BadDecrypt
                | SimpleChatUpdate::UnsupportedProtocolMessage
                | SimpleChatUpdate::ReportedSpam
                | SimpleChatUpdate::Blocked
                | SimpleChatUpdate::Unblocked
                | SimpleChatUpdate::MessageRequestAccepted,
            )
            | UpdateMessage::ProfileChange { .. }
            | UpdateMessage::LearnedProfileUpdate(_) => {
                match chat {
                    ChatRecipientKind::Contact { .. } | ChatRecipientKind::Group { .. } => Ok(()),
                    ChatRecipientKind::Self_ => {
                        // Again, Self is allowed because of possible past thread merging.
                        // See above.
                        Ok(())
                    }
                    ChatRecipientKind::ReleaseNotes => {
                        Err(ChatItemError::UnexpectedUpdateInReleaseNotes)
                    }
                }
            }
            UpdateMessage::Simple(SimpleChatUpdate::ReleaseChannelDonationRequest) => {
                if !matches!(chat, ChatRecipientKind::ReleaseNotes) {
                    Err(ChatItemError::DonationRequestNotInReleaseNotesChat)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::GroupChange { .. } => {
                if !matches!(chat, ChatRecipientKind::Group { .. }) {
                    Err(ChatItemError::GroupUpdateNotInGroupThread)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::ExpirationTimerChange { .. } => {
                if !chat.is_individual() {
                    Err(ChatItemError::ExpirationTimerChangeNotInContactThread)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::ThreadMerge { .. } => {
                if !chat.is_contact_with_aci() {
                    Err(ChatItemError::ThreadMergeNotInContactThread)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::SessionSwitchover { .. } => {
                if !chat.is_contact_with_aci() {
                    Err(ChatItemError::SessionSwitchoverNotInContactThread)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::IndividualCall(_) => {
                if !chat.is_individual() {
                    Err(ChatItemError::IndividualCallNotInContactThread)
                } else {
                    Ok(())
                }
            }
            UpdateMessage::GroupCall(_) => {
                if !matches!(chat, ChatRecipientKind::Group { .. }) {
                    Err(ChatItemError::GroupCallNotInGroupThread)
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::test_case;

    use super::*;
    use crate::backup::call::CallError;
    use crate::backup::testutil::TestContext;
    use crate::proto::backup::chat_update_message::Update as ChatUpdateProto;

    impl proto::SimpleChatUpdate {
        pub(crate) fn test_data() -> Self {
            Self {
                type_: proto::simple_chat_update::Type::IDENTITY_VERIFIED.into(),
                ..Default::default()
            }
        }
    }

    const BAD_RECIPIENT: RecipientId = RecipientId(u64::MAX);

    impl proto::GroupCall {
        fn no_started_call() -> Self {
            Self {
                startedCallRecipientId: None,
                ..Self::test_data()
            }
        }

        fn bad_started_call() -> Self {
            Self {
                startedCallRecipientId: Some(BAD_RECIPIENT.0),
                ..Self::test_data()
            }
        }
    }

    #[test_case(ChatUpdateProto::IndividualCall(proto::IndividualCall::test_data()), Ok(()))]
    #[test_case(ChatUpdateProto::GroupCall(proto::GroupCall::test_data()), Ok(()))]
    #[test_case(
        ChatUpdateProto::GroupCall(proto::GroupCall::no_started_call()),
        Ok(())
    )]
    #[test_case(
        ChatUpdateProto::GroupCall(proto::GroupCall::bad_started_call()),
        Err(CallError::UnknownCallStarter(BAD_RECIPIENT))
    )]
    fn call_chat_update(update: ChatUpdateProto, expected: Result<(), CallError>) {
        assert_eq!(
            proto::ChatUpdateMessage {
                update: Some(update),
                special_fields: Default::default()
            }
            .try_into_with(&TestContext::default())
            .map(|_: UpdateMessage<_>| ()),
            expected.map_err(ChatItemError::Call)
        );
    }

    #[test]
    fn chat_update_message_no_item() {
        assert_matches!(
            UpdateMessage::try_from_with(
                proto::ChatUpdateMessage::default(),
                &TestContext::default()
            ),
            Err(ChatItemError::UpdateIsEmpty)
        );
    }

    #[test_case(proto::SimpleChatUpdate::test_data(), Ok(()))]
    #[test_case(proto::ExpirationTimerChatUpdate::default(), Ok(()))]
    #[test_case(
        proto::ProfileChangeChatUpdate::default(),
        Err(ChatItemError::ProfileChangeMissingNames)
    )]
    #[test_case(
        proto::ProfileChangeChatUpdate {
            previousName: "Kon".into(),
            ..Default::default()
        },
        Err(ChatItemError::ProfileChangeMissingNames)
    )]
    #[test_case(
        proto::ProfileChangeChatUpdate {
            newName: "Bak".into(),
            ..Default::default()
        },
        Err(ChatItemError::ProfileChangeMissingNames)
    )]
    #[test_case(
        proto::ProfileChangeChatUpdate {
            previousName: "Kon".into(),
            newName: "Bak".into(),
            ..Default::default()
        },
        Ok(())
    )]
    #[test_case(
        proto::ThreadMergeChatUpdate::default(),
        Err(ChatItemError::InvalidE164)
    )]
    #[test_case(
        proto::SessionSwitchoverChatUpdate::default(),
        Err(ChatItemError::InvalidE164)
    )]
    #[test_case(
        proto::LearnedProfileChatUpdate::default(),
        Err(ChatItemError::LearnedProfileIsEmpty)
    )]
    fn chat_update_message_item(
        update: impl Into<proto::chat_update_message::Update>,
        expected: Result<(), ChatItemError>,
    ) {
        let result = proto::ChatUpdateMessage {
            update: Some(update.into()),
            ..Default::default()
        }
        .try_into_with(&TestContext::default())
        .map(|_: UpdateMessage<_>| ());

        assert_eq!(result, expected)
    }
}
