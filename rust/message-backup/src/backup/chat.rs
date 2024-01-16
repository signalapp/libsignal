//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complains about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use derive_where::derive_where;
use libsignal_protocol::Aci;

use crate::backup::frame::{CallId, RecipientId};
use crate::backup::method::{Contains, Method, Store};
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum ChatError {
    /// multiple records with the same ID
    DuplicateId,
    /// no record for {0:?}
    NoRecipient(RecipientId),
    /// {0}
    ChatItem(#[from] ChatItemError),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ChatItemError {
    /// no record for chat
    NoChatForItem,
    /// no record for chat item author {0:?}
    AuthorNotFound(RecipientId),
    /// no value for item
    MissingItem,
    /// quote has unknown author {0:?}
    QuoteAuthorNotFound(RecipientId),
    /// reaction: {0}
    Reaction(#[from] ReactionError),
    /// ChatUpdateMessage has no update value
    UpdateIsEmpty,
    /// CallChatUpdate has no call value
    CallIsEmpty,
    /// unknown call ID {0:?}
    NoCallForId(CallId),
    /// invalid ACI uuid
    InvalidAci,
}

/// Validated version of [`proto::Chat`].
#[derive_where(Debug)]
pub struct ChatData<M: Method = Store> {
    pub(super) items: M::List<ChatItemData>,
}

/// Validated version of [`proto::ChatItem`].
#[derive(Debug)]
pub struct ChatItemData {
    pub message: ChatItemMessage,
    pub revisions: Vec<ChatItemData>,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::chat_item::Item`].
#[derive(Debug)]
pub enum ChatItemMessage {
    Standard(StandardMessage),
    Contact(ContactMessage),
    Voice(VoiceMessage),
    Sticker(StickerMessage),
    RemoteDeleted,
    Update(UpdateMessage),
}

/// Validated version of [`proto::StandardMessage`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct StandardMessage {
    pub quote: Option<Quote>,
    pub reactions: Vec<Reaction>,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::ContactMessage`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ContactMessage {
    pub reactions: Vec<Reaction>,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::VoiceMessage`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct VoiceMessage {
    pub quote: Option<Quote>,
    pub reactions: Vec<Reaction>,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::StickerMessage`].
#[derive(Debug)]
pub struct StickerMessage {
    pub reactions: Vec<Reaction>,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::chat_update_message::Update`].
#[derive(Debug)]
pub enum UpdateMessage {
    Simple {
        type_: proto::simple_chat_update::Type,
    },
    GroupDescription {
        new_description: String,
    },
    ExpirationTimerChange,
    ProfileChange {
        previous: String,
        new: String,
    },
    ThreadMerge,
    SessionSwitchover,
    Call(CallChatUpdate),
}

/// Validated version of [`proto::ContactAttachment`].
#[derive(Debug)]
pub struct ContactAttachment {
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::call_chat_update::Call`].
#[derive(Debug)]
pub enum CallChatUpdate {
    Call(CallId),
    CallMessage,
    GroupCall {
        started_call_aci: Option<Aci>,
        in_call_acis: Vec<Aci>,
    },
}

/// Validated version of [`proto::Reaction`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Reaction {
    pub author: RecipientId,
    _limit_construction_to_module: (),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ReactionError {
    /// unknown author {0:?}
    AuthorNotFound(RecipientId),
}

/// Validated version of [`proto::Quote`]
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Quote {
    pub author: RecipientId,
    _limit_construction_to_module: (),
}

impl<M: Method> TryFrom<proto::Chat> for ChatData<M> {
    type Error = ChatError;

    fn try_from(value: proto::Chat) -> Result<Self, Self::Error> {
        let proto::Chat {
            id: _,
            recipientId: _,
            // TODO validate these fields
            archived: _,
            pinnedOrder: _,
            expirationTimerMs: _,
            muteUntilMs: _,
            markedUnread: _,
            dontNotifyForMentionsIfMuted: _,
            wallpaper: _,
            special_fields: _,
        } = value;

        Ok(Self {
            items: Default::default(),
        })
    }
}

impl<R: Contains<RecipientId> + Contains<CallId>> TryFromWith<proto::ChatItem, R> for ChatItemData {
    type Error = ChatItemError;

    fn try_from_with(value: proto::ChatItem, recipients: &R) -> Result<Self, ChatItemError> {
        let proto::ChatItem {
            chatId: _,
            authorId: _,
            item,
            revisions,

            // TODO validate these fields
            dateSent: _,
            sealedSender: _,
            expireStartDate: _,
            expiresInMs: _,
            sms: _,
            directionalDetails: _,
            special_fields: _,
        } = value;

        let message =
            ChatItemMessage::try_from_with(item.ok_or(ChatItemError::MissingItem)?, recipients)?;

        let revisions = revisions
            .into_iter()
            .map(|rev| rev.try_into_with(recipients))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            message,
            revisions,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId> + Contains<CallId>> TryFromWith<proto::chat_item::Item, R>
    for ChatItemMessage
{
    type Error = ChatItemError;

    fn try_from_with(value: proto::chat_item::Item, recipients: &R) -> Result<Self, Self::Error> {
        use proto::chat_item::Item;

        Ok(match value {
            Item::StandardMessage(message) => Self::Standard(message.try_into_with(recipients)?),
            Item::ContactMessage(message) => Self::Contact(message.try_into_with(recipients)?),

            Item::VoiceMessage(message) => Self::Voice(message.try_into_with(recipients)?),
            Item::StickerMessage(message) => Self::Sticker(message.try_into_with(recipients)?),
            Item::RemoteDeletedMessage(proto::RemoteDeletedMessage { special_fields: _ }) => {
                Self::RemoteDeleted
            }
            Item::UpdateMessage(message) => Self::Update(message.try_into_with(recipients)?),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::StandardMessage, R> for StandardMessage {
    type Error = ChatItemError;

    fn try_from_with(item: proto::StandardMessage, context: &R) -> Result<Self, Self::Error> {
        let proto::StandardMessage {
            quote,
            reactions,
            // TODO validate these fields
            text: _,
            attachments: _,
            linkPreview: _,
            longText: _,
            special_fields: _,
        } = item;

        let reactions = reactions
            .into_iter()
            .map(|r| r.try_into_with(context))
            .collect::<Result<_, _>>()?;

        let quote = quote
            .into_option()
            .map(|q| q.try_into_with(context))
            .transpose()?;

        Ok(Self {
            quote,
            reactions,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::ContactMessage, R> for ContactMessage {
    type Error = ChatItemError;

    fn try_from_with(item: proto::ContactMessage, context: &R) -> Result<Self, Self::Error> {
        let proto::ContactMessage {
            reactions,
            // TODO validate these fields
            contact: _,
            special_fields: _,
        } = item;

        let reactions = reactions
            .into_iter()
            .map(|r| r.try_into_with(context))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            reactions,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::VoiceMessage, R> for VoiceMessage {
    type Error = ChatItemError;

    fn try_from_with(item: proto::VoiceMessage, context: &R) -> Result<Self, Self::Error> {
        let proto::VoiceMessage {
            quote,
            reactions,
            // TODO validate these fields
            audio: _,
            special_fields: _,
        } = item;

        let quote = quote
            .into_option()
            .map(|q| q.try_into_with(context))
            .transpose()?;
        let reactions = reactions
            .into_iter()
            .map(|r| r.try_into_with(context))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            reactions,
            quote,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::StickerMessage, R> for StickerMessage {
    type Error = ChatItemError;

    fn try_from_with(item: proto::StickerMessage, context: &R) -> Result<Self, Self::Error> {
        let proto::StickerMessage {
            reactions,
            // TODO validate these fields
            sticker: _,
            special_fields: _,
        } = item;

        let reactions = reactions
            .into_iter()
            .map(|r| r.try_into_with(context))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            reactions,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId> + Contains<CallId>> TryFromWith<proto::ChatUpdateMessage, R>
    for UpdateMessage
{
    type Error = ChatItemError;

    fn try_from_with(item: proto::ChatUpdateMessage, context: &R) -> Result<Self, Self::Error> {
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
            }) => Self::Simple {
                type_: type_.enum_value_or_default(),
            },
            Update::GroupDescription(proto::GroupDescriptionChatUpdate {
                newDescription,
                special_fields: _,
            }) => Self::GroupDescription {
                new_description: newDescription,
            },
            Update::ExpirationTimerChange(proto::ExpirationTimerChatUpdate {
                // TODO validate this field
                expiresInMs: _,
                special_fields: _,
            }) => Self::ExpirationTimerChange,
            Update::ProfileChange(proto::ProfileChangeChatUpdate {
                previousName,
                newName,
                special_fields: _,
            }) => Self::ProfileChange {
                previous: previousName,
                new: newName,
            },
            Update::ThreadMerge(proto::ThreadMergeChatUpdate {
                // TODO validate this field
                previousE164: _,
                special_fields: _,
            }) => Self::ThreadMerge,
            Update::SessionSwitchover(proto::SessionSwitchoverChatUpdate {
                // TODO validate this field
                e164: _,
                special_fields: _,
            }) => Self::SessionSwitchover,
            Update::CallingMessage(proto::CallChatUpdate {
                call,
                special_fields: _,
            }) => {
                let call = call.ok_or(ChatItemError::CallIsEmpty)?;

                Self::Call(call.try_into_with(context)?)
            }
        })
    }
}

impl<R: Contains<CallId>> TryFromWith<proto::call_chat_update::Call, R> for CallChatUpdate {
    type Error = ChatItemError;
    fn try_from_with(
        item: proto::call_chat_update::Call,
        context: &R,
    ) -> Result<Self, Self::Error> {
        use proto::call_chat_update::Call;
        match item {
            Call::CallId(id) => {
                let id = CallId(id);
                context
                    .contains(&id)
                    .then_some(Self::Call(id))
                    .ok_or(ChatItemError::NoCallForId(id))
            }
            Call::CallMessage(proto::IndividualCallChatUpdate { special_fields: _ }) => {
                Ok(Self::CallMessage)
            }
            Call::GroupCall(group) => {
                let proto::GroupCallChatUpdate {
                    startedCallAci,
                    inCallAcis,
                    // TODO validate these fields
                    startedCallTimestamp: _,
                    special_fields: _,
                } = group;

                let uuid_bytes_to_aci = |bytes: Vec<u8>| {
                    bytes
                        .try_into()
                        .map(Aci::from_uuid_bytes)
                        .map_err(|_| ChatItemError::InvalidAci)
                };
                let started_call_aci = startedCallAci.map(uuid_bytes_to_aci).transpose()?;

                let in_call_acis = inCallAcis
                    .into_iter()
                    .map(uuid_bytes_to_aci)
                    .collect::<Result<_, _>>()?;

                Ok(Self::GroupCall {
                    started_call_aci,
                    in_call_acis,
                })
            }
        }
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::Quote, R> for Quote {
    type Error = ChatItemError;

    fn try_from_with(item: proto::Quote, context: &R) -> Result<Self, Self::Error> {
        let proto::Quote {
            authorId,
            // TODO validate these fields
            targetSentTimestamp: _,
            text: _,
            attachments: _,
            bodyRanges: _,
            type_: _,
            special_fields: _,
        } = item;

        let author = RecipientId(authorId);
        if !context.contains(&author) {
            return Err(ChatItemError::QuoteAuthorNotFound(author));
        }
        Ok(Self {
            author,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::Reaction, R> for Reaction {
    type Error = ReactionError;

    fn try_from_with(item: proto::Reaction, context: &R) -> Result<Self, Self::Error> {
        let proto::Reaction {
            authorId,
            // TODO validate these fields
            emoji: _,
            sentTimestamp: _,
            receivedTimestamp: _,
            sortOrder: _,
            special_fields: _,
        } = item;

        let author = RecipientId(authorId);
        if !context.contains(&author) {
            return Err(ReactionError::AuthorNotFound(author));
        }
        Ok(Self {
            author,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use protobuf::{MessageField, SpecialFields};
    use test_case::test_case;

    use super::*;

    impl proto::StandardMessage {
        pub(crate) fn test_data() -> Self {
            Self {
                reactions: vec![proto::Reaction::test_data()],
                quote: Some(proto::Quote::test_data()).into(),
                ..Default::default()
            }
        }
    }

    impl proto::ContactMessage {
        fn test_data() -> Self {
            Self {
                reactions: vec![proto::Reaction::test_data()],
                ..Default::default()
            }
        }
    }

    impl proto::Reaction {
        fn test_data() -> Self {
            Self {
                authorId: proto::Recipient::TEST_ID,
                ..Default::default()
            }
        }
    }

    impl proto::VoiceMessage {
        fn test_data() -> Self {
            Self {
                quote: Some(proto::Quote::test_data()).into(),
                reactions: vec![proto::Reaction::test_data()],
                ..Default::default()
            }
        }
    }

    impl proto::Quote {
        fn test_data() -> Self {
            Self {
                authorId: proto::Recipient::TEST_ID,
                ..Default::default()
            }
        }
    }

    impl proto::StickerMessage {
        fn test_data() -> Self {
            Self {
                reactions: vec![proto::Reaction::test_data()],
                ..Default::default()
            }
        }
    }

    trait ProtoHasField<T> {
        fn get_field_mut(&mut self) -> &mut T;
    }
    impl ProtoHasField<Vec<proto::Reaction>> for proto::VoiceMessage {
        fn get_field_mut(&mut self) -> &mut Vec<proto::Reaction> {
            &mut self.reactions
        }
    }

    impl ProtoHasField<Vec<proto::Reaction>> for proto::ContactMessage {
        fn get_field_mut(&mut self) -> &mut Vec<proto::Reaction> {
            &mut self.reactions
        }
    }

    impl ProtoHasField<Vec<proto::Reaction>> for proto::StickerMessage {
        fn get_field_mut(&mut self) -> &mut Vec<proto::Reaction> {
            &mut self.reactions
        }
    }

    impl ProtoHasField<MessageField<proto::Quote>> for proto::StandardMessage {
        fn get_field_mut(&mut self) -> &mut MessageField<proto::Quote> {
            &mut self.quote
        }
    }
    impl ProtoHasField<MessageField<proto::Quote>> for proto::VoiceMessage {
        fn get_field_mut(&mut self) -> &mut MessageField<proto::Quote> {
            &mut self.quote
        }
    }

    impl Reaction {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                author: RecipientId(proto::Recipient::TEST_ID),
                _limit_construction_to_module: (),
            }
        }
    }

    struct TestContext;

    impl Contains<RecipientId> for TestContext {
        fn contains(&self, key: &RecipientId) -> bool {
            key == &RecipientId(proto::Recipient::TEST_ID)
        }
    }

    impl Contains<CallId> for TestContext {
        fn contains(&self, key: &CallId) -> bool {
            key == &CallId(proto::Call::TEST_ID)
        }
    }

    #[test]
    fn valid_standard_message() {
        assert_eq!(
            proto::StandardMessage::test_data().try_into_with(&TestContext),
            Ok(StandardMessage {
                reactions: vec![Reaction::from_proto_test_data(),],
                quote: Some(Quote {
                    author: RecipientId(proto::Recipient::TEST_ID),
                    _limit_construction_to_module: ()
                }),
                _limit_construction_to_module: ()
            })
        );
    }

    #[test]
    fn valid_contact_message() {
        assert_eq!(
            proto::ContactMessage::test_data().try_into_with(&TestContext),
            Ok(ContactMessage {
                reactions: vec![Reaction::from_proto_test_data()],
                _limit_construction_to_module: ()
            })
        )
    }

    fn no_reactions(message: &mut impl ProtoHasField<Vec<proto::Reaction>>) {
        message.get_field_mut().clear()
    }

    fn invalid_reaction(message: &mut impl ProtoHasField<Vec<proto::Reaction>>) {
        message.get_field_mut().push(proto::Reaction::default());
    }

    fn no_quote(input: &mut impl ProtoHasField<MessageField<proto::Quote>>) {
        *input.get_field_mut() = None.into();
    }

    #[test_case(no_reactions, Ok(()))]
    #[test_case(
        invalid_reaction,
        Err(ChatItemError::Reaction(ReactionError::AuthorNotFound(RecipientId(0))))
    )]
    fn contact_message(
        modifier: fn(&mut proto::ContactMessage),
        expected: Result<(), ChatItemError>,
    ) {
        let mut message = proto::ContactMessage::test_data();
        modifier(&mut message);

        let result = message
            .try_into_with(&TestContext)
            .map(|_: ContactMessage| ());
        assert_eq!(result, expected);
    }

    #[test]
    fn valid_voice_message() {
        assert_eq!(
            proto::VoiceMessage::test_data().try_into_with(&TestContext),
            Ok(VoiceMessage {
                quote: Some(Quote {
                    author: RecipientId(proto::Recipient::TEST_ID),
                    _limit_construction_to_module: ()
                }),
                reactions: vec![Reaction::from_proto_test_data()],
                _limit_construction_to_module: ()
            })
        )
    }

    #[test_case(no_reactions, Ok(()))]
    #[test_case(
        invalid_reaction,
        Err(ChatItemError::Reaction(ReactionError::AuthorNotFound(RecipientId(0))))
    )]
    #[test_case(no_quote, Ok(()))]
    fn voice_message(modifier: fn(&mut proto::VoiceMessage), expected: Result<(), ChatItemError>) {
        let mut message = proto::VoiceMessage::test_data();
        modifier(&mut message);

        let result = message
            .try_into_with(&TestContext)
            .map(|_: VoiceMessage| ());
        assert_eq!(result, expected);
    }

    #[test_case(no_reactions, Ok(()))]
    #[test_case(
        invalid_reaction,
        Err(ChatItemError::Reaction(ReactionError::AuthorNotFound(RecipientId(0))))
    )]
    fn sticker_message(
        modifier: fn(&mut proto::StickerMessage),
        expected: Result<(), ChatItemError>,
    ) {
        let mut message = proto::StickerMessage::test_data();
        modifier(&mut message);

        let result = message
            .try_into_with(&TestContext)
            .map(|_: StickerMessage| ());
        assert_eq!(result, expected);
    }

    #[test]
    fn chat_update_message_no_item() {
        assert_matches!(
            UpdateMessage::try_from_with(proto::ChatUpdateMessage::default(), &TestContext),
            Err(ChatItemError::UpdateIsEmpty)
        );
    }

    #[test_case(proto::SimpleChatUpdate::default(), Ok(()))]
    #[test_case(proto::GroupDescriptionChatUpdate::default(), Ok(()))]
    #[test_case(proto::ExpirationTimerChatUpdate::default(), Ok(()))]
    #[test_case(proto::ProfileChangeChatUpdate::default(), Ok(()))]
    #[test_case(proto::ThreadMergeChatUpdate::default(), Ok(()))]
    #[test_case(proto::SessionSwitchoverChatUpdate::default(), Ok(()))]
    #[test_case(proto::CallChatUpdate::default(), Err(ChatItemError::CallIsEmpty))]
    fn chat_update_message_item(
        update: impl Into<proto::chat_update_message::Update>,
        expected: Result<(), ChatItemError>,
    ) {
        let result = proto::ChatUpdateMessage {
            update: Some(update.into()),
            ..Default::default()
        }
        .try_into_with(&TestContext)
        .map(|_: UpdateMessage| ());

        assert_eq!(result, expected)
    }

    use proto::call_chat_update::Call as CallChatUpdateProto;
    impl CallChatUpdateProto {
        const TEST_CALL_ID: Self = Self::CallId(proto::Call::TEST_ID);
        const TEST_WRONG_CALL_ID: Self = Self::CallId(proto::Call::TEST_ID + 1);
        fn test_call_message() -> Self {
            Self::CallMessage(proto::IndividualCallChatUpdate {
                special_fields: SpecialFields::new(),
            })
        }
    }

    impl proto::GroupCallChatUpdate {
        const TEST_ACI: [u8; 16] = [0x12; 16];

        fn test_data() -> Self {
            Self {
                startedCallAci: Some(Self::TEST_ACI.into()),
                inCallAcis: vec![Self::TEST_ACI.into()],
                ..Default::default()
            }
        }
        fn no_started_call_aci() -> Self {
            Self {
                startedCallAci: None,
                ..Self::test_data()
            }
        }

        fn bad_started_call_aci() -> Self {
            Self {
                startedCallAci: Some(vec![0x01; 2]),
                ..Self::test_data()
            }
        }

        fn bad_in_call_aci() -> Self {
            Self {
                inCallAcis: vec![Self::TEST_ACI.into(), vec![0x01; 3]],
                ..Self::test_data()
            }
        }
    }

    #[test_case(CallChatUpdateProto::TEST_CALL_ID, Ok(()))]
    #[test_case(CallChatUpdateProto::TEST_WRONG_CALL_ID, Err(ChatItemError::NoCallForId(CallId(proto::Call::TEST_ID + 1))))]
    #[test_case(CallChatUpdateProto::test_call_message(), Ok(()))]
    #[test_case(CallChatUpdateProto::GroupCall(proto::GroupCallChatUpdate::test_data()), Ok(()))]
    #[test_case(
        CallChatUpdateProto::GroupCall(proto::GroupCallChatUpdate::no_started_call_aci()),
        Ok(())
    )]
    #[test_case(
        CallChatUpdateProto::GroupCall(proto::GroupCallChatUpdate::bad_started_call_aci()),
        Err(ChatItemError::InvalidAci)
    )]
    #[test_case(
        CallChatUpdateProto::GroupCall(proto::GroupCallChatUpdate::bad_in_call_aci()),
        Err(ChatItemError::InvalidAci)
    )]
    fn call_chat_update(update: CallChatUpdateProto, expected: Result<(), ChatItemError>) {
        assert_eq!(
            update
                .try_into_with(&TestContext)
                .map(|_: CallChatUpdate| ()),
            expected
        );
    }

    #[test]
    fn valid_reaction() {
        assert_eq!(
            proto::Reaction::test_data().try_into_with(&TestContext),
            Ok(Reaction::from_proto_test_data())
        )
    }

    fn invalid_author_id(input: &mut proto::Reaction) {
        input.authorId = proto::Recipient::TEST_ID + 2;
    }

    fn no_received_timestamp(input: &mut proto::Reaction) {
        input.receivedTimestamp = None;
    }

    #[test_case(invalid_author_id, Err(ReactionError::AuthorNotFound(RecipientId(proto::Recipient::TEST_ID + 2))))]
    #[test_case(no_received_timestamp, Ok(()))]
    fn reaction(modifier: fn(&mut proto::Reaction), expected: Result<(), ReactionError>) {
        let mut reaction = proto::Reaction::test_data();
        modifier(&mut reaction);

        let result = reaction.try_into_with(&TestContext).map(|_: Reaction| ());
        assert_eq!(result, expected);
    }
}
