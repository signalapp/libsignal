//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complains about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use std::fmt::Debug;
use std::hash::Hash;
use std::num::{NonZeroU32, NonZeroU64};

use derive_where::derive_where;

use crate::backup::chat::chat_style::{ChatStyle, ChatStyleError, CustomColorId};
use crate::backup::file::{FilePointerError, MessageAttachmentError};
use crate::backup::frame::RecipientId;
use crate::backup::method::{Contains, Lookup, Method};
use crate::backup::serialize::SerializeOrder;
use crate::backup::sticker::MessageStickerError;
use crate::backup::time::{Duration, Timestamp};
use crate::backup::{BackupMeta, CallError, ReferencedTypes, TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

mod contact_message;
use contact_message::*;

pub(crate) mod chat_style;

mod gift_badge;
use gift_badge::*;

mod group;
use group::*;

mod link;
use link::*;

mod payment;
use payment::*;

mod quote;
use quote::*;

mod standard_message;
use standard_message::*;

mod sticker_message;
use sticker_message::*;

#[cfg(test)]
mod testutil;

mod text;
use text::*;

mod update_message;
use update_message::*;

mod voice_message;
use voice_message::*;

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ChatError {
    /// multiple records with the same ID
    DuplicateId,
    /// no record for {0:?}
    NoRecipient(RecipientId),
    /// chat item: {0}
    ChatItem(#[from] ChatItemError),
    /// {0:?} already appeared
    DuplicatePinnedOrder(PinOrder),
    /// style error: {0}
    Style(#[from] ChatStyleError),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ChatItemError {
    /// no record for chat
    NoChatForItem,
    /// no record for chat item author {0:?}
    AuthorNotFound(RecipientId),
    /// ChatItem.item is a oneof but is empty
    MissingItem,
    /// text: {0}
    Text(#[from] TextError),
    /// long text: {0}
    LongText(FilePointerError),
    /// quote: {0}
    Quote(#[from] QuoteError),
    /// link preview: {0}
    Link(#[from] LinkPreviewError),
    /// reaction: {0}
    Reaction(#[from] ReactionError),
    /// payment: {0}
    Payment(#[from] PaymentError),
    /// ChatUpdateMessage.update is a oneof but is empty
    UpdateIsEmpty,
    /// call error: {0}
    Call(#[from] CallError),
    /// GroupChange has no changes.
    GroupChangeIsEmpty,
    /// for GroupUpdate change {0}, Update.update is a oneof but is empty
    GroupChangeUpdateIsEmpty(usize),
    /// group update: {0}
    GroupUpdate(#[from] GroupUpdateError),
    /// StickerMessage has no sticker
    StickerMessageMissingSticker,
    /// sticker message: {0}
    StickerMessage(#[from] MessageStickerError),
    /// gift badge: {0}
    GiftBadge(#[from] GiftBadgeError),
    /// ChatItem.directionalDetails is a oneof but is empty
    NoDirection,
    /// outgoing message {0}
    Outgoing(#[from] OutgoingSendError),
    /// attachment: {0}
    Attachment(#[from] MessageAttachmentError),
    /// contact message: {0}
    ContactAttachment(#[from] ContactAttachmentError),
    /// chat update type is UNKNOWN
    ChatUpdateUnknown,
    /// voice message: {0}
    VoiceMessage(#[from] VoiceMessageError),
    /// found exactly one of expiration start date and duration
    ExpirationMismatch,
    /// expiration too soon: {0}
    InvalidExpiration(#[from] InvalidExpiration),
    /// revisions contains a ChatItem with a call message
    RevisionContainsCall,
    /// learned profile chat update has no e164 or name
    LearnedProfileIsEmpty,
    /// invalid e164
    InvalidE164,
}

#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub struct InvalidExpiration {
    backup_time: Timestamp,
    expires_at: Timestamp,
}

/// Validated version of [`proto::Chat`].
#[derive_where(Debug)]
#[derive(serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq;
    M::List<ChatItemData<M>>: PartialEq,
    M::RecipientReference: PartialEq,
    ChatStyle<M>: PartialEq,
))]
pub struct ChatData<M: Method + ReferencedTypes> {
    pub recipient: M::RecipientReference,
    #[serde(bound(serialize = "M::List<ChatItemData<M>>: serde::Serialize"))]
    pub items: M::List<ChatItemData<M>>,
    pub expiration_timer: Option<Duration>,
    pub mute_until: Option<Timestamp>,
    pub style: Option<ChatStyle<M>>,
    pub pinned_order: Option<PinOrder>,
    pub dont_notify_for_mentions_if_muted: bool,
    pub marked_unread: bool,
    pub archived: bool,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, serde::Serialize)]
pub struct PinOrder(NonZeroU32);

/// Validated version of [`proto::ChatItem`].
#[derive_where(Debug)]
#[derive(serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq;
    ChatItemMessage<M>: PartialEq,
    M::RecipientReference: PartialEq
))]
pub struct ChatItemData<M: Method + ReferencedTypes> {
    pub author: M::RecipientReference,
    #[serde(bound(serialize = "ChatItemMessage<M>: serde::Serialize"))]
    pub message: ChatItemMessage<M>,
    // This could be Self: Serialize but that just confuses the compiler.
    pub revisions: Vec<ChatItemData<M>>,
    pub direction: Direction,
    pub expire_start: Option<Timestamp>,
    pub expires_in: Option<Duration>,
    pub sent_at: Timestamp,
    pub sms: bool,
    /// The position of this chat item among all chat items (across chats) in
    /// the source stream.
    pub total_chat_item_order_index: usize,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::chat_item::Item`].
#[derive_where(Debug)]
#[derive(serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq;
    M::BoxedValue<GiftBadge>: PartialEq,
    M::RecipientReference: PartialEq
))]
pub enum ChatItemMessage<M: Method + ReferencedTypes> {
    Standard(StandardMessage),
    Contact(ContactMessage),
    Voice(VoiceMessage),
    Sticker(StickerMessage),
    RemoteDeleted,
    Update(UpdateMessage<M::RecipientReference>),
    PaymentNotification(PaymentNotification),
    GiftBadge(M::BoxedValue<GiftBadge>),
}

/// Validated version of [`proto::Reaction`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub struct Reaction {
    pub emoji: String,
    // This field is not generated consistently on all platforms, so we only use it to sort
    // containers of Reactions.
    #[serde(skip)]
    pub sort_order: u64,
    pub author: RecipientId,
    pub sent_timestamp: Timestamp,
    pub received_timestamp: Option<Timestamp>,
    _limit_construction_to_module: (),
}

impl SerializeOrder for Reaction {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_order.cmp(&other.sort_order)
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ReactionError {
    /// unknown author {0:?}
    AuthorNotFound(RecipientId),
    /// "emoji" is an empty string
    EmptyEmoji,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Direction {
    Incoming {
        sent: Timestamp,
        received: Timestamp,
        read: bool,
        sealed_sender: bool,
    },
    Outgoing(Vec<OutgoingSend>),
    Directionless,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct OutgoingSend {
    pub recipient: RecipientId,
    pub status: DeliveryStatus,
    pub last_status_update: Timestamp,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum DeliveryFailureReason {
    Unknown,
    Network,
    IdentityKeyMismatch,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum DeliveryStatus {
    Failed(DeliveryFailureReason),
    Pending,
    Sent { sealed_sender: bool },
    Delivered { sealed_sender: bool },
    Read { sealed_sender: bool },
    Viewed { sealed_sender: bool },
    Skipped,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum OutgoingSendError {
    /// send status has unknown recipient {0:?}
    UnknownRecipient(RecipientId),
    /// send status is missing
    SendStatusMissing,
}

impl std::fmt::Display for InvalidExpiration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            backup_time,
            expires_at,
        } = self;
        match expires_at
            .into_inner()
            .duration_since(backup_time.into_inner())
        {
            Ok(until) => write!(f, "expires {}s after backup creation", until.as_secs()),
            Err(e) => write!(
                f,
                "expired {}s before backup creation",
                e.duration().as_secs()
            ),
        }
    }
}

impl<
        M: Method + ReferencedTypes,
        C: Lookup<RecipientId, M::RecipientReference>
            + Lookup<PinOrder, M::RecipientReference>
            + Lookup<CustomColorId, M::CustomColorReference>,
    > TryFromWith<proto::Chat, C> for ChatData<M>
{
    type Error = ChatError;

    fn try_from_with(value: proto::Chat, context: &C) -> Result<Self, Self::Error> {
        let proto::Chat {
            id: _,
            recipientId,
            expirationTimerMs,
            muteUntilMs,
            pinnedOrder,
            archived,
            markedUnread,
            dontNotifyForMentionsIfMuted,
            style,
            special_fields: _,
        } = value;

        let recipient = RecipientId(recipientId);
        let Some(recipient) = context.lookup(&recipient).cloned() else {
            return Err(ChatError::NoRecipient(recipient));
        };

        let pinned_order = NonZeroU32::new(pinnedOrder).map(PinOrder);
        if let Some(pinned_order) = pinned_order {
            if let Some(_recipient) = context.lookup(&pinned_order) {
                return Err(ChatError::DuplicatePinnedOrder(pinned_order));
            }
        };

        let style = style
            .into_option()
            .map(|chat_style| chat_style.try_into_with(context))
            .transpose()?;

        let expiration_timer =
            NonZeroU64::new(expirationTimerMs).map(|t| Duration::from_millis(t.get()));
        let mute_until = NonZeroU64::new(muteUntilMs)
            .map(|t| Timestamp::from_millis(t.get(), "Chat.muteUntilMs"));

        Ok(Self {
            recipient,
            expiration_timer,
            mute_until,
            items: Default::default(),
            style,
            pinned_order,
            archived,
            marked_unread: markedUnread,
            dont_notify_for_mentions_if_muted: dontNotifyForMentionsIfMuted,
        })
    }
}

impl<
        C: Lookup<RecipientId, M::RecipientReference> + AsRef<BackupMeta>,
        M: Method + ReferencedTypes,
    > TryFromWith<proto::ChatItem, C> for ChatItemData<M>
{
    type Error = ChatItemError;

    fn try_from_with(value: proto::ChatItem, context: &C) -> Result<Self, ChatItemError> {
        let proto::ChatItem {
            chatId: _,
            authorId,
            item,
            directionalDetails,
            revisions,
            expireStartDate,
            expiresInMs,
            dateSent,
            sms,
            special_fields: _,
        } = value;

        let author = RecipientId(authorId);

        let Some(author) = context.lookup(&author).cloned() else {
            return Err(ChatItemError::AuthorNotFound(author));
        };

        let message = item
            .ok_or(ChatItemError::MissingItem)?
            .try_into_with(context)?;

        let direction = directionalDetails
            .ok_or(ChatItemError::NoDirection)?
            .try_into_with(context)?;

        let revisions: Vec<_> = revisions
            .into_iter()
            .map(|rev| {
                let item: ChatItemData<M> = rev.try_into_with(context)?;
                match &item.message {
                    ChatItemMessage::Update(update) => match update {
                        UpdateMessage::GroupCall(_) | UpdateMessage::IndividualCall(_) => {
                            return Err(ChatItemError::RevisionContainsCall)
                        }
                        UpdateMessage::Simple(_)
                        | UpdateMessage::GroupChange { updates: _ }
                        | UpdateMessage::ExpirationTimerChange { expires_in: _ }
                        | UpdateMessage::ProfileChange {
                            previous: _,
                            new: _,
                        }
                        | UpdateMessage::ThreadMerge { previous_e164: _ }
                        | UpdateMessage::SessionSwitchover { e164: _ }
                        | UpdateMessage::LearnedProfileUpdate(_) => (),
                    },
                    ChatItemMessage::Standard(_)
                    | ChatItemMessage::Contact(_)
                    | ChatItemMessage::Voice(_)
                    | ChatItemMessage::PaymentNotification(_)
                    | ChatItemMessage::Sticker(_)
                    | ChatItemMessage::GiftBadge(_)
                    | ChatItemMessage::RemoteDeleted => (),
                };
                Ok(item)
            })
            .collect::<Result<_, _>>()?;

        let sent_at = Timestamp::from_millis(dateSent, "ChatItem.dateSent");
        let expire_start = NonZeroU64::new(expireStartDate)
            .map(|date| Timestamp::from_millis(date.into(), "ChatItem.expireStartDate"));
        let expires_in = NonZeroU64::new(expiresInMs)
            .map(Into::into)
            .map(Duration::from_millis);

        let expires_at = match (expire_start, expires_in) {
            (Some(expire_start), Some(expires_in)) => Some(expire_start + expires_in),
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => return Err(ChatItemError::ExpirationMismatch),
        };

        if let Some(expires_at) = expires_at {
            // Ensure that ephemeral content that's due to expire soon isn't backed up.
            let backup_time = context.as_ref().backup_time;
            let allowed_expire_at = backup_time
                + match context.as_ref().purpose {
                    crate::backup::Purpose::DeviceTransfer => Duration::ZERO,
                    crate::backup::Purpose::RemoteBackup => Duration::TWELVE_HOURS,
                };

            if expires_at < allowed_expire_at {
                return Err(InvalidExpiration {
                    expires_at,
                    backup_time,
                }
                .into());
            }
        }

        Ok(Self {
            author,
            message,
            revisions,
            direction,
            sent_at,
            expire_start,
            expires_in,
            sms,
            total_chat_item_order_index: Default::default(),
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::chat_item::DirectionalDetails, R> for Direction {
    type Error = ChatItemError;

    fn try_from_with(
        item: proto::chat_item::DirectionalDetails,
        context: &R,
    ) -> Result<Self, Self::Error> {
        use proto::chat_item::*;
        match item {
            DirectionalDetails::Incoming(IncomingMessageDetails {
                special_fields: _,
                dateReceived,
                dateServerSent,
                read,
                sealedSender,
            }) => {
                let sent =
                    Timestamp::from_millis(dateServerSent, "DirectionalDetails.dateServerSent");
                let received =
                    Timestamp::from_millis(dateReceived, "DirectionalDetails.dateReceived");
                Ok(Self::Incoming {
                    received,
                    sent,
                    read,
                    sealed_sender: sealedSender,
                })
            }
            DirectionalDetails::Outgoing(OutgoingMessageDetails {
                sendStatus,
                special_fields: _,
            }) => Ok(Self::Outgoing(
                sendStatus
                    .into_iter()
                    .map(|s| s.try_into_with(context))
                    .collect::<Result<_, _>>()?,
            )),
            DirectionalDetails::Directionless(DirectionlessMessageDetails {
                special_fields: _,
            }) => Ok(Self::Directionless),
        }
    }
}
impl<R: Contains<RecipientId>> TryFromWith<proto::SendStatus, R> for OutgoingSend {
    type Error = OutgoingSendError;

    fn try_from_with(item: proto::SendStatus, context: &R) -> Result<Self, Self::Error> {
        let proto::SendStatus {
            recipientId,
            timestamp,
            deliveryStatus,
            special_fields: _,
        } = item;

        let recipient = RecipientId(recipientId);

        if !context.contains(&recipient) {
            return Err(OutgoingSendError::UnknownRecipient(recipient));
        }

        let Some(status) = deliveryStatus else {
            return Err(OutgoingSendError::SendStatusMissing);
        };

        use proto::send_status;
        let status = match status {
            send_status::DeliveryStatus::Pending(send_status::Pending { special_fields: _ }) => {
                DeliveryStatus::Pending
            }
            send_status::DeliveryStatus::Sent(send_status::Sent {
                sealedSender,
                special_fields: _,
            }) => DeliveryStatus::Sent {
                sealed_sender: sealedSender,
            },
            send_status::DeliveryStatus::Delivered(send_status::Delivered {
                sealedSender,
                special_fields: _,
            }) => DeliveryStatus::Delivered {
                sealed_sender: sealedSender,
            },
            send_status::DeliveryStatus::Read(send_status::Read {
                sealedSender,
                special_fields: _,
            }) => DeliveryStatus::Read {
                sealed_sender: sealedSender,
            },
            send_status::DeliveryStatus::Viewed(send_status::Viewed {
                sealedSender,
                special_fields: _,
            }) => DeliveryStatus::Viewed {
                sealed_sender: sealedSender,
            },
            send_status::DeliveryStatus::Skipped(send_status::Skipped { special_fields: _ }) => {
                DeliveryStatus::Skipped
            }
            send_status::DeliveryStatus::Failed(send_status::Failed {
                reason,
                special_fields: _,
            }) => {
                // Note that we treat truly unknown enum values here as the default; that's already
                // checked separately.
                DeliveryStatus::Failed(match reason.enum_value_or_default() {
                    send_status::failed::FailureReason::UNKNOWN => DeliveryFailureReason::Unknown,
                    send_status::failed::FailureReason::NETWORK => DeliveryFailureReason::Network,
                    send_status::failed::FailureReason::IDENTITY_KEY_MISMATCH => {
                        DeliveryFailureReason::IdentityKeyMismatch
                    }
                })
            }
        };

        let last_status_update = Timestamp::from_millis(timestamp, "SendStatus.timestamp");

        Ok(Self {
            recipient,
            status,
            last_status_update,
        })
    }
}

impl<
        R: Lookup<RecipientId, M::RecipientReference> + AsRef<BackupMeta>,
        M: Method + ReferencedTypes,
    > TryFromWith<proto::chat_item::Item, R> for ChatItemMessage<M>
{
    type Error = ChatItemError;

    fn try_from_with(value: proto::chat_item::Item, recipients: &R) -> Result<Self, Self::Error> {
        use proto::chat_item::Item;

        Ok(match value {
            Item::StandardMessage(message) => {
                let is_voice_message = matches!(message.attachments.as_slice(),
                [single_attachment] if
                    single_attachment.flag.enum_value_or_default()
                        == proto::message_attachment::Flag::VOICE_MESSAGE
                );

                if is_voice_message {
                    ChatItemMessage::Voice(message.try_into_with(recipients)?)
                } else {
                    ChatItemMessage::Standard(message.try_into_with(recipients)?)
                }
            }
            Item::ContactMessage(message) => {
                ChatItemMessage::Contact(message.try_into_with(recipients)?)
            }
            Item::StickerMessage(message) => {
                ChatItemMessage::Sticker(message.try_into_with(recipients)?)
            }
            Item::RemoteDeletedMessage(proto::RemoteDeletedMessage { special_fields: _ }) => {
                ChatItemMessage::RemoteDeleted
            }
            Item::UpdateMessage(message) => {
                ChatItemMessage::Update(message.try_into_with(recipients)?)
            }
            Item::PaymentNotification(message) => {
                ChatItemMessage::PaymentNotification(message.try_into()?)
            }
            Item::GiftBadge(badge) => ChatItemMessage::GiftBadge(M::boxed_value(badge.try_into()?)),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::Reaction, R> for Reaction {
    type Error = ReactionError;

    fn try_from_with(item: proto::Reaction, context: &R) -> Result<Self, Self::Error> {
        let proto::Reaction {
            authorId,
            sentTimestamp,
            receivedTimestamp,
            emoji,
            sortOrder,
            special_fields: _,
        } = item;

        if emoji.is_empty() {
            return Err(ReactionError::EmptyEmoji);
        }

        let author = RecipientId(authorId);
        if !context.contains(&author) {
            return Err(ReactionError::AuthorNotFound(author));
        }

        let sent_timestamp = Timestamp::from_millis(sentTimestamp, "Reaction.sentTimestamp");
        let received_timestamp = receivedTimestamp
            .map(|timestamp| Timestamp::from_millis(timestamp, "Reaction.receivedTimestamp"));

        Ok(Self {
            emoji,
            sort_order: sortOrder,
            author,
            sent_timestamp,
            received_timestamp,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use std::time::UNIX_EPOCH;

    use assert_matches::assert_matches;

    use protobuf::SpecialFields;
    use test_case::test_case;

    use crate::backup::chat::testutil::TestContext;
    use crate::backup::method::Store;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;
    use crate::backup::Purpose;

    use super::*;

    impl proto::ChatItem {
        pub(crate) fn test_data() -> Self {
            Self {
                chatId: proto::Chat::TEST_ID,
                authorId: proto::Recipient::TEST_ID,
                item: Some(proto::chat_item::Item::StandardMessage(
                    proto::StandardMessage::test_data(),
                )),
                directionalDetails: Some(proto::chat_item::DirectionalDetails::Incoming(
                    proto::chat_item::IncomingMessageDetails {
                        dateReceived: MillisecondsSinceEpoch::TEST_VALUE.0,
                        dateServerSent: MillisecondsSinceEpoch::TEST_VALUE.0,
                        ..Default::default()
                    },
                )),
                expireStartDate: MillisecondsSinceEpoch::TEST_VALUE.0,
                expiresInMs: 12 * 60 * 60 * 1000,
                dateSent: MillisecondsSinceEpoch::TEST_VALUE.0,
                ..Default::default()
            }
        }
    }

    impl proto::Reaction {
        pub(crate) fn test_data() -> Self {
            Self {
                emoji: "📲".to_string(),
                sortOrder: 3,
                authorId: proto::Recipient::TEST_ID,
                sentTimestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                receivedTimestamp: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                ..Default::default()
            }
        }
    }

    impl Reaction {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                emoji: "📲".to_string(),
                sort_order: 3,
                author: RecipientId(proto::Recipient::TEST_ID),
                sent_timestamp: Timestamp::test_value(),
                received_timestamp: Some(Timestamp::test_value()),
                _limit_construction_to_module: (),
            }
        }
    }

    impl proto::chat_item::OutgoingMessageDetails {
        fn test_data() -> Self {
            Self {
                sendStatus: vec![proto::SendStatus::test_data()],
                special_fields: SpecialFields::default(),
            }
        }
    }

    impl proto::SendStatus {
        fn test_data() -> Self {
            Self {
                recipientId: proto::Recipient::TEST_ID,
                deliveryStatus: Some(proto::send_status::DeliveryStatus::Pending(
                    proto::send_status::Pending::default(),
                )),
                ..Default::default()
            }
        }
    }

    #[test]
    fn valid_chat() {
        assert_eq!(
            proto::Chat::test_data().try_into_with(&TestContext::default()),
            Ok(ChatData::<Store> {
                recipient: TestContext::test_recipient().clone(),
                items: Vec::default(),
                expiration_timer: None,
                mute_until: None,
                style: None,
                pinned_order: None,
                archived: false,
                marked_unread: false,
                dont_notify_for_mentions_if_muted: false,
            })
        );
    }

    #[test_case(|x| x.expirationTimerMs = 123456 => Ok(()); "with_expiration_timer")]
    #[test_case(|x| x.muteUntilMs = MillisecondsSinceEpoch::TEST_VALUE.0 => Ok(()); "with mute until")]
    #[test_case(
        |x| x.pinnedOrder = TestContext::DUPLICATE_PINNED_ORDER.0.get() =>
        Err(ChatError::DuplicatePinnedOrder(TestContext::DUPLICATE_PINNED_ORDER,));
        "duplicate_pinned_order"
    )]
    fn chat(modifier: fn(&mut proto::Chat)) -> Result<(), ChatError> {
        let mut chat = proto::Chat::test_data();
        modifier(&mut chat);
        chat.try_into_with(&TestContext::default())
            .map(|_: ChatData<Store>| ())
    }

    #[test]
    fn valid_chat_item() {
        assert_eq!(
            proto::ChatItem::test_data().try_into_with(&TestContext::default()),
            Ok(ChatItemData::<Store> {
                author: TestContext::test_recipient().clone(),
                message: ChatItemMessage::Standard(StandardMessage::from_proto_test_data()),
                revisions: vec![],
                direction: Direction::Incoming {
                    received: Timestamp::test_value(),
                    sent: Timestamp::test_value(),
                    read: false,
                    sealed_sender: false,
                },
                expire_start: Some(Timestamp::test_value()),
                expires_in: Some(Duration::TWELVE_HOURS),
                sent_at: Timestamp::test_value(),
                sms: false,
                total_chat_item_order_index: 0,
                _limit_construction_to_module: (),
            })
        )
    }

    #[test_case(|x| x.authorId = 0xffff => Err(ChatItemError::AuthorNotFound(RecipientId(0xffff))); "unknown_author")]
    #[test_case(|x| x.directionalDetails = None => Err(ChatItemError::NoDirection); "no_direction")]
    #[test_case(|x| x.directionalDetails = Some(proto::chat_item::OutgoingMessageDetails::test_data().into()) => Ok(()); "outgoing_valid")]
    #[test_case(|x| x.directionalDetails = Some(
            proto::chat_item::OutgoingMessageDetails {
                sendStatus: vec![proto::SendStatus {
                    deliveryStatus: None,
                    ..proto::SendStatus::test_data()
                }],
                ..proto::chat_item::OutgoingMessageDetails::test_data()
            }
            .into(),
        ) => Err(ChatItemError::Outgoing(OutgoingSendError::SendStatusMissing)); "outgoing_send_status_unknown"
    )]
    #[test_case(|x| x.directionalDetails = Some(
            proto::chat_item::OutgoingMessageDetails {
                sendStatus: vec![proto::SendStatus {
                    deliveryStatus: Some(proto::send_status::DeliveryStatus::Failed(
                        proto::send_status::Failed {
                            // Unlike many other UNKNOWN cases in Backup.proto, this one is
                            // considered valid; the other cases are just being more specific.
                            reason: proto::send_status::failed::FailureReason::UNKNOWN.into(),
                            ..Default::default()
                        },
                    )),
                    ..proto::SendStatus::test_data()
                }],
                ..proto::chat_item::OutgoingMessageDetails::test_data()
            }
            .into()
        ) => Ok(()); "outgoing send status failed")]
    #[test_case(
        |x| x.directionalDetails = Some(
            proto::chat_item::OutgoingMessageDetails {
                sendStatus: vec![proto::SendStatus {
                    recipientId: 0xffff,
                    ..proto::SendStatus::test_data()
                }],
                ..proto::chat_item::OutgoingMessageDetails::test_data()
            }
            .into(),
        ) => Err(ChatItemError::Outgoing(OutgoingSendError::UnknownRecipient(RecipientId(0xffff)))); "outgoing_unknown_recipient"
    )]
    fn chat_item(modifier: fn(&mut proto::ChatItem)) -> Result<(), ChatItemError> {
        let mut message = proto::ChatItem::test_data();
        modifier(&mut message);

        message
            .try_into_with(&TestContext::default())
            .map(|_: ChatItemData<Store>| ())
    }

    #[test]
    fn valid_reaction() {
        assert_eq!(
            proto::Reaction::test_data().try_into_with(&TestContext::default()),
            Ok(Reaction::from_proto_test_data())
        )
    }

    #[test_case(
        |x| x.authorId = proto::Recipient::TEST_ID + 2 => Err(ReactionError::AuthorNotFound(RecipientId(proto::Recipient::TEST_ID + 2)));
        "invalid_author_id"
    )]
    #[test_case(|x| x.receivedTimestamp = None => Ok(()); "no_received_timestamp")]
    fn reaction(modifier: fn(&mut proto::Reaction)) -> Result<(), ReactionError> {
        let mut reaction = proto::Reaction::test_data();
        modifier(&mut reaction);

        reaction
            .try_into_with(&TestContext::default())
            .map(|_: Reaction| ())
    }

    #[test_case(Purpose::DeviceTransfer, 3600, Ok(()))]
    #[test_case(Purpose::RemoteBackup, 86400, Ok(()))]
    #[test_case(
        Purpose::RemoteBackup,
        3600,
        Err("expires 3600s after backup creation")
    )]
    #[test_case(Purpose::DeviceTransfer, -3600, Err("expired 3600s before backup creation"))]
    #[test_case(Purpose::RemoteBackup, -3600, Err("expired 3600s before backup creation"))]
    fn expiring_message(
        backup_purpose: Purpose,
        until_expiration_s: i64,
        expected: Result<(), &str>,
    ) {
        const SINCE_RECEIVED_MS: u64 = 1000 * 60 * 60 * 5;

        // There are three points in time here: the time when a message was
        // received, the time when the backup was started, and the time when the
        // message expires.
        let received_at = Timestamp::test_value();
        let backup_time = received_at + Duration::from_millis(SINCE_RECEIVED_MS);
        let until_expiration_ms =
            u64::try_from(SINCE_RECEIVED_MS as i64 + (1000 * until_expiration_s))
                .expect("positive");

        let meta = BackupMeta {
            backup_time,
            purpose: backup_purpose,
            version: 0,
        };

        let mut item = proto::ChatItem::test_data();

        item.expireStartDate = received_at
            .into_inner()
            .duration_since(UNIX_EPOCH)
            .expect("valid")
            .as_millis()
            .try_into()
            .unwrap();
        item.expiresInMs = until_expiration_ms;

        let result = ChatItemData::<Store>::try_from_with(item, &TestContext(meta))
            .map(|_| ())
            .map_err(|e| assert_matches!(e, ChatItemError::InvalidExpiration(e) => e).to_string());
        assert_eq!(result, expected.map_err(ToString::to_string));
    }

    #[test]
    fn mismatch_between_expiration_start_and_duration_presence() {
        let mut item = proto::ChatItem::test_data();
        assert_ne!(item.expireStartDate, 0);
        item.expiresInMs = 0;

        assert_matches!(
            ChatItemData::<Store>::try_from_with(item, &TestContext::default()),
            Err(ChatItemError::ExpirationMismatch)
        );
    }
}
