//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complains about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use std::fmt::Debug;

use derive_where::derive_where;

use crate::backup::chat::chat_style::{ChatStyle, ChatStyleError, CustomColorId};
use crate::backup::file::{FilePointerError, MessageAttachmentError};
use crate::backup::frame::RecipientId;
use crate::backup::method::{Lookup, LookupPair, Method};
use crate::backup::recipient::{
    ChatItemAuthorKind, ChatRecipientKind, DestinationKind, MinimalRecipientData,
};
use crate::backup::serialize::{SerializeOrder, UnorderedList};
use crate::backup::sticker::MessageStickerError;
use crate::backup::time::{
    Duration, ReportUnusualTimestamp, Timestamp, TimestampError, TimestampOrForever,
};
use crate::backup::{
    likely_empty, BackupMeta, CallError, ReferencedTypes, TryFromWith, TryIntoWith as _,
};
use crate::proto::backup as proto;

mod contact_message;
use contact_message::*;

pub(crate) mod chat_style;

mod gift_badge;
use gift_badge::*;

pub(crate) mod group;
use group::*;

mod link;
use link::*;

mod payment;
use payment::*;

mod quote;
use quote::*;

mod reactions;
use reactions::*;

mod standard_message;
use standard_message::*;

mod sticker_message;
use sticker_message::*;

mod story_reply;
use story_reply::*;

pub(crate) mod text;
use text::*;

mod update_message;
use update_message::*;

mod view_once_message;
use view_once_message::*;

mod voice_message;
use voice_message::*;

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ChatError {
    /// 0 is not a valid chat ID
    InvalidId,
    /// multiple records with the same ID
    DuplicateId,
    /// no record for {0:?}
    NoRecipient(RecipientId),
    /// cannot have a chat with recipient {0:?}, a {1:?}
    InvalidRecipient(RecipientId, DestinationKind),
    /// chat with {0:?} has an expirationTimerMs but no expireTimerVersion
    MissingExpireTimerVersion(RecipientId),
    /// chat item {raw_timestamp}: {error}
    ChatItem {
        raw_timestamp: u64,
        error: ChatItemError,
    },
    /// {0:?} already appeared
    DuplicatePinnedOrder(PinOrder),
    /// style error: {0}
    Style(#[from] ChatStyleError),
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ChatItemError {
    /// no record for chat
    NoChatForItem,
    /// no record for chat item author {0:?}
    AuthorNotFound(RecipientId),
    /// chat item author {0:?} is a {1:?}
    InvalidAuthor(RecipientId, DestinationKind),
    /// incoming message authored by self
    IncomingMessageFromSelf,
    /// outgoing message authored by {1:?} {0:?}
    OutgoingMessageFrom(RecipientId, DestinationKind),
    /// incoming message authored by contact {0:?} with no ACI or e164
    IncomingMessageFromContactWithoutAciOrE164(RecipientId),
    /// ChatItem.item is a oneof but is empty
    MissingItem,
    /// StandardMessage has neither text nor attachments
    StandardMessageIsEmpty,
    /// text: {0}
    Text(#[from] TextError),
    /// long text: {0}
    LongText(FilePointerError),
    /// StandardMessage has longText but no body text
    LongTextWithoutBody,
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
    /// view-once message: {0}
    ViewOnce(#[from] ViewOnceMessageError),
    /// direct story reply: {0}
    DirectStoryReply(#[from] DirectStoryReplyError),
    /// ChatItem.directionalDetails is a oneof but is empty
    NoDirection,
    /// directionless ChatItem wasn't an update message
    DirectionlessMessage,
    /// update message wasn't directionless
    UpdateMessageShouldBeDirectionless,
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
    /// item has expiration start date but no duration
    ExpirationMismatch,
    /// item has been read/sent but expiration timer has not started
    ExpirationNotStarted,
    /// expiration too soon: {0}
    InvalidExpiration(#[from] InvalidExpiration),
    /// revisions of message from author {0:?} contained message from author {1:?}
    RevisionWithMismatchedAuthor(RecipientId, RecipientId),
    /// revisions of {0:?} message contained {1:?} message
    RevisionWithMismatchedDirection(DirectionDiscriminants, DirectionDiscriminants),
    /// revisions of {0:?} message contained {1:?} message
    RevisionWithMismatchedMessageType(ChatItemMessageDiscriminants, ChatItemMessageDiscriminants),
    /// ChatItem that isn't a StandardMessage or DirectStoryReplyMessage has revisions
    NonStandardMessageHasRevisions,
    /// nested revisions
    RevisionContainsRevisions,
    /// profile change update must have both a previousName and a newName
    ProfileChangeMissingNames,
    /// learned profile chat update has no e164 or name
    LearnedProfileIsEmpty,
    /// chat update not from contact: {0:?}
    ChatUpdateNotFromContact(SimpleChatUpdate),
    /// chat update not from ACI: {0:?}
    ChatUpdateNotFromAci(SimpleChatUpdate),
    /// chat update not from Self: {0:?}
    ChatUpdateNotFromSelf(SimpleChatUpdate),
    /// donation request not from Release Notes recipient
    DonationRequestNotFromReleaseNotesRecipient,
    /// group update not from contact or Self
    GroupUpdateNotFromContact,
    /// expiration timer change not from contact or Self
    ExpirationTimerChangeNotFromContact,
    /// profile change not from contact
    ProfileChangeNotFromContact,
    /// thread merge not from ACI
    ThreadMergeNotFromAci,
    /// session switchover not from ACI
    SessionSwitchoverNotFromAci,
    /// call not from contact or self
    CallNotFromContact,
    /// learned profile update not from contact
    LearnedProfileUpdateNotFromContact,
    /// message from contact found in a different 1:1 chat
    MessageFromContactInWrongIndividualChat,
    /// message from contact found in Note to Self
    MessageFromContactInNoteToSelf,
    /// message from contact found in Release Notes
    MessageFromContactInReleaseNotes,
    /// message from release notes recipient found in {0:?} chat instead
    ReleaseNoteMessageNotInReleaseNoteChat(DestinationKind),
    /// payment notification found in {0:?} chat
    PaymentNotificationNotInContactThread(DestinationKind),
    /// direct story reply found in {0:?} chat
    DirectStoryReplyNotInContactThread(DestinationKind),
    /// chat update not in contact thread: {0:?}
    ChatUpdateNotInContactThread(SimpleChatUpdate),
    /// unexpected update message in Release Notes
    UnexpectedUpdateInReleaseNotes,
    /// donation request outside of Release Notes chat
    DonationRequestNotInReleaseNotesChat,
    /// group update not in group thread
    GroupUpdateNotInGroupThread,
    /// expiration timer change not in contact thread
    ExpirationTimerChangeNotInContactThread,
    /// thread merge not in contact thread
    ThreadMergeNotInContactThread,
    /// session switchover not in contact thread
    SessionSwitchoverNotInContactThread,
    /// individual call not in contact thread
    IndividualCallNotInContactThread,
    /// group call not in group thread
    GroupCallNotInGroupThread,
    /// invalid e164
    InvalidE164,
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
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
    // Stored inline to avoid a second lookup when we want to do checks against a chat's recipient.
    #[serde(skip)]
    pub cached_recipient_info: ChatRecipientKind,
    // This list can get quite large (when using the Store method), to the point that reallocation
    // times start showing up in benchmarks of the `validator` CLI tool. However, experiments with a
    // custom "segmented list" type (roughly `Vec<Vec<ChatItemData>>`) showed that there wasn't too
    // much time to be gained here; while we can move less data around on reallocation, ultimately
    // large backups just have a lot of ChatItems to push, one at a time.
    #[serde(bound(serialize = "M::List<ChatItemData<M>>: serde::Serialize"))]
    pub items: M::List<ChatItemData<M>>,
    pub expiration_timer: Option<Duration>,
    pub expiration_timer_version: u32,
    pub mute_until: Option<TimestampOrForever>,
    pub style: Option<ChatStyle<M>>,
    pub pinned_order: Option<PinOrder>,
    pub dont_notify_for_mentions_if_muted: bool,
    pub marked_unread: bool,
    pub archived: bool,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, serde::Serialize)]
pub struct PinOrder(pub(super) u32);

/// Validated version of [`proto::ChatItem`].
#[derive_where(Debug)]
#[derive(serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq;
    ChatItemMessage<M>: PartialEq,
    M::RecipientReference: PartialEq
))]
pub struct ChatItemData<M: Method + ReferencedTypes> {
    pub author: M::RecipientReference,
    // Stored here to save a lookup.
    #[serde(skip)]
    pub cached_author_kind: ChatItemAuthorKind,
    #[serde(bound(serialize = "ChatItemMessage<M>: serde::Serialize"))]
    pub message: ChatItemMessage<M>,
    // This could be Self: Serialize but that just confuses the compiler.
    pub revisions: Vec<ChatItemData<M>>,
    pub direction: Direction<M::RecipientReference>,
    pub expire_start: Option<Timestamp>,
    pub expires_in: Option<Duration>,
    pub sent_at: Timestamp,
    pub sms: bool,
    /// The position of this chat item among all chat items (across chats) in
    /// the source stream.
    pub total_chat_item_order_index: usize,
    _limit_construction_to_module: (),
}

const MAX_REMOTE_BACKUP_DISAPPEARING_MESSAGE_TIME: Duration = Duration::from_hours(24);

/// Validated version of [`proto::chat_item::Item`].
#[derive_where(Debug)]
#[derive(serde::Serialize, strum::EnumDiscriminants)]
#[cfg_attr(test, derive_where(PartialEq;
    M::BoxedValue<GiftBadge>: PartialEq,
    M::RecipientReference: PartialEq
))]
pub enum ChatItemMessage<M: Method + ReferencedTypes> {
    Standard(StandardMessage<M::RecipientReference>),
    Contact(ContactMessage<M::RecipientReference>),
    Voice(VoiceMessage<M::RecipientReference>),
    Sticker(StickerMessage<M::RecipientReference>),
    RemoteDeleted,
    Update(UpdateMessage<M::RecipientReference>),
    PaymentNotification(PaymentNotification),
    GiftBadge(M::BoxedValue<GiftBadge>),
    ViewOnce(ViewOnceMessage<M::RecipientReference>),
    DirectStoryReply(DirectStoryReplyMessage<M::RecipientReference>),
}

#[allow(dead_code)]
const CHAT_ITEM_MESSAGE_SIZE_LIMIT: usize = 200;
static_assertions::const_assert!(
    std::mem::size_of::<StandardMessage<RecipientId>>() < CHAT_ITEM_MESSAGE_SIZE_LIMIT
);
static_assertions::const_assert!(
    std::mem::size_of::<ContactMessage<RecipientId>>() < CHAT_ITEM_MESSAGE_SIZE_LIMIT
);
static_assertions::const_assert!(
    std::mem::size_of::<VoiceMessage<RecipientId>>() < CHAT_ITEM_MESSAGE_SIZE_LIMIT
);
static_assertions::const_assert!(
    std::mem::size_of::<StickerMessage<RecipientId>>() < CHAT_ITEM_MESSAGE_SIZE_LIMIT
);
static_assertions::const_assert!(
    std::mem::size_of::<UpdateMessage<RecipientId>>() < CHAT_ITEM_MESSAGE_SIZE_LIMIT
);
static_assertions::const_assert!(
    std::mem::size_of::<PaymentNotification>() < CHAT_ITEM_MESSAGE_SIZE_LIMIT
);
static_assertions::const_assert!(
    std::mem::size_of::<ViewOnceMessage<RecipientId>>() < CHAT_ITEM_MESSAGE_SIZE_LIMIT
);
static_assertions::const_assert!(
    std::mem::size_of::<ViewOnceMessage<RecipientId>>() < CHAT_ITEM_MESSAGE_SIZE_LIMIT
);

#[derive(Debug, serde::Serialize, strum::EnumDiscriminants)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Direction<Recipient> {
    Incoming {
        sent: Option<Timestamp>,
        received: Timestamp,
        read: bool,
        sealed_sender: bool,
    },
    Outgoing(
        #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
        UnorderedList<OutgoingSend<Recipient>>,
    ),
    Directionless,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub struct OutgoingSend<Recipient> {
    #[serde(bound(serialize = "Recipient: serde::Serialize"))]
    pub recipient: Recipient,
    pub status: DeliveryStatus,
    pub last_status_update: Timestamp,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub enum DeliveryFailureReason {
    Unknown,
    Network,
    IdentityKeyMismatch,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq, Clone))]
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
    /// send status recipient {0:?} is a {1:?}, not a contact or self
    InvalidRecipient(RecipientId, DestinationKind),
    /// send status is missing
    SendStatusMissing,
    /// send status for recipient {0:?}: {1}
    InvalidTimestamp(RecipientId, TimestampError),
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
        C: LookupPair<RecipientId, MinimalRecipientData, M::RecipientReference>
            + Lookup<PinOrder, M::RecipientReference>
            + Lookup<CustomColorId, M::CustomColorReference>
            + ReportUnusualTimestamp,
    > TryFromWith<proto::Chat, C> for ChatData<M>
{
    type Error = ChatError;

    fn try_from_with(value: proto::Chat, context: &C) -> Result<Self, Self::Error> {
        let proto::Chat {
            id: _,
            recipientId,
            expirationTimerMs,
            expireTimerVersion,
            muteUntilMs,
            pinnedOrder,
            archived,
            markedUnread,
            dontNotifyForMentionsIfMuted,
            style,
            special_fields: _,
        } = value;

        let recipient_id = RecipientId(recipientId);
        let Some((recipient_data, recipient)) = context.lookup_pair(&recipient_id) else {
            return Err(ChatError::NoRecipient(recipient_id));
        };
        let cached_recipient_info = ChatRecipientKind::try_from(recipient_data)
            .map_err(|kind| ChatError::InvalidRecipient(recipient_id, kind))?;

        let pinned_order = pinnedOrder.map(PinOrder);
        if let Some(pinned_order) = pinned_order {
            if let Some(_recipient) = context.lookup(&pinned_order) {
                return Err(ChatError::DuplicatePinnedOrder(pinned_order));
            }
        };

        let style = style
            .into_option()
            .map(|style| ChatStyle::try_from_proto(style, context, context))
            .transpose()?;

        let expiration_timer = expirationTimerMs.map(Duration::from_millis);

        let mute_until = muteUntilMs
            .map(|t| TimestampOrForever::from_millis(t, "Chat.muteUntilMs", context))
            .transpose()?;

        if expiration_timer.is_some() && expireTimerVersion == 0 {
            return Err(ChatError::MissingExpireTimerVersion(recipient_id));
        }
        let expiration_timer_version = expireTimerVersion;

        Ok(Self {
            recipient: recipient.clone(),
            cached_recipient_info,
            expiration_timer,
            expiration_timer_version,
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
        C: LookupPair<RecipientId, MinimalRecipientData, M::RecipientReference>
            + AsRef<BackupMeta>
            + ReportUnusualTimestamp,
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

        let direction = directionalDetails
            .ok_or(ChatItemError::NoDirection)?
            .try_into_with(context)?;

        let author_id = RecipientId(authorId);

        let Some((author_data, author)) = context.lookup_pair(&author_id) else {
            return Err(ChatItemError::AuthorNotFound(author_id));
        };
        let cached_author_kind = match (author_data, &direction) {
            // Even update messages in groups are still attributed to self (if not a specific
            // author)
            (
                MinimalRecipientData::Group { .. }
                | MinimalRecipientData::DistributionList { .. }
                | MinimalRecipientData::CallLink { .. },
                _,
            ) => Err(ChatItemError::InvalidAuthor(
                author_id,
                *author_data.as_ref(),
            )),

            (MinimalRecipientData::Self_, Direction::Incoming { .. }) => {
                Err(ChatItemError::IncomingMessageFromSelf)
            }

            (
                MinimalRecipientData::Contact { .. } | MinimalRecipientData::ReleaseNotes,
                Direction::Outgoing(_),
            ) => Err(ChatItemError::OutgoingMessageFrom(
                author_id,
                *author_data.as_ref(),
            )),

            (
                MinimalRecipientData::Contact {
                    e164: None,
                    aci: None,
                    pni: _,
                },
                Direction::Incoming { .. },
            ) => Err(ChatItemError::IncomingMessageFromContactWithoutAciOrE164(
                author_id,
            )),

            (MinimalRecipientData::Self_, Direction::Outgoing(_))
            | (MinimalRecipientData::Self_, Direction::Directionless) => {
                Ok(ChatItemAuthorKind::Self_)
            }
            (MinimalRecipientData::Contact { aci, e164, .. }, Direction::Incoming { .. })
            | (MinimalRecipientData::Contact { aci, e164, .. }, Direction::Directionless) => {
                Ok(ChatItemAuthorKind::Contact {
                    has_aci: aci.is_some(),
                    has_e164: e164.is_some(),
                })
            }
            (MinimalRecipientData::ReleaseNotes, Direction::Incoming { .. })
            | (MinimalRecipientData::ReleaseNotes, Direction::Directionless) => {
                Ok(ChatItemAuthorKind::ReleaseNotes)
            }
        }?;

        let message = item
            .ok_or(ChatItemError::MissingItem)?
            .try_into_with(context)?;

        match (&direction, &message) {
            (Direction::Directionless, ChatItemMessage::Update(_)) => Ok(()),
            (Direction::Directionless, _) => Err(ChatItemError::DirectionlessMessage),
            (_, ChatItemMessage::Update(_)) => {
                Err(ChatItemError::UpdateMessageShouldBeDirectionless)
            }
            (_, _) => Ok(()),
        }?;

        if let ChatItemMessage::Update(update) = &message {
            update.validate_author(&cached_author_kind)?;
        }

        if !revisions.is_empty() {
            match &message {
                ChatItemMessage::Standard(_) | ChatItemMessage::DirectStoryReply(_) => {}
                ChatItemMessage::Contact(_)
                | ChatItemMessage::Voice(_)
                | ChatItemMessage::Sticker(_)
                | ChatItemMessage::RemoteDeleted
                | ChatItemMessage::Update(_)
                | ChatItemMessage::PaymentNotification(_)
                | ChatItemMessage::GiftBadge(_)
                | ChatItemMessage::ViewOnce(_) => {
                    return Err(ChatItemError::NonStandardMessageHasRevisions);
                }
            }
        }

        let expected_message_type = ChatItemMessageDiscriminants::from(&message);
        let revisions: Vec<_> = likely_empty(revisions, |iter| {
            iter.map(|rev| {
                // We have to test this on the raw IDs because RecipientReference isn't necessarily
                // comparable.
                if author_id.0 != rev.authorId {
                    return Err(ChatItemError::RevisionWithMismatchedAuthor(
                        author_id,
                        RecipientId(rev.authorId),
                    ));
                }

                let item: ChatItemData<M> = rev.try_into_with(context)?;
                if DirectionDiscriminants::from(&direction)
                    != DirectionDiscriminants::from(&item.direction)
                {
                    return Err(ChatItemError::RevisionWithMismatchedDirection(
                        DirectionDiscriminants::from(&direction),
                        DirectionDiscriminants::from(&item.direction),
                    ));
                }

                let revision_message_type = ChatItemMessageDiscriminants::from(&item.message);
                if revision_message_type != expected_message_type {
                    return Err(ChatItemError::RevisionWithMismatchedMessageType(
                        expected_message_type,
                        revision_message_type,
                    ));
                }

                if !item.revisions.is_empty() {
                    return Err(ChatItemError::RevisionContainsRevisions);
                }
                Ok(item)
            })
            .collect::<Result<_, _>>()
        })?;

        let sent_at = Timestamp::from_millis(dateSent, "ChatItem.dateSent", context)?;
        let expire_start = expireStartDate
            .map(|date| Timestamp::from_millis(date, "ChatItem.expireStartDate", context))
            .transpose()?;
        let expires_in = expiresInMs.map(Into::into).map(Duration::from_millis);

        match (expire_start, expires_in) {
            (None, None) => {
                // Not a disappearing message.
            }
            (Some(_), None) => return Err(ChatItemError::ExpirationMismatch),
            (None, Some(_)) => {
                let should_have_started = match &direction {
                    Direction::Incoming {
                        sent: _,
                        received: _,
                        read,
                        sealed_sender: _,
                    } => *read,
                    Direction::Outgoing(outgoing) => {
                        outgoing.0.iter().all(|send| match send.status {
                            DeliveryStatus::Failed(_) => false,
                            DeliveryStatus::Pending => false,

                            // The timer starts when the "sent" checkmark shows up.
                            DeliveryStatus::Sent { .. } => true,
                            DeliveryStatus::Delivered { .. } => true,
                            DeliveryStatus::Read { .. } => true,
                            DeliveryStatus::Viewed { .. } => true,
                            DeliveryStatus::Skipped => true,
                        })
                    }
                    Direction::Directionless => {
                        // "read" state isn't tracked, so we have to conservatively allow this.
                        false
                    }
                };
                if should_have_started {
                    return Err(ChatItemError::ExpirationNotStarted);
                }
            }
            (Some(expire_start), Some(expires_in)) => {
                let expires_at = expire_start + expires_in;
                // Ensure that ephemeral content that's due to expire soon isn't backed up.
                let backup_time = context.as_ref().backup_time;
                let allowed_expire_at = backup_time
                    + match context.as_ref().purpose {
                        crate::backup::Purpose::DeviceTransfer => Duration::ZERO,
                        crate::backup::Purpose::RemoteBackup => {
                            MAX_REMOTE_BACKUP_DISAPPEARING_MESSAGE_TIME
                        }
                    };

                if expires_at < allowed_expire_at {
                    return Err(InvalidExpiration {
                        expires_at,
                        backup_time,
                    }
                    .into());
                }
            }
        }

        Ok(Self {
            author: author.clone(),
            cached_author_kind,
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

impl<M: Method + ReferencedTypes> ChatItemData<M> {
    pub(crate) fn validate_chat_recipient(
        &self,
        recipient_ref: &M::RecipientReference,
        recipient_data: &ChatRecipientKind,
    ) -> Result<(), ChatItemError> {
        match self.cached_author_kind {
            ChatItemAuthorKind::Contact { .. } => match recipient_data {
                ChatRecipientKind::Contact { .. } => {
                    if !M::is_same_reference(&self.author, recipient_ref) {
                        return Err(ChatItemError::MessageFromContactInWrongIndividualChat);
                    }
                }
                ChatRecipientKind::Group => {
                    // Okay (anyone could have been in a group at some point in the past)
                }
                ChatRecipientKind::Self_ => {
                    return Err(ChatItemError::MessageFromContactInNoteToSelf);
                }
                ChatRecipientKind::ReleaseNotes => {
                    return Err(ChatItemError::MessageFromContactInReleaseNotes);
                }
            },
            ChatItemAuthorKind::Self_ => {
                // Okay (Self can send messages in every channel, at least update messages)
            }
            ChatItemAuthorKind::ReleaseNotes => {
                if !matches!(recipient_data, ChatRecipientKind::ReleaseNotes) {
                    return Err(ChatItemError::ReleaseNoteMessageNotInReleaseNoteChat(
                        (*recipient_data).into(),
                    ));
                }
            }
        }

        match &self.message {
            ChatItemMessage::Standard(_)
            | ChatItemMessage::Contact(_)
            | ChatItemMessage::Voice(_)
            | ChatItemMessage::Sticker(_)
            | ChatItemMessage::RemoteDeleted
            | ChatItemMessage::ViewOnce(_) => {
                // Most messages can appear in any chat.
            }
            ChatItemMessage::GiftBadge(_) => {
                // Gift badge messages *can* end up in any chat, even though usually only 1:1 chats
                // make sense.
            }
            ChatItemMessage::Update(update) => {
                update.validate_chat_recipient(recipient_data)?;
            }
            ChatItemMessage::PaymentNotification(_) => {
                if !recipient_data.is_contact_with_aci() {
                    return Err(ChatItemError::PaymentNotificationNotInContactThread(
                        (*recipient_data).into(),
                    ));
                }
            }
            ChatItemMessage::DirectStoryReply(_) => {
                if !recipient_data.is_contact_with_aci() {
                    return Err(ChatItemError::DirectStoryReplyNotInContactThread(
                        (*recipient_data).into(),
                    ));
                }
            }
        }

        Ok(())
    }
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryFromWith<proto::chat_item::DirectionalDetails, C> for Direction<R>
{
    type Error = ChatItemError;

    fn try_from_with(
        item: proto::chat_item::DirectionalDetails,
        context: &C,
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
                let sent = dateServerSent
                    .map(|sent| {
                        Timestamp::from_millis(sent, "DirectionalDetails.dateServerSent", context)
                    })
                    .transpose()?;
                let received = Timestamp::from_millis(
                    dateReceived,
                    "DirectionalDetails.dateReceived",
                    context,
                )?;
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
impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryFromWith<proto::SendStatus, C> for OutgoingSend<R>
{
    type Error = OutgoingSendError;

    fn try_from_with(item: proto::SendStatus, context: &C) -> Result<Self, Self::Error> {
        let proto::SendStatus {
            recipientId,
            timestamp,
            deliveryStatus,
            special_fields: _,
        } = item;

        let recipient_id = RecipientId(recipientId);
        let Some((recipient_data, recipient)) = context.lookup_pair(&recipient_id) else {
            return Err(OutgoingSendError::UnknownRecipient(recipient_id));
        };
        let recipient = match recipient_data {
            MinimalRecipientData::Contact { .. } | MinimalRecipientData::Self_ => {
                Ok(recipient.clone())
            }
            MinimalRecipientData::Group { .. }
            | MinimalRecipientData::DistributionList { .. }
            | MinimalRecipientData::ReleaseNotes
            | MinimalRecipientData::CallLink { .. } => Err(OutgoingSendError::InvalidRecipient(
                recipient_id,
                *recipient_data.as_ref(),
            )),
        }?;

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

        let last_status_update = Timestamp::from_millis(timestamp, "SendStatus.timestamp", context)
            .map_err(|e| OutgoingSendError::InvalidTimestamp(recipient_id, e))?;

        Ok(Self {
            recipient,
            status,
            last_status_update,
        })
    }
}

impl<
        C: LookupPair<RecipientId, MinimalRecipientData, M::RecipientReference>
            + AsRef<BackupMeta>
            + ReportUnusualTimestamp,
        M: Method + ReferencedTypes,
    > TryFromWith<proto::chat_item::Item, C> for ChatItemMessage<M>
{
    type Error = ChatItemError;

    fn try_from_with(value: proto::chat_item::Item, context: &C) -> Result<Self, Self::Error> {
        use proto::chat_item::Item;

        Ok(match value {
            Item::StandardMessage(message) => {
                let is_voice_message = matches!(message.attachments.as_slice(),
                [single_attachment] if
                    single_attachment.flag.enum_value_or_default()
                        == proto::message_attachment::Flag::VOICE_MESSAGE
                );

                if is_voice_message {
                    ChatItemMessage::Voice(message.try_into_with(context)?)
                } else {
                    ChatItemMessage::Standard(message.try_into_with(context)?)
                }
            }
            Item::ContactMessage(message) => {
                ChatItemMessage::Contact(message.try_into_with(context)?)
            }
            Item::StickerMessage(message) => {
                ChatItemMessage::Sticker(message.try_into_with(context)?)
            }
            Item::RemoteDeletedMessage(proto::RemoteDeletedMessage { special_fields: _ }) => {
                ChatItemMessage::RemoteDeleted
            }
            Item::UpdateMessage(message) => {
                ChatItemMessage::Update(message.try_into_with(context)?)
            }
            Item::PaymentNotification(message) => {
                ChatItemMessage::PaymentNotification(message.try_into_with(context)?)
            }
            Item::GiftBadge(badge) => ChatItemMessage::GiftBadge(M::boxed_value(badge.try_into()?)),
            Item::ViewOnceMessage(message) => {
                ChatItemMessage::ViewOnce(message.try_into_with(context)?)
            }
            Item::DirectStoryReplyMessage(message) => {
                ChatItemMessage::DirectStoryReply(message.try_into_with(context)?)
            }
        })
    }
}

#[cfg(test)]
mod test {
    use std::time::UNIX_EPOCH;

    use assert_matches::assert_matches;
    use protobuf::SpecialFields;
    use test_case::test_case;

    use super::*;
    use crate::backup::method::Store;
    use crate::backup::testutil::TestContext;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;
    use crate::backup::Purpose;

    impl proto::ChatItem {
        pub(crate) fn test_data() -> Self {
            Self {
                chatId: proto::Chat::TEST_ID,
                authorId: TestContext::CONTACT_ID.0,
                item: Some(proto::chat_item::Item::StandardMessage(
                    proto::StandardMessage::test_data(),
                )),
                directionalDetails: Some(proto::chat_item::DirectionalDetails::Incoming(
                    proto::chat_item::IncomingMessageDetails {
                        dateReceived: MillisecondsSinceEpoch::TEST_VALUE.0,
                        dateServerSent: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                        ..Default::default()
                    },
                )),
                expireStartDate: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                expiresInMs: Some(24 * 60 * 60 * 1000),
                dateSent: MillisecondsSinceEpoch::TEST_VALUE.0,
                ..Default::default()
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
                recipient: TestContext::contact_recipient().clone(),
                cached_recipient_info: (AsRef::<MinimalRecipientData>::as_ref(
                    TestContext::contact_recipient()
                ))
                .try_into()
                .unwrap(),
                items: Vec::default(),
                expiration_timer: None,
                expiration_timer_version: 0,
                mute_until: None,
                style: None,
                pinned_order: None,
                archived: false,
                marked_unread: false,
                dont_notify_for_mentions_if_muted: false,
            })
        );
    }

    #[test_case(|x| {
        x.expirationTimerMs = Some(123456);
        x.expireTimerVersion = 3;
     } => Ok(()); "with_expiration_timer")]
    #[test_case(|x| x.expirationTimerMs = Some(123456) => Err(ChatError::MissingExpireTimerVersion(TestContext::CONTACT_ID)); "with_expiration_timer_only")]
    #[test_case(|x| x.expireTimerVersion = 3 => Ok(()); "with_expire_timer_version_only")]
    #[test_case(|x| x.muteUntilMs = Some(MillisecondsSinceEpoch::TEST_VALUE.0) => Ok(()); "with mute until")]
    #[test_case(
        |x| x.muteUntilMs = Some(MillisecondsSinceEpoch::FAR_FUTURE.0) =>
        Err(ChatError::InvalidTimestamp(TimestampError("Chat.muteUntilMs", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid mute until"
    )]
    #[test_case(
        |x| x.pinnedOrder = Some(TestContext::DUPLICATE_PINNED_ORDER.0) =>
        Err(ChatError::DuplicatePinnedOrder(TestContext::DUPLICATE_PINNED_ORDER));
        "duplicate_pinned_order"
    )]
    #[test_case(|x| {
        x.recipientId = TestContext::CALL_LINK_ID.0;
    } => Err(ChatError::InvalidRecipient(TestContext::CALL_LINK_ID, DestinationKind::CallLink)); "call link chat")]
    #[test_case(|x| {
        x.recipientId = 0;
    } => Err(ChatError::NoRecipient(RecipientId(0))); "unknown recipient")]
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
                author: TestContext::contact_recipient().clone(),
                cached_author_kind: ChatItemAuthorKind::Contact {
                    has_aci: true,
                    has_e164: true,
                },
                message: ChatItemMessage::Standard(StandardMessage::from_proto_test_data()),
                revisions: vec![],
                direction: Direction::Incoming {
                    received: Timestamp::test_value(),
                    sent: Some(Timestamp::test_value()),
                    read: false,
                    sealed_sender: false,
                },
                expire_start: Some(Timestamp::test_value()),
                expires_in: Some(MAX_REMOTE_BACKUP_DISAPPEARING_MESSAGE_TIME),
                sent_at: Timestamp::test_value(),
                sms: false,
                total_chat_item_order_index: 0,
                _limit_construction_to_module: (),
            })
        )
    }

    #[test_case(|x| x.authorId = 0xffff => Err(ChatItemError::AuthorNotFound(RecipientId(0xffff))); "unknown_author")]
    #[test_case(|x| x.authorId = TestContext::GROUP_ID.0 => Err(ChatItemError::InvalidAuthor(TestContext::GROUP_ID, DestinationKind::Group)); "invalid author")]
    #[test_case(|x| x.authorId = TestContext::PNI_ONLY_ID.0 => Err(ChatItemError::IncomingMessageFromContactWithoutAciOrE164(TestContext::PNI_ONLY_ID)); "pni-only author")]
    #[test_case(|x| x.directionalDetails = None => Err(ChatItemError::NoDirection); "no_direction")]
    #[test_case(|x| {
        x.authorId = TestContext::SELF_ID.0;
        x.directionalDetails = Some(proto::chat_item::OutgoingMessageDetails::test_data().into());
    } => Ok(()); "outgoing_valid")]
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
    #[test_case(|x| {
        x.authorId = TestContext::SELF_ID.0;
        x.directionalDetails = Some(
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
        );
    } => Ok(()); "outgoing send status failed")]
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
    #[test_case(
        |x| x.directionalDetails = Some(
            proto::chat_item::OutgoingMessageDetails {
                sendStatus: vec![proto::SendStatus {
                    recipientId: TestContext::GROUP_ID.0,
                    ..proto::SendStatus::test_data()
                }],
                ..proto::chat_item::OutgoingMessageDetails::test_data()
            }
            .into(),
        ) => Err(ChatItemError::Outgoing(OutgoingSendError::InvalidRecipient(TestContext::GROUP_ID, DestinationKind::Group))); "outgoing invalid recipient"
    )]
    #[test_case(|x| x.directionalDetails = Some(proto::chat_item::DirectionlessMessageDetails::default().into()) => Err(ChatItemError::DirectionlessMessage); "directionless_non_update")]
    #[test_case(|x| {
        x.directionalDetails = Some(proto::chat_item::DirectionlessMessageDetails::default().into());
        x.set_updateMessage(proto::ChatUpdateMessage {
            update: Some(proto::chat_update_message::Update::SimpleUpdate(proto::SimpleChatUpdate {
                type_: proto::simple_chat_update::Type::JOINED_SIGNAL.into(),
                ..Default::default()
            })),
            ..Default::default()
        });
    } => Ok(()); "directionless_update")]
    #[test_case(|x| {
        x.set_updateMessage(proto::ChatUpdateMessage {
            update: Some(proto::chat_update_message::Update::SimpleUpdate(proto::SimpleChatUpdate {
                type_: proto::simple_chat_update::Type::JOINED_SIGNAL.into(),
                ..Default::default()
            })),
            ..Default::default()
        });
    } => Err(ChatItemError::UpdateMessageShouldBeDirectionless); "update_with_direction")]
    #[test_case(|x| x.revisions.push(proto::ChatItem::test_data()) => Ok(()); "revision")]
    #[test_case(|x| {
        x.revisions.push(proto::ChatItem {
            item: Some(proto::chat_item::Item::RemoteDeletedMessage(Default::default())),
            ..proto::ChatItem::test_data()
        })
    } => Err(ChatItemError::RevisionWithMismatchedMessageType(ChatItemMessageDiscriminants::Standard, ChatItemMessageDiscriminants::RemoteDeleted)); "revision not StandardMessage")]
    #[test_case(|x| {
        x.item = Some(proto::chat_item::Item::RemoteDeletedMessage(Default::default()));
        x.revisions.push(proto::ChatItem::test_data());
    } => Err(ChatItemError::NonStandardMessageHasRevisions); "revision not attached to StandardMessage")]
    #[test_case(|x| {
        x.revisions.push(proto::ChatItem {
            authorId: 0,
            ..proto::ChatItem::test_data()
        })
    } => Err(ChatItemError::RevisionWithMismatchedAuthor(TestContext::CONTACT_ID, RecipientId(0))); "revision mismatched author")]
    #[test_case(|x| {
        x.revisions.push(proto::ChatItem {
            directionalDetails: Some(proto::chat_item::DirectionlessMessageDetails::default().into()),
            item: Some(proto::chat_item::Item::UpdateMessage(proto::ChatUpdateMessage {
                update: Some(proto::chat_update_message::Update::SimpleUpdate(proto::SimpleChatUpdate {
                    type_: proto::simple_chat_update::Type::JOINED_SIGNAL.into(),
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..proto::ChatItem::test_data()
        })
    } => Err(ChatItemError::RevisionWithMismatchedDirection(DirectionDiscriminants::Incoming, DirectionDiscriminants::Directionless)); "revision mismatched direction")]
    #[test_case(|x| {
        x.revisions.push(proto::ChatItem {
            revisions: vec![proto::ChatItem::test_data()],
            ..proto::ChatItem::test_data()
        })
    } => Err(ChatItemError::RevisionContainsRevisions); "revision recursion")]
    #[test_case(|x| {
        *x.mut_directStoryReplyMessage() = proto::DirectStoryReplyMessage::test_data();
        x.revisions.push(proto::ChatItem {
            item: Some(proto::chat_item::Item::DirectStoryReplyMessage(proto::DirectStoryReplyMessage::test_data())),
            ..proto::ChatItem::test_data()
        });
    } => Ok(()); "DirectStoryReplyMessages can have revisions too")]
    #[test_case(|x| {
        *x.mut_directStoryReplyMessage() = proto::DirectStoryReplyMessage::test_data();
        x.revisions.push(proto::ChatItem::test_data());
    } => Err(ChatItemError::RevisionWithMismatchedMessageType(ChatItemMessageDiscriminants::DirectStoryReply, ChatItemMessageDiscriminants::Standard)); "DirectStoryReplyMessage with StandardMessage revision")]
    #[test_case(
        |x| x.dateSent = MillisecondsSinceEpoch::FAR_FUTURE.0 =>
        Err(ChatItemError::InvalidTimestamp(TimestampError("ChatItem.dateSent", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid dateSent"
    )]
    #[test_case(
        |x| x.expireStartDate = Some(MillisecondsSinceEpoch::FAR_FUTURE.0) =>
        Err(ChatItemError::InvalidTimestamp(TimestampError("ChatItem.expireStartDate", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid expireStartDate"
    )]
    #[test_case(
        |x| x.mut_incoming().dateServerSent = Some(MillisecondsSinceEpoch::FAR_FUTURE.0) =>
        Err(ChatItemError::InvalidTimestamp(TimestampError("DirectionalDetails.dateServerSent", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid dateServerSent"
    )]
    #[test_case(
        |x| x.mut_incoming().dateReceived = MillisecondsSinceEpoch::FAR_FUTURE.0 =>
        Err(ChatItemError::InvalidTimestamp(TimestampError("DirectionalDetails.dateReceived", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid dateReceived"
    )]
    #[test_case(|x| {
        x.authorId = TestContext::SELF_ID.0;
        x.directionalDetails = Some(proto::chat_item::OutgoingMessageDetails::test_data().into());
        x.mut_outgoing().sendStatus[0].timestamp = MillisecondsSinceEpoch::FAR_FUTURE.0;
    } => Err(ChatItemError::Outgoing(OutgoingSendError::InvalidTimestamp(TestContext::SELF_ID, TimestampError("SendStatus.timestamp", MillisecondsSinceEpoch::FAR_FUTURE.0)))); "invalid SendStatus timestamp")]
    fn chat_item(modifier: fn(&mut proto::ChatItem)) -> Result<(), ChatItemError> {
        let mut message = proto::ChatItem::test_data();
        modifier(&mut message);

        message
            .try_into_with(&TestContext::default())
            .map(|_: ChatItemData<Store>| ())
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
            media_root_backup_key: libsignal_account_keys::BackupKey(
                [0; libsignal_account_keys::BACKUP_KEY_LEN],
            ),
            version: 0,
            current_app_version: "".into(),
            first_app_version: "".into(),
        };

        let mut item = proto::ChatItem::test_data();

        item.expireStartDate = Some(
            received_at
                .into_inner()
                .duration_since(UNIX_EPOCH)
                .expect("valid")
                .as_millis()
                .try_into()
                .unwrap(),
        );
        item.expiresInMs = Some(until_expiration_ms);

        let result = ChatItemData::<Store>::try_from_with(item, &TestContext(meta))
            .map(|_| ())
            .map_err(|e| assert_matches!(e, ChatItemError::InvalidExpiration(e) => e).to_string());
        assert_eq!(result, expected.map_err(ToString::to_string));
    }

    #[test]
    fn expiration_start_without_duration() {
        let mut item = proto::ChatItem::test_data();
        assert!(item.expireStartDate.is_some());
        item.expiresInMs = None;

        assert_matches!(
            ChatItemData::<Store>::try_from_with(item, &TestContext::default()),
            Err(ChatItemError::ExpirationMismatch)
        );
    }

    #[test]
    fn expiration_duration_without_start() {
        let mut item = proto::ChatItem::test_data();
        assert!(item.expiresInMs.is_some());
        item.expireStartDate = None;

        // This one is okay, it's an expiring message that hasn't been viewed yet.
        assert_matches!(
            ChatItemData::<Store>::try_from_with(item.clone(), &TestContext::default()),
            Ok(_)
        );

        // But not once it's been viewed.
        let incoming = assert_matches!(
            &mut item.directionalDetails,
            Some(proto::chat_item::DirectionalDetails::Incoming(incoming)) => incoming,
            "ChatItem::test_data is an unread incoming message"
        );
        incoming.read = true;
        assert_matches!(
            ChatItemData::<Store>::try_from_with(item.clone(), &TestContext::default()),
            Err(ChatItemError::ExpirationNotStarted)
        );

        // And if it's outgoing, it's okay as long as a recipient is Pending...
        item.authorId = TestContext::SELF_ID.0;
        item.directionalDetails =
            Some(proto::chat_item::OutgoingMessageDetails::test_data().into());
        assert_matches!(
            ChatItemData::<Store>::try_from_with(item.clone(), &TestContext::default()),
            Ok(_)
        );

        // ...but not if sent.
        let outgoing = assert_matches!(
            &mut item.directionalDetails,
            Some(proto::chat_item::DirectionalDetails::Outgoing(outgoing)) => outgoing,
            "just set to an Outgoing message"
        );
        assert!(
            outgoing.sendStatus[0].has_pending(),
            "OutgoingMessageDetails::test_data is Pending by default"
        );
        outgoing.sendStatus[0].set_sent(proto::send_status::Sent::default());
        assert_matches!(
            ChatItemData::<Store>::try_from_with(item, &TestContext::default()),
            Err(ChatItemError::ExpirationNotStarted)
        );
    }

    #[test]
    fn outgoing_sends_are_sorted_when_serialized() {
        let send1 = OutgoingSend {
            recipient: RecipientId(1),
            status: DeliveryStatus::Pending,
            last_status_update: Timestamp::test_value(),
        };
        let send2 = OutgoingSend {
            recipient: RecipientId(2),
            status: DeliveryStatus::Sent {
                sealed_sender: true,
            },
            last_status_update: Timestamp::test_value(),
        };

        let message1 = Direction::Outgoing(vec![send1.clone(), send2.clone()].into());
        let message2 = Direction::Outgoing(vec![send2, send1].into());

        assert_eq!(
            serde_json::to_string_pretty(&message1).expect("valid"),
            serde_json::to_string_pretty(&message2).expect("valid"),
        );
    }

    #[test_case(
        TestContext::CONTACT_ID,
        |_| () =>
        Ok(());
        "1:1 message in correct chat"
    )]
    #[test_case(
        TestContext::GROUP_ID,
        |_| () =>
        Ok(());
        "1:1 message in group chat"
    )]
    #[test_case(
        TestContext::E164_ONLY_ID,
        |_| () =>
        Err(ChatItemError::MessageFromContactInWrongIndividualChat);
        "1:1 message in wrong 1:1 chat"
    )]
    #[test_case(
        TestContext::SELF_ID,
        |_| () =>
        Err(ChatItemError::MessageFromContactInNoteToSelf);
        "1:1 message in Note to Self"
    )]
    #[test_case(
        TestContext::RELEASE_NOTES_ID,
        |_| () =>
        Err(ChatItemError::MessageFromContactInReleaseNotes);
        "1:1 message in Release Notes"
    )]
    #[test_case(
        TestContext::RELEASE_NOTES_ID,
        |x| x.authorId = TestContext::RELEASE_NOTES_ID.0 =>
        Ok(());
        "release note in Release Notes"
    )]
    #[test_case(
        TestContext::CONTACT_ID,
        |x| x.authorId = TestContext::RELEASE_NOTES_ID.0 =>
        Err(ChatItemError::ReleaseNoteMessageNotInReleaseNoteChat(DestinationKind::Contact));
        "release note in 1:1 chat"
    )]
    #[test_case(
        TestContext::CONTACT_ID,
        |x| x.item = Some(proto::chat_item::Item::PaymentNotification(proto::PaymentNotification::test_data())) =>
        Ok(());
        "payment notification in 1:1 chat"
    )]
    #[test_case(
        TestContext::GROUP_ID,
        |x| x.item = Some(proto::chat_item::Item::PaymentNotification(proto::PaymentNotification::test_data())) =>
        Err(ChatItemError::PaymentNotificationNotInContactThread(DestinationKind::Group));
        "payment notification in group chat"
    )]
    #[test_case(
        TestContext::GROUP_ID,
        |x| x.item = Some(proto::chat_item::Item::DirectStoryReplyMessage(proto::DirectStoryReplyMessage::test_data())) =>
        Err(ChatItemError::DirectStoryReplyNotInContactThread(DestinationKind::Group));
        "direct story reply in group chat"
    )]
    fn validate_chat_recipient(
        recipient_id: RecipientId,
        modifier: fn(&mut proto::ChatItem),
    ) -> Result<(), ChatItemError> {
        let context = TestContext::default();
        let mut message = proto::ChatItem::test_data();
        modifier(&mut message);

        let item: ChatItemData<Store> =
            message.try_into_with(&context).expect("valid in isolation");
        let (minimal_data, full_data) = context.lookup_pair(&recipient_id).expect("present");
        item.validate_chat_recipient(full_data, &minimal_data.try_into().unwrap())
    }
}
