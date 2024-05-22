//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complains about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use std::num::{NonZeroU32, NonZeroU64};

use derive_where::derive_where;
use libsignal_protocol::Aci;
use protobuf::EnumOrUnknown;

use crate::backup::call::{GroupCall, IndividualCall};
use crate::backup::file::{VoiceMessageAttachment, VoiceMessageAttachmentError};
use crate::backup::frame::RecipientId;
use crate::backup::method::{Contains, Lookup, Method, Store};
use crate::backup::sticker::{MessageSticker, MessageStickerError};
use crate::backup::time::{Duration, Timestamp};
use crate::backup::{uuid_bytes_to_aci, BackupMeta, CallError, TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

mod group;

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ChatError {
    /// multiple records with the same ID
    DuplicateId,
    /// no record for {0:?}
    NoRecipient(RecipientId),
    /// chat item: {0}
    ChatItem(#[from] ChatItemError),
    /// {0:?} already appeared for {1:?}
    DuplicatePinnedOrder(PinOrder, RecipientId),
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
    /// quote: {0}
    Quote(#[from] QuoteError),
    /// link preview: {0}
    Link(#[from] LinkPreviewError),
    /// reaction: {0}
    Reaction(#[from] ReactionError),
    /// ChatUpdateMessage.update is a oneof but is empty
    UpdateIsEmpty,
    /// call error: {0}
    Call(#[from] CallError),
    /// GroupChange has no changes.
    GroupChangeIsEmpty,
    /// for GroupUpdate change {0}, Update.update is a oneof but is empty
    GroupChangeUpdateIsEmpty(usize),
    /// group update: {0}
    GroupUpdate(#[from] group::GroupUpdateError),
    /// StickerMessage has no sticker
    StickerMessageMissingSticker,
    /// sticker message: {0}
    StickerMessage(#[from] MessageStickerError),
    /// ChatItem.directionalDetails is a oneof but is empty
    NoDirection,
    /// outgoing message {0}
    Outgoing(#[from] OutgoingSendError),
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
}

#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub struct InvalidExpiration {
    backup_time: Timestamp,
    expires_at: Timestamp,
}

/// Validated version of [`proto::Chat`].
#[derive_where(Debug)]
#[cfg_attr(test, derive_where(PartialEq; M::List<ChatItemData>: PartialEq))]
pub struct ChatData<M: Method = Store> {
    pub recipient: RecipientId,
    pub(super) items: M::List<ChatItemData>,
    pub expiration_timer: Option<Duration>,
    pub mute_until: Option<Timestamp>,
    pub pinned_order: Option<PinOrder>,
    pub dont_notify_for_mentions_if_muted: bool,
    pub marked_unread: bool,
    pub archived: bool,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct PinOrder(NonZeroU32);

/// Validated version of [`proto::ChatItem`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ChatItemData {
    pub author: RecipientId,
    pub message: ChatItemMessage,
    pub revisions: Vec<ChatItemData>,
    pub direction: Direction,
    pub expire_start: Option<Timestamp>,
    pub expires_in: Option<Duration>,
    pub sent_at: Timestamp,
    pub sms: bool,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::chat_item::Item`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
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
    pub text: Option<MessageText>,
    pub quote: Option<Quote>,
    pub reactions: Vec<Reaction>,
    pub link_previews: Vec<LinkPreview>,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::Text`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MessageText {
    pub text: String,
    pub ranges: Vec<TextRange>,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct TextRange {
    pub start: Option<u32>,
    pub length: Option<u32>,
    pub effect: TextEffect,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum TextEffect {
    MentionAci(Aci),
    Style(proto::body_range::Style),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum TextError {
    /// mention had invalid ACI
    MentionInvalidAci,
    /// BodyRange.associatedValue is a oneof but has no value
    NoAssociatedValueForBodyRange,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct LinkPreview {
    pub url: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub date: Option<Timestamp>,
}

#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum LinkPreviewError {}

/// Validated version of [`proto::ContactMessage`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ContactMessage {
    pub contacts: Vec<ContactAttachment>,
    pub reactions: Vec<Reaction>,
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ContactAttachmentError {
    /// {0} type is unknown
    UnknownType(&'static str),
}

/// Validated version of a voice message [`proto::StandardMessage`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct VoiceMessage {
    pub quote: Option<Quote>,
    pub reactions: Vec<Reaction>,
    pub attachment: VoiceMessageAttachment,
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum VoiceMessageError {
    /// attachment: {0}
    Attachment(#[from] VoiceMessageAttachmentError),
    /// has unexpected field {0}
    UnexpectedField(&'static str),
    /// has {0} attachments
    WrongAttachmentsCount(usize),
    /// invalid quote: {0}
    Quote(#[from] QuoteError),
    /// invalid reaction: {0}
    Reaction(#[from] ReactionError),
}

/// Validated version of [`proto::StickerMessage`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct StickerMessage {
    pub reactions: Vec<Reaction>,
    pub sticker: MessageSticker,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::chat_update_message::Update`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum UpdateMessage {
    Simple(SimpleChatUpdate),
    GroupChange {
        updates: Vec<group::GroupChatUpdate>,
    },
    ExpirationTimerChange {
        expires_in: Duration,
    },
    ProfileChange {
        previous: String,
        new: String,
    },
    ThreadMerge,
    SessionSwitchover,
    IndividualCall(IndividualCall),
    GroupCall(GroupCall),
}

/// Validated version of [`proto::simple_chat_update::Type`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum SimpleChatUpdate {
    JoinedSignal,
    IdentityUpdate,
    IdentityVerified,
    IdentityDefault,
    ChangeNumber,
    BoostRequest,
    EndSession,
    ChatSessionRefresh,
    BadDecrypt,
    PaymentsActivated,
    PaymentActivationRequest,
}

/// Validated version of [`proto::ContactAttachment`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ContactAttachment {
    pub name: Option<proto::contact_attachment::Name>,
    pub number: Vec<proto::contact_attachment::Phone>,
    pub email: Vec<proto::contact_attachment::Email>,
    pub address: Vec<proto::contact_attachment::PostalAddress>,
    pub organization: Option<String>,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::Reaction`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Reaction {
    pub emoji: String,
    pub sort_order: u64,
    pub author: RecipientId,
    pub sent_timestamp: Timestamp,
    pub received_timestamp: Option<Timestamp>,
    _limit_construction_to_module: (),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ReactionError {
    /// unknown author {0:?}
    AuthorNotFound(RecipientId),
    /// "emoji" is an empty string
    EmptyEmoji,
}

/// Validated version of [`proto::Quote`]
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Quote {
    pub author: RecipientId,
    pub quote_type: QuoteType,
    pub target_sent_timestamp: Option<Timestamp>,
    pub text: Option<MessageText>,
    _limit_construction_to_module: (),
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum QuoteType {
    Normal,
    GiftBadge,
}

#[derive(Debug)]
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

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct OutgoingSend {
    pub recipient: RecipientId,
    pub status: DeliveryStatus,
    pub last_status_update: Timestamp,
    pub network_failure: bool,
    pub identity_key_mismatch: bool,
    pub sealed_sender: bool,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum DeliveryStatus {
    Failed,
    Pending,
    Sent,
    Delivered,
    Read,
    Viewed,
    Skipped,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum OutgoingSendError {
    /// send status has unknown recipient {0:?}
    UnknownRecipient(RecipientId),
    /// send status is unknown
    SendStatusUnknown,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum QuoteError {
    /// has unknown author {0:?}
    AuthorNotFound(RecipientId),
    /// "type" is unknown
    TypeUnknown,
    /// "text" is missing but "bodyRanges" is not empty
    BodyRangesWithoutText,
    /// text error: {0}
    Text(#[from] TextError),
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

impl<M: Method, C: Contains<RecipientId> + Lookup<PinOrder, RecipientId>>
    TryFromWith<proto::Chat, C> for ChatData<M>
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
            special_fields: _,
            // TODO validate this field
            wallpaper: _,
        } = value;

        let recipient = RecipientId(recipientId);
        if !context.contains(&recipient) {
            return Err(ChatError::NoRecipient(recipient));
        }

        let pinned_order = NonZeroU32::new(pinnedOrder).map(PinOrder);
        if let Some(pinned_order) = pinned_order {
            if let Some(recipient) = context.lookup(&pinned_order) {
                return Err(ChatError::DuplicatePinnedOrder(pinned_order, *recipient));
            }
        };

        let expiration_timer =
            NonZeroU64::new(expirationTimerMs).map(|t| Duration::from_millis(t.get()));
        let mute_until = NonZeroU64::new(muteUntilMs)
            .map(|t| Timestamp::from_millis(t.get(), "Chat.muteUntilMs"));

        Ok(Self {
            recipient,
            expiration_timer,
            mute_until,
            items: Default::default(),
            pinned_order,
            archived,
            marked_unread: markedUnread,
            dont_notify_for_mentions_if_muted: dontNotifyForMentionsIfMuted,
        })
    }
}

impl<R: Contains<RecipientId> + AsRef<BackupMeta>> TryFromWith<proto::ChatItem, R>
    for ChatItemData
{
    type Error = ChatItemError;

    fn try_from_with(value: proto::ChatItem, context: &R) -> Result<Self, ChatItemError> {
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

        if !context.contains(&author) {
            return Err(ChatItemError::AuthorNotFound(author));
        }

        let message = item
            .ok_or(ChatItemError::MissingItem)?
            .try_into_with(context)?;

        let direction = directionalDetails
            .ok_or(ChatItemError::NoDirection)?
            .try_into_with(context)?;

        let revisions: Vec<_> = revisions
            .into_iter()
            .map(|rev| {
                let item: ChatItemData = rev.try_into_with(context)?;
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
                        | UpdateMessage::ThreadMerge
                        | UpdateMessage::SessionSwitchover => (),
                    },
                    ChatItemMessage::Standard(_)
                    | ChatItemMessage::Contact(_)
                    | ChatItemMessage::Voice(_)
                    | ChatItemMessage::Sticker(_)
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
            deliveryStatus,
            lastStatusUpdateTimestamp,
            networkFailure,
            identityKeyMismatch,
            sealedSender,
            special_fields: _,
        } = item;

        let recipient = RecipientId(recipientId);

        if !context.contains(&recipient) {
            return Err(OutgoingSendError::UnknownRecipient(recipient));
        }

        use proto::send_status::Status;
        let status = match deliveryStatus.enum_value_or_default() {
            Status::UNKNOWN => return Err(OutgoingSendError::SendStatusUnknown),
            Status::FAILED => DeliveryStatus::Failed,
            Status::PENDING => DeliveryStatus::Pending,
            Status::SENT => DeliveryStatus::Sent,
            Status::DELIVERED => DeliveryStatus::Delivered,
            Status::READ => DeliveryStatus::Read,
            Status::VIEWED => DeliveryStatus::Viewed,
            Status::SKIPPED => DeliveryStatus::Skipped,
        };

        let last_status_update = Timestamp::from_millis(
            lastStatusUpdateTimestamp,
            "SendStatus.lastStatusUpdateTimestamp",
        );

        Ok(Self {
            recipient,
            status,
            last_status_update,
            network_failure: networkFailure,
            identity_key_mismatch: identityKeyMismatch,
            sealed_sender: sealedSender,
        })
    }
}

impl<R: Contains<RecipientId> + AsRef<BackupMeta>> TryFromWith<proto::chat_item::Item, R>
    for ChatItemMessage
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
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::StandardMessage, R> for StandardMessage {
    type Error = ChatItemError;

    fn try_from_with(item: proto::StandardMessage, context: &R) -> Result<Self, Self::Error> {
        let proto::StandardMessage {
            text,
            quote,
            reactions,
            linkPreview,
            special_fields: _,
            // TODO validate these fields
            attachments: _,
            longText: _,
        } = item;

        let reactions = reactions
            .into_iter()
            .map(|r| r.try_into_with(context))
            .collect::<Result<_, _>>()?;

        let quote = quote
            .into_option()
            .map(|q| q.try_into_with(context))
            .transpose()?;

        let text = text.into_option().map(MessageText::try_from).transpose()?;

        let link_previews = linkPreview
            .into_iter()
            .map(LinkPreview::try_from)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            text,
            quote,
            reactions,
            link_previews,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::ContactMessage, R> for ContactMessage {
    type Error = ChatItemError;

    fn try_from_with(item: proto::ContactMessage, context: &R) -> Result<Self, Self::Error> {
        let proto::ContactMessage {
            reactions,
            contact,
            special_fields: _,
        } = item;

        let reactions = reactions
            .into_iter()
            .map(|r| r.try_into_with(context))
            .collect::<Result<_, _>>()?;

        let contacts = contact
            .into_iter()
            .map(|c| c.try_into())
            .collect::<Result<_, _>>()?;

        Ok(Self {
            contacts,
            reactions,
            _limit_construction_to_module: (),
        })
    }
}

impl TryFrom<proto::ContactAttachment> for ContactAttachment {
    type Error = ContactAttachmentError;

    fn try_from(value: proto::ContactAttachment) -> Result<Self, Self::Error> {
        let proto::ContactAttachment {
            name,
            number,
            email,
            address,
            organization,
            special_fields: _,
            // TODO validate this field
            avatarUrlPath: _,
        } = value;

        if let Some(proto::contact_attachment::Name {
            // Ignore all these fields, but cause a compilation error if
            // they are changed.
            givenName: _,
            familyName: _,
            prefix: _,
            suffix: _,
            middleName: _,
            displayName: _,
            special_fields: _,
        }) = name.as_ref()
        {}

        for proto::contact_attachment::Phone {
            type_,
            value: _,
            label: _,
            special_fields: _,
        } in &number
        {
            if let Some(proto::contact_attachment::phone::Type::UNKNOWN) =
                type_.as_ref().map(EnumOrUnknown::enum_value_or_default)
            {
                return Err(ContactAttachmentError::UnknownType("phone number"));
            }
        }

        for proto::contact_attachment::Email {
            type_,
            value: _,
            label: _,
            special_fields: _,
        } in &email
        {
            if let Some(proto::contact_attachment::email::Type::UNKNOWN) =
                type_.as_ref().map(EnumOrUnknown::enum_value_or_default)
            {
                return Err(ContactAttachmentError::UnknownType("email"));
            }
        }

        for proto::contact_attachment::PostalAddress {
            type_,
            label: _,
            street: _,
            pobox: _,
            neighborhood: _,
            city: _,
            region: _,
            postcode: _,
            country: _,
            special_fields: _,
        } in &address
        {
            if let Some(proto::contact_attachment::postal_address::Type::UNKNOWN) =
                type_.as_ref().map(EnumOrUnknown::enum_value_or_default)
            {
                return Err(ContactAttachmentError::UnknownType("address"));
            }
        }

        Ok(ContactAttachment {
            name: name.into_option(),
            number,
            email,
            address,
            organization,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::StandardMessage, R> for VoiceMessage {
    type Error = VoiceMessageError;

    fn try_from_with(item: proto::StandardMessage, context: &R) -> Result<Self, Self::Error> {
        let proto::StandardMessage {
            quote,
            reactions,
            text,
            attachments,
            linkPreview,
            longText,
            special_fields: _,
        } = item;

        match () {
            _ if text.is_some() => Err("text"),
            _ if longText.is_some() => Err("longText"),
            _ if !linkPreview.is_empty() => Err("linkPreview"),
            _ => Ok(()),
        }
        .map_err(VoiceMessageError::UnexpectedField)?;

        let [attachment] = <[_; 1]>::try_from(attachments)
            .map_err(|attachments| VoiceMessageError::WrongAttachmentsCount(attachments.len()))?;

        let attachment = attachment.try_into()?;

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
            attachment,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::StickerMessage, R> for StickerMessage {
    type Error = ChatItemError;

    fn try_from_with(item: proto::StickerMessage, context: &R) -> Result<Self, Self::Error> {
        let proto::StickerMessage {
            reactions,
            sticker,
            special_fields: _,
        } = item;

        let reactions = reactions
            .into_iter()
            .map(|r| r.try_into_with(context))
            .collect::<Result<_, _>>()?;

        let sticker = sticker
            .into_option()
            .ok_or(ChatItemError::StickerMessageMissingSticker)?
            .try_into()?;

        Ok(Self {
            reactions,
            sticker,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::ChatUpdateMessage, R> for UpdateMessage {
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
            }) => UpdateMessage::Simple({
                use proto::simple_chat_update::Type;
                match type_.enum_value_or_default() {
                    Type::UNKNOWN => return Err(ChatItemError::ChatUpdateUnknown),
                    Type::JOINED_SIGNAL => SimpleChatUpdate::JoinedSignal,
                    Type::IDENTITY_UPDATE => SimpleChatUpdate::IdentityUpdate,
                    Type::IDENTITY_VERIFIED => SimpleChatUpdate::IdentityVerified,
                    Type::IDENTITY_DEFAULT => SimpleChatUpdate::IdentityDefault,
                    Type::CHANGE_NUMBER => SimpleChatUpdate::ChangeNumber,
                    Type::BOOST_REQUEST => SimpleChatUpdate::BoostRequest,
                    Type::END_SESSION => SimpleChatUpdate::EndSession,
                    Type::CHAT_SESSION_REFRESH => SimpleChatUpdate::ChatSessionRefresh,
                    Type::BAD_DECRYPT => SimpleChatUpdate::BadDecrypt,
                    Type::PAYMENTS_ACTIVATED => SimpleChatUpdate::PaymentsActivated,
                    Type::PAYMENT_ACTIVATION_REQUEST => SimpleChatUpdate::PaymentActivationRequest,
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
                                group::GroupChatUpdate::try_from(update)
                                    .map_err(ChatItemError::from)
                            },
                        )
                        .collect::<Result<_, _>>()?,
                }
            }
            Update::ExpirationTimerChange(proto::ExpirationTimerChatUpdate {
                expiresInMs,
                special_fields: _,
            }) => UpdateMessage::ExpirationTimerChange {
                expires_in: Duration::from_millis(expiresInMs.into()),
            },
            Update::ProfileChange(proto::ProfileChangeChatUpdate {
                previousName,
                newName,
                special_fields: _,
            }) => UpdateMessage::ProfileChange {
                previous: previousName,
                new: newName,
            },
            Update::ThreadMerge(proto::ThreadMergeChatUpdate {
                special_fields: _,
                // TODO validate this field
                previousE164: _,
            }) => UpdateMessage::ThreadMerge,
            Update::SessionSwitchover(proto::SessionSwitchoverChatUpdate {
                special_fields: _,
                // TODO validate this field
                e164: _,
            }) => UpdateMessage::SessionSwitchover,
            Update::IndividualCall(call) => UpdateMessage::IndividualCall(call.try_into()?),
            Update::GroupCall(call) => UpdateMessage::GroupCall(call.try_into_with(context)?),
        })
    }
}

impl TryFrom<proto::Text> for MessageText {
    type Error = TextError;

    fn try_from(value: proto::Text) -> Result<Self, Self::Error> {
        let proto::Text {
            body,
            bodyRanges,
            special_fields: _,
        } = value;

        let ranges = bodyRanges
            .into_iter()
            .map(|range| {
                let proto::BodyRange {
                    start,
                    length,
                    associatedValue,
                    special_fields: _,
                } = range;
                use proto::body_range::AssociatedValue;
                let effect =
                    match associatedValue.ok_or(TextError::NoAssociatedValueForBodyRange)? {
                        AssociatedValue::MentionAci(aci) => TextEffect::MentionAci(
                            uuid_bytes_to_aci(aci).map_err(|_| TextError::MentionInvalidAci)?,
                        ),
                        AssociatedValue::Style(style) => {
                            // All style values are valid
                            TextEffect::Style(style.enum_value_or_default())
                        }
                    };
                Ok(TextRange {
                    start,
                    length,
                    effect,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { text: body, ranges })
    }
}

impl TryFrom<proto::LinkPreview> for LinkPreview {
    type Error = LinkPreviewError;

    fn try_from(value: proto::LinkPreview) -> Result<Self, Self::Error> {
        let proto::LinkPreview {
            url,
            title,
            description,
            date,
            special_fields: _,
            // TODO validate this field
            image: _,
        } = value;
        let date = date.map(|d| Timestamp::from_millis(d, "LinkPreview.date"));

        Ok(Self {
            url,
            title,
            description,
            date,
        })
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::Quote, R> for Quote {
    type Error = QuoteError;

    fn try_from_with(item: proto::Quote, context: &R) -> Result<Self, Self::Error> {
        let proto::Quote {
            authorId,
            type_,
            targetSentTimestamp,
            text,
            bodyRanges,
            // TODO validate these fields
            attachments: _,
            special_fields: _,
        } = item;

        let author = RecipientId(authorId);
        if !context.contains(&author) {
            return Err(QuoteError::AuthorNotFound(author));
        }

        let target_sent_timestamp = targetSentTimestamp
            .map(|timestamp| Timestamp::from_millis(timestamp, "Quote.targetSentTimestamp"));
        let quote_type = match type_.enum_value_or_default() {
            proto::quote::Type::UNKNOWN => return Err(QuoteError::TypeUnknown),
            proto::quote::Type::NORMAL => QuoteType::Normal,
            proto::quote::Type::GIFTBADGE => QuoteType::GiftBadge,
        };

        let text = match text {
            None if !bodyRanges.is_empty() => return Err(QuoteError::BodyRangesWithoutText),
            None => None,
            Some(text) => Some(
                proto::Text {
                    body: text,
                    bodyRanges,
                    special_fields: Default::default(),
                }
                .try_into()?,
            ),
        };
        Ok(Self {
            author,
            quote_type,
            target_sent_timestamp,
            text,
            _limit_construction_to_module: (),
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
    use nonzero_ext::nonzero;
    use protobuf::{EnumOrUnknown, MessageField, SpecialFields};
    use test_case::test_case;

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

    impl proto::StandardMessage {
        pub(crate) fn test_data() -> Self {
            Self {
                text: Some(proto::Text::test_data()).into(),
                reactions: vec![proto::Reaction::test_data()],
                quote: Some(proto::Quote::test_data()).into(),
                ..Default::default()
            }
        }

        pub(crate) fn test_voice_message_data() -> Self {
            Self {
                attachments: vec![proto::MessageAttachment {
                    pointer: Some(proto::FilePointer {
                        locator: Some(proto::file_pointer::Locator::BackupLocator(
                            Default::default(),
                        )),
                        ..Default::default()
                    })
                    .into(),
                    flag: proto::message_attachment::Flag::VOICE_MESSAGE.into(),
                    ..Default::default()
                }],
                longText: None.into(),
                linkPreview: vec![],
                text: None.into(),
                ..Self::test_data()
            }
        }
    }

    impl proto::ContactMessage {
        fn test_data() -> Self {
            Self {
                reactions: vec![proto::Reaction::test_data()],
                contact: vec![proto::ContactAttachment::test_data()],
                ..Default::default()
            }
        }
    }

    impl proto::ContactAttachment {
        fn test_data() -> Self {
            Self {
                ..Default::default()
            }
        }
    }

    impl proto::Reaction {
        fn test_data() -> Self {
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

    const TEST_MESSAGE_TEXT: &str = "test message text";
    impl proto::Quote {
        fn test_data() -> Self {
            let proto::Text {
                body,
                bodyRanges,
                special_fields: _,
            } = proto::Text::test_data();

            Self {
                authorId: proto::Recipient::TEST_ID,
                type_: proto::quote::Type::NORMAL.into(),
                targetSentTimestamp: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                text: Some(body),
                bodyRanges,
                ..Default::default()
            }
        }
    }

    impl proto::StickerMessage {
        fn test_data() -> Self {
            Self {
                reactions: vec![proto::Reaction::test_data()],
                sticker: Some(proto::Sticker::test_data()).into(),
                ..Default::default()
            }
        }
    }

    trait ProtoHasField<T> {
        fn get_field_mut(&mut self) -> &mut T;
    }

    impl ProtoHasField<Vec<proto::Reaction>> for proto::StandardMessage {
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

    impl ProtoHasField<Vec<proto::MessageAttachment>> for proto::StandardMessage {
        fn get_field_mut(&mut self) -> &mut Vec<proto::MessageAttachment> {
            &mut self.attachments
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

    impl ContactAttachment {
        fn from_proto_test_data() -> Self {
            Self {
                name: None,
                number: vec![],
                email: vec![],
                address: vec![],
                organization: None,
                _limit_construction_to_module: (),
            }
        }
    }

    impl StandardMessage {
        fn from_proto_test_data() -> Self {
            Self {
                text: Some(MessageText::from_proto_test_data()),
                reactions: vec![Reaction::from_proto_test_data()],
                quote: Some(Quote {
                    text: Some(MessageText::from_proto_test_data()),
                    author: RecipientId(proto::Recipient::TEST_ID),
                    quote_type: QuoteType::Normal,
                    target_sent_timestamp: Some(Timestamp::test_value()),
                    _limit_construction_to_module: (),
                }),
                link_previews: vec![],
                _limit_construction_to_module: (),
            }
        }
    }

    impl proto::Text {
        fn test_data() -> Self {
            Self {
                body: TEST_MESSAGE_TEXT.to_string(),
                bodyRanges: vec![proto::BodyRange {
                    start: Some(2),
                    length: Some(5),
                    associatedValue: Some(proto::body_range::AssociatedValue::Style(
                        proto::body_range::Style::MONOSPACE.into(),
                    )),
                    special_fields: Default::default(),
                }],
                special_fields: Default::default(),
            }
        }
    }

    impl MessageText {
        fn from_proto_test_data() -> Self {
            Self {
                text: TEST_MESSAGE_TEXT.to_string(),
                ranges: vec![TextRange {
                    start: Some(2),
                    length: Some(5),
                    effect: TextEffect::Style(proto::body_range::Style::MONOSPACE),
                }],
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
                deliveryStatus: proto::send_status::Status::PENDING.into(),
                ..Default::default()
            }
        }
    }

    impl proto::SimpleChatUpdate {
        fn test_data() -> Self {
            Self {
                type_: proto::simple_chat_update::Type::IDENTITY_VERIFIED.into(),
                ..Default::default()
            }
        }
    }

    impl BackupMeta {
        fn test_value() -> Self {
            Self {
                backup_time: Timestamp::test_value(),
                purpose: Purpose::RemoteBackup,
                version: 0,
            }
        }
    }

    struct TestContext(BackupMeta);

    impl Default for TestContext {
        fn default() -> Self {
            Self(BackupMeta::test_value())
        }
    }

    impl Contains<RecipientId> for TestContext {
        fn contains(&self, key: &RecipientId) -> bool {
            key == &RecipientId(proto::Recipient::TEST_ID)
        }
    }

    impl Contains<PinOrder> for TestContext {
        fn contains(&self, key: &PinOrder) -> bool {
            Self::lookup(self, key).is_some()
        }
    }

    impl Lookup<PinOrder, RecipientId> for TestContext {
        fn lookup(&self, key: &PinOrder) -> Option<&RecipientId> {
            (*key == TEST_DUPLICATE_PINNED_ORDER).then_some(&TEST_DUPLICATE_PINNED_ORDER_RECIPIENT)
        }
    }

    impl AsRef<BackupMeta> for TestContext {
        fn as_ref(&self) -> &BackupMeta {
            &self.0
        }
    }

    const TEST_DUPLICATE_PINNED_ORDER: PinOrder = PinOrder(nonzero!(183324u32));
    const TEST_DUPLICATE_PINNED_ORDER_RECIPIENT: RecipientId = RecipientId(183324);

    #[test]
    fn valid_chat() {
        assert_eq!(
            proto::Chat::test_data().try_into_with(&TestContext::default()),
            Ok(ChatData::<Store> {
                recipient: RecipientId(proto::Recipient::TEST_ID),
                items: Vec::default(),
                expiration_timer: None,
                mute_until: None,
                pinned_order: None,
                archived: false,
                marked_unread: false,
                dont_notify_for_mentions_if_muted: false,
            })
        );
    }

    fn duplicate_pinned_order(message: &mut proto::Chat) {
        message.pinnedOrder = TEST_DUPLICATE_PINNED_ORDER.0.get();
    }

    fn with_expiration_timer(chat: &mut proto::Chat) {
        chat.expirationTimerMs = 123456;
    }
    fn with_mute_until(chat: &mut proto::Chat) {
        chat.muteUntilMs = MillisecondsSinceEpoch::TEST_VALUE.0;
    }

    #[test_case(with_expiration_timer, Ok(()))]
    #[test_case(with_mute_until, Ok(()))]
    #[test_case(
        duplicate_pinned_order,
        Err(ChatError::DuplicatePinnedOrder(
            TEST_DUPLICATE_PINNED_ORDER,
            TEST_DUPLICATE_PINNED_ORDER_RECIPIENT
        ))
    )]
    fn chat(modifier: fn(&mut proto::Chat), expected: Result<(), ChatError>) {
        let mut chat = proto::Chat::test_data();
        modifier(&mut chat);
        assert_eq!(
            chat.try_into_with(&TestContext::default())
                .map(|_: ChatData| ()),
            expected
        );
    }

    #[test]
    fn valid_chat_item() {
        assert_eq!(
            proto::ChatItem::test_data().try_into_with(&TestContext::default()),
            Ok(ChatItemData {
                author: RecipientId(proto::Recipient::TEST_ID),
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
                _limit_construction_to_module: (),
            })
        )
    }

    fn unknown_author(message: &mut proto::ChatItem) {
        message.authorId = 0xffff;
    }
    fn no_direction(message: &mut proto::ChatItem) {
        message.directionalDetails = None;
    }
    fn outgoing_valid(message: &mut proto::ChatItem) {
        message.directionalDetails =
            Some(proto::chat_item::OutgoingMessageDetails::test_data().into());
    }
    fn outgoing_send_status_unknown(message: &mut proto::ChatItem) {
        message.directionalDetails = Some(
            proto::chat_item::OutgoingMessageDetails {
                sendStatus: vec![proto::SendStatus {
                    deliveryStatus: EnumOrUnknown::default(),
                    ..proto::SendStatus::test_data()
                }],
                ..proto::chat_item::OutgoingMessageDetails::test_data()
            }
            .into(),
        );
    }
    fn outgoing_unknown_recipient(message: &mut proto::ChatItem) {
        message.directionalDetails = Some(
            proto::chat_item::OutgoingMessageDetails {
                sendStatus: vec![proto::SendStatus {
                    recipientId: 0xffff,
                    ..proto::SendStatus::test_data()
                }],
                ..proto::chat_item::OutgoingMessageDetails::test_data()
            }
            .into(),
        );
    }

    #[test_case(
        unknown_author,
        Err(ChatItemError::AuthorNotFound(RecipientId(0xffff)))
    )]
    #[test_case(no_direction, Err(ChatItemError::NoDirection))]
    #[test_case(outgoing_valid, Ok(()))]
    #[test_case(
        outgoing_send_status_unknown,
        Err(ChatItemError::Outgoing(OutgoingSendError::SendStatusUnknown))
    )]
    #[test_case(
        outgoing_unknown_recipient,
        Err(ChatItemError::Outgoing(OutgoingSendError::UnknownRecipient(RecipientId(0xffff))))
    )]
    fn chat_item(modifier: fn(&mut proto::ChatItem), expected: Result<(), ChatItemError>) {
        let mut message = proto::ChatItem::test_data();
        modifier(&mut message);

        let result = message
            .try_into_with(&TestContext::default())
            .map(|_: ChatItemData| ());
        assert_eq!(result, expected);
    }

    #[test]
    fn valid_standard_message() {
        assert_eq!(
            proto::StandardMessage::test_data().try_into_with(&TestContext::default()),
            Ok(StandardMessage::from_proto_test_data())
        );
    }

    #[test]
    fn valid_text() {
        assert_eq!(
            proto::Text::test_data().try_into(),
            Ok(MessageText::from_proto_test_data())
        );
    }

    #[test]
    fn valid_contact_message() {
        assert_eq!(
            proto::ContactMessage::test_data().try_into_with(&TestContext::default()),
            Ok(ContactMessage {
                contacts: vec![ContactAttachment::from_proto_test_data()],
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

    fn no_attachments(input: &mut impl ProtoHasField<Vec<proto::MessageAttachment>>) {
        input.get_field_mut().clear();
    }

    fn extra_attachment(input: &mut impl ProtoHasField<Vec<proto::MessageAttachment>>) {
        input
            .get_field_mut()
            .push(proto::MessageAttachment::default());
    }

    #[test_case(no_reactions, Ok(()))]
    #[test_case(
        invalid_reaction,
        Err(ChatItemError::Reaction(ReactionError::EmptyEmoji))
    )]
    fn contact_message(
        modifier: fn(&mut proto::ContactMessage),
        expected: Result<(), ChatItemError>,
    ) {
        let mut message = proto::ContactMessage::test_data();
        modifier(&mut message);

        let result = message
            .try_into_with(&TestContext::default())
            .map(|_: ContactMessage| ());
        assert_eq!(result, expected);
    }

    #[test]
    fn valid_voice_message() {
        assert_eq!(
            proto::StandardMessage::test_voice_message_data()
                .try_into_with(&TestContext::default()),
            Ok(VoiceMessage {
                quote: Some(Quote {
                    text: Some(MessageText::from_proto_test_data()),
                    author: RecipientId(proto::Recipient::TEST_ID),
                    quote_type: QuoteType::Normal,
                    target_sent_timestamp: Some(Timestamp::test_value()),
                    _limit_construction_to_module: ()
                }),
                reactions: vec![Reaction::from_proto_test_data()],
                attachment: VoiceMessageAttachment::default(),
                _limit_construction_to_module: ()
            })
        )
    }

    #[test_case(no_reactions, Ok(()))]
    #[test_case(
        invalid_reaction,
        Err(VoiceMessageError::Reaction(ReactionError::EmptyEmoji))
    )]
    #[test_case(no_quote, Ok(()))]
    #[test_case(no_attachments, Err(VoiceMessageError::WrongAttachmentsCount(0)))]
    #[test_case(extra_attachment, Err(VoiceMessageError::WrongAttachmentsCount(2)))]
    fn voice_message(
        modifier: fn(&mut proto::StandardMessage),
        expected: Result<(), VoiceMessageError>,
    ) {
        let mut message = proto::StandardMessage::test_voice_message_data();
        modifier(&mut message);

        let result = message
            .try_into_with(&TestContext::default())
            .map(|_: VoiceMessage| ());
        assert_eq!(result, expected);
    }

    #[test_case(no_reactions, Ok(()))]
    #[test_case(
        invalid_reaction,
        Err(ChatItemError::Reaction(ReactionError::EmptyEmoji))
    )]
    fn sticker_message(
        modifier: fn(&mut proto::StickerMessage),
        expected: Result<(), ChatItemError>,
    ) {
        let mut message = proto::StickerMessage::test_data();
        modifier(&mut message);

        let result = message
            .try_into_with(&TestContext::default())
            .map(|_: StickerMessage| ());
        assert_eq!(result, expected);
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
    #[test_case(proto::ProfileChangeChatUpdate::default(), Ok(()))]
    #[test_case(proto::ThreadMergeChatUpdate::default(), Ok(()))]
    #[test_case(proto::SessionSwitchoverChatUpdate::default(), Ok(()))]
    fn chat_update_message_item(
        update: impl Into<proto::chat_update_message::Update>,
        expected: Result<(), ChatItemError>,
    ) {
        let result = proto::ChatUpdateMessage {
            update: Some(update.into()),
            ..Default::default()
        }
        .try_into_with(&TestContext::default())
        .map(|_: UpdateMessage| ());

        assert_eq!(result, expected)
    }

    use proto::chat_update_message::Update as ChatUpdateProto;
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
            .map(|_: UpdateMessage| ()),
            expected.map_err(ChatItemError::Call)
        );
    }

    #[test]
    fn valid_reaction() {
        assert_eq!(
            proto::Reaction::test_data().try_into_with(&TestContext::default()),
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

        let result = reaction
            .try_into_with(&TestContext::default())
            .map(|_: Reaction| ());
        assert_eq!(result, expected);
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

        let result = ChatItemData::try_from_with(item, &TestContext(meta))
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
            ChatItemData::try_from_with(item, &TestContext::default()),
            Err(ChatItemError::ExpirationMismatch)
        );
    }
}
