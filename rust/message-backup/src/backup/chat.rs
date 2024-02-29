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
use protobuf::EnumOrUnknown;

use crate::backup::file::{VoiceMessageAttachment, VoiceMessageAttachmentError};
use crate::backup::frame::{CallId, RecipientId};
use crate::backup::method::{Contains, Method, Store};
use crate::backup::sticker::{MessageSticker, MessageStickerError};
use crate::backup::time::{Duration, Timestamp};
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

mod group;

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum ChatError {
    /// multiple records with the same ID
    DuplicateId,
    /// no record for {0:?}
    NoRecipient(RecipientId),
    /// chat item: {0}
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
    /// quote: {0}
    Quote(#[from] QuoteError),
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
    /// GroupChange has no changes.
    GroupChangeIsEmpty,
    /// GroupUpdate change {0} has no update value.
    GroupChangeUpdateIsEmpty(usize),
    /// group update: {0}
    GroupUpdate(#[from] group::GroupUpdateError),
    /// StickerMessage has no sticker
    StickerMessageMissingSticker,
    /// sticker message: {0}
    StickerMessage(#[from] MessageStickerError),
    /// directionalDetails is empty
    NoDirection,
    /// outgoing message {0}
    Outgoing(#[from] OutgoingSendError),
    /// contact message: {0}
    ContactAttachment(#[from] ContactAttachmentError),
    /// chat update type is UNKNOWN
    ChatUpdateUnknown,
    /// voice message: {0}
    VoiceMessage(#[from] VoiceMessageError),
}

/// Validated version of [`proto::Chat`].
#[derive_where(Debug)]
pub struct ChatData<M: Method = Store> {
    pub(super) items: M::List<ChatItemData>,
    pub expiration_timer: Duration,
    pub mute_until: Timestamp,
}

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
    pub quote: Option<Quote>,
    pub reactions: Vec<Reaction>,
    _limit_construction_to_module: (),
}

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
    Call(CallChatUpdate),
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
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::call_chat_update::Call`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum CallChatUpdate {
    Call(CallId),
    CallMessage,
    GroupCall {
        started_call_aci: Option<Aci>,
        in_call_acis: Vec<Aci>,
        started_call_at: Timestamp,
    },
}

/// Validated version of [`proto::Reaction`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Reaction {
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
}

/// Validated version of [`proto::Quote`]
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Quote {
    pub author: RecipientId,
    pub quote_type: QuoteType,
    pub target_sent_timestamp: Option<Timestamp>,
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
}

impl<M: Method, C: Contains<RecipientId>> TryFromWith<proto::Chat, C> for ChatData<M> {
    type Error = ChatError;

    fn try_from_with(value: proto::Chat, context: &C) -> Result<Self, Self::Error> {
        let proto::Chat {
            id: _,
            recipientId,
            expirationTimerMs,
            muteUntilMs,
            // TODO validate these fields
            archived: _,
            pinnedOrder: _,
            markedUnread: _,
            dontNotifyForMentionsIfMuted: _,
            wallpaper: _,
            special_fields: _,
        } = value;

        let recipient_id = RecipientId(recipientId);

        if !context.contains(&recipient_id) {
            return Err(ChatError::NoRecipient(recipient_id));
        }

        let expiration_timer = Duration::from_millis(expirationTimerMs);
        let mute_until = Timestamp::from_millis(muteUntilMs, "Chat.muteUntilMs");

        Ok(Self {
            expiration_timer,
            mute_until,
            items: Default::default(),
        })
    }
}

impl<R: Contains<RecipientId> + Contains<CallId>> TryFromWith<proto::ChatItem, R> for ChatItemData {
    type Error = ChatItemError;

    fn try_from_with(value: proto::ChatItem, recipients: &R) -> Result<Self, ChatItemError> {
        let proto::ChatItem {
            chatId: _,
            authorId,
            item,
            directionalDetails,
            revisions,
            expireStartDate,
            expiresInMs,
            dateSent,

            // TODO validate these fields
            sealedSender: _,
            sms: _,
            special_fields: _,
        } = value;

        let author = RecipientId(authorId);

        if !recipients.contains(&author) {
            return Err(ChatItemError::AuthorNotFound(author));
        }

        let message =
            ChatItemMessage::try_from_with(item.ok_or(ChatItemError::MissingItem)?, recipients)?;

        let direction = directionalDetails
            .ok_or(ChatItemError::NoDirection)?
            .try_into_with(recipients)?;

        let revisions = revisions
            .into_iter()
            .map(|rev| rev.try_into_with(recipients))
            .collect::<Result<_, _>>()?;

        let sent_at = Timestamp::from_millis(dateSent, "ChatItem.dateSent");
        let expire_start =
            expireStartDate.map(|date| Timestamp::from_millis(date, "ChatItem.expireStartDate"));
        let expires_in = expiresInMs.map(Duration::from_millis);

        Ok(Self {
            author,
            message,
            revisions,
            direction,
            sent_at,
            expire_start,
            expires_in,
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
                // TODO validate this field.
                read: _,
            }) => {
                let sent =
                    Timestamp::from_millis(dateServerSent, "DirectionalDetails.dateServerSent");
                let received =
                    Timestamp::from_millis(dateReceived, "DirectionalDetails.dateReceived");
                Ok(Self::Incoming { received, sent })
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
            special_fields: _,
            // TODO validate these fields
            networkFailure: _,
            identityKeyMismatch: _,
            sealedSender: _,
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
            Item::StandardMessage(message) => {
                let is_voice_message = matches!(message.attachments.as_slice(),
                [single_attachment] if
                    single_attachment.flag.enum_value_or_default()
                        == proto::message_attachment::Flag::VOICE_MESSAGE
                );

                if is_voice_message {
                    Self::Voice(message.try_into_with(recipients)?)
                } else {
                    Self::Standard(message.try_into_with(recipients)?)
                }
            }
            Item::ContactMessage(message) => Self::Contact(message.try_into_with(recipients)?),
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
            organization: _,
            special_fields: _,
            // TODO validate this field
            avatarUrlPath: _,
        } = value;

        name.map(
            |proto::contact_attachment::Name {
                 // Ignore all these fields, but cause a compilation error if
                 // they are changed.
                 givenName: _,
                 familyName: _,
                 prefix: _,
                 suffix: _,
                 middleName: _,
                 displayName: _,
                 special_fields: _,
             }| {},
        );

        for proto::contact_attachment::Phone {
            type_,
            value: _,
            label: _,
            special_fields: _,
        } in number
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
        } in email
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
        } in address
        {
            if let Some(proto::contact_attachment::postal_address::Type::UNKNOWN) =
                type_.as_ref().map(EnumOrUnknown::enum_value_or_default)
            {
                return Err(ContactAttachmentError::UnknownType("address"));
            }
        }

        Ok(ContactAttachment {
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
            }) => Self::Simple({
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
                Self::GroupChange {
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
            }) => Self::ExpirationTimerChange {
                expires_in: Duration::from_millis(expiresInMs.into()),
            },
            Update::ProfileChange(proto::ProfileChangeChatUpdate {
                previousName,
                newName,
                special_fields: _,
            }) => Self::ProfileChange {
                previous: previousName,
                new: newName,
            },
            Update::ThreadMerge(proto::ThreadMergeChatUpdate {
                special_fields: _,
                // TODO validate this field
                previousE164: _,
            }) => Self::ThreadMerge,
            Update::SessionSwitchover(proto::SessionSwitchoverChatUpdate {
                special_fields: _,
                // TODO validate this field
                e164: _,
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
                // TODO check "type" field once it gets added upstream.
                Ok(Self::CallMessage)
            }
            Call::GroupCall(group) => {
                let proto::GroupCallChatUpdate {
                    startedCallAci,
                    inCallAcis,
                    startedCallTimestamp,
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

                let started_call_at = Timestamp::from_millis(
                    startedCallTimestamp,
                    "ChatUpdate.Call.startedCallTimestamp",
                );

                Ok(Self::GroupCall {
                    started_call_aci,
                    in_call_acis,
                    started_call_at,
                })
            }
        }
    }
}

impl<R: Contains<RecipientId>> TryFromWith<proto::Quote, R> for Quote {
    type Error = QuoteError;

    fn try_from_with(item: proto::Quote, context: &R) -> Result<Self, Self::Error> {
        let proto::Quote {
            authorId,
            type_,
            targetSentTimestamp,
            // TODO validate these fields
            text: _,
            attachments: _,
            bodyRanges: _,
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
        Ok(Self {
            author,
            quote_type,
            target_sent_timestamp,
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
            // TODO validate these fields
            emoji: _,
            sortOrder: _,
            special_fields: _,
        } = item;

        let author = RecipientId(authorId);
        if !context.contains(&author) {
            return Err(ReactionError::AuthorNotFound(author));
        }

        let sent_timestamp = Timestamp::from_millis(sentTimestamp, "Reaction.sentTimestamp");
        let received_timestamp = receivedTimestamp
            .map(|timestamp| Timestamp::from_millis(timestamp, "Reaction.receivedTimestamp"));

        Ok(Self {
            author,
            sent_timestamp,
            received_timestamp,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use protobuf::{EnumOrUnknown, MessageField, SpecialFields};
    use test_case::test_case;

    use crate::backup::time::testutil::MillisecondsSinceEpoch;

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
                expireStartDate: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                expiresInMs: Some(111),
                dateSent: MillisecondsSinceEpoch::TEST_VALUE.0,
                ..Default::default()
            }
        }
    }

    impl proto::StandardMessage {
        pub(crate) fn test_data() -> Self {
            Self {
                reactions: vec![proto::Reaction::test_data()],
                quote: Some(proto::Quote::test_data()).into(),
                ..Default::default()
            }
        }

        pub(crate) fn test_voice_message_data() -> Self {
            Self {
                attachments: vec![proto::MessageAttachment {
                    pointer: Some(proto::FilePointer::default()).into(),
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
                authorId: proto::Recipient::TEST_ID,
                sentTimestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                receivedTimestamp: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                ..Default::default()
            }
        }
    }

    impl proto::Quote {
        fn test_data() -> Self {
            Self {
                authorId: proto::Recipient::TEST_ID,
                type_: proto::quote::Type::NORMAL.into(),
                targetSentTimestamp: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
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
                _limit_construction_to_module: (),
            }
        }
    }

    impl StandardMessage {
        fn from_proto_test_data() -> Self {
            Self {
                reactions: vec![Reaction::from_proto_test_data()],
                quote: Some(Quote {
                    author: RecipientId(proto::Recipient::TEST_ID),
                    quote_type: QuoteType::Normal,
                    target_sent_timestamp: Some(Timestamp::test_value()),
                    _limit_construction_to_module: (),
                }),
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
    fn valid_chat_item() {
        assert_eq!(
            proto::ChatItem::test_data().try_into_with(&TestContext),
            Ok(ChatItemData {
                author: RecipientId(proto::Recipient::TEST_ID),
                message: ChatItemMessage::Standard(StandardMessage::from_proto_test_data()),
                revisions: vec![],
                direction: Direction::Incoming {
                    received: Timestamp::test_value(),
                    sent: Timestamp::test_value()
                },
                expire_start: Some(Timestamp::test_value()),
                expires_in: Some(Duration::from_millis(111)),
                sent_at: Timestamp::test_value(),
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
            .try_into_with(&TestContext)
            .map(|_: ChatItemData| ());
        assert_eq!(result, expected);
    }

    #[test]
    fn valid_standard_message() {
        assert_eq!(
            proto::StandardMessage::test_data().try_into_with(&TestContext),
            Ok(StandardMessage::from_proto_test_data())
        );
    }

    #[test]
    fn valid_contact_message() {
        assert_eq!(
            proto::ContactMessage::test_data().try_into_with(&TestContext),
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
            proto::StandardMessage::test_voice_message_data().try_into_with(&TestContext),
            Ok(VoiceMessage {
                quote: Some(Quote {
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
        Err(VoiceMessageError::Reaction(ReactionError::AuthorNotFound(RecipientId(0))))
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

    #[test_case(proto::SimpleChatUpdate::test_data(), Ok(()))]
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
                startedCallTimestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
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
