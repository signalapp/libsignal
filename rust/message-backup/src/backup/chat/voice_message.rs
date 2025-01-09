// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
use derive_where::derive_where;

use crate::backup::chat::quote::{Quote, QuoteError};
use crate::backup::chat::{ReactionError, ReactionSet};
use crate::backup::file::{MessageAttachment, MessageAttachmentError};
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::MinimalRecipientData;
use crate::backup::serialize::SerializeOrder;
use crate::backup::time::ReportUnusualTimestamp;
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of a voice message [`proto::StandardMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq + SerializeOrder))]
pub struct VoiceMessage<Recipient> {
    pub quote: Option<Quote<Recipient>>,
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub reactions: ReactionSet<Recipient>,
    pub attachment: Box<MessageAttachment>,
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum VoiceMessageError {
    /// attachment: {0}
    Attachment(#[from] MessageAttachmentError),
    /// has unexpected field {0}
    UnexpectedField(&'static str),
    /// has {0} attachments
    WrongAttachmentsCount(usize),
    /// attachment should be a VOICE_MESSAGE, but was {0:?}
    WrongAttachmentType(proto::message_attachment::Flag),
    /// invalid quote: {0}
    Quote(#[from] QuoteError),
    /// invalid reaction: {0}
    Reaction(#[from] ReactionError),
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryFromWith<proto::StandardMessage, C> for VoiceMessage<R>
{
    type Error = VoiceMessageError;

    fn try_from_with(item: proto::StandardMessage, context: &C) -> Result<Self, Self::Error> {
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

        let attachment: MessageAttachment = attachment.try_into_with(context)?;

        if attachment.flag != proto::message_attachment::Flag::VOICE_MESSAGE {
            return Err(VoiceMessageError::WrongAttachmentType(attachment.flag));
        }

        let quote = quote
            .into_option()
            .map(|q| q.try_into_with(context))
            .transpose()?;

        let reactions = reactions.try_into_with(context)?;

        Ok(Self {
            reactions,
            quote,
            attachment: Box::new(attachment),
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;
    use crate::backup::chat::Reaction;
    use crate::backup::recipient::FullRecipientData;
    use crate::backup::testutil::TestContext;

    #[test]
    fn valid_voice_message() {
        assert_eq!(
            proto::StandardMessage::test_voice_message_data()
                .try_into_with(&TestContext::default()),
            Ok(VoiceMessage {
                quote: Some(Quote::from_proto_test_data()),
                reactions: ReactionSet::from_iter([Reaction::from_proto_test_data()]),
                attachment: Box::new(MessageAttachment::from_proto_voice_message_data()),
                _limit_construction_to_module: ()
            })
        )
    }

    #[test_case(|x| x.reactions.clear() => Ok(()); "no reactions")]
    #[test_case(|x| x.reactions.push(proto::Reaction::default()) => Err(VoiceMessageError::Reaction(ReactionError::EmptyEmoji)); "invalid reaction")]
    #[test_case(|x| x.quote = None.into() => Ok(()); "no quote")]
    #[test_case(|x| x.attachments.clear() => Err(VoiceMessageError::WrongAttachmentsCount(0)); "no attachments")]
    #[test_case(|x| x.attachments.push(proto::MessageAttachment::default()) => Err(VoiceMessageError::WrongAttachmentsCount(2)); "extra attachment")]
    fn voice_message(modifier: fn(&mut proto::StandardMessage)) -> Result<(), VoiceMessageError> {
        let mut message = proto::StandardMessage::test_voice_message_data();
        modifier(&mut message);

        message
            .try_into_with(&TestContext::default())
            .map(|_: VoiceMessage<FullRecipientData>| ())
    }
}
