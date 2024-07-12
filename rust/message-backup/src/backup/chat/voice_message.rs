// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::chat::quote::{Quote, QuoteError};
use crate::backup::chat::{Reaction, ReactionError};
use crate::backup::file::{VoiceMessageAttachment, VoiceMessageAttachmentError};
use crate::backup::frame::RecipientId;
use crate::backup::method::Contains;
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of a voice message [`proto::StandardMessage`].
#[derive(Debug, serde::Serialize)]
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

#[cfg(test)]
mod test {
    use test_case::test_case;

    use crate::backup::chat::testutil::{
        extra_attachment, invalid_reaction, no_attachments, no_quote, no_reactions, TestContext,
    };

    use super::*;

    #[test]
    fn valid_voice_message() {
        assert_eq!(
            proto::StandardMessage::test_voice_message_data()
                .try_into_with(&TestContext::default()),
            Ok(VoiceMessage {
                quote: Some(Quote::from_proto_test_data()),
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
}
