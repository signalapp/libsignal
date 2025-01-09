// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
use derive_where::derive_where;

use crate::backup::chat::link::LinkPreview;
use crate::backup::chat::quote::Quote;
use crate::backup::chat::text::MessageText;
use crate::backup::chat::{ChatItemError, ReactionSet};
use crate::backup::file::{FilePointer, MessageAttachment};
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::MinimalRecipientData;
use crate::backup::serialize::SerializeOrder;
use crate::backup::time::ReportUnusualTimestamp;
use crate::backup::{likely_empty, TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of [`proto::StandardMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq + SerializeOrder))]
pub struct StandardMessage<Recipient> {
    pub text: Option<MessageText>,
    pub quote: Option<Box<Quote<Recipient>>>,
    pub attachments: Vec<MessageAttachment>,
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub reactions: ReactionSet<Recipient>,
    pub link_previews: Vec<LinkPreview>,
    pub long_text: Option<Box<FilePointer>>,
    _limit_construction_to_module: (),
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryFromWith<proto::StandardMessage, C> for StandardMessage<R>
{
    type Error = ChatItemError;

    fn try_from_with(item: proto::StandardMessage, context: &C) -> Result<Self, Self::Error> {
        let proto::StandardMessage {
            text,
            quote,
            attachments,
            reactions,
            linkPreview,
            longText,
            special_fields: _,
        } = item;

        let reactions = reactions.try_into_with(context)?;

        let quote = quote
            .into_option()
            .map(|q| q.try_into_with(context))
            .transpose()?;

        let text = match text.into_option() {
            None => None,
            // Fast-path for a message with no body-ranges.
            Some(proto::Text {
                body,
                bodyRanges,
                special_fields: _,
            }) if bodyRanges.is_empty() => Some(MessageText {
                text: body,
                ranges: Default::default(),
            }),
            Some(text) => Some(text.try_into()?),
        };

        let link_previews = likely_empty(linkPreview, |iter| {
            iter.map(|preview| LinkPreview::try_from_with(preview, context))
                .collect::<Result<_, _>>()
        })?;

        let long_text = longText
            .into_option()
            .map(|file| FilePointer::try_from_with(file, context))
            .transpose()
            .map_err(ChatItemError::LongText)?;

        let attachments: Vec<MessageAttachment> = likely_empty(attachments, |iter| {
            iter.map(|attachment| MessageAttachment::try_from_with(attachment, context))
                .collect::<Result<_, _>>()
        })?;

        if text.is_none() {
            if attachments.is_empty() {
                return Err(ChatItemError::StandardMessageIsEmpty);
            }
            if long_text.is_some() {
                return Err(ChatItemError::LongTextWithoutBody);
            }
        }

        Ok(Self {
            text,
            quote: quote.map(Box::new),
            attachments,
            reactions,
            link_previews,
            long_text: long_text.map(Box::new),
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

    impl proto::StandardMessage {
        pub(crate) fn test_data() -> Self {
            Self {
                text: Some(proto::Text::test_data()).into(),
                reactions: vec![proto::Reaction::test_data()],
                attachments: vec![proto::MessageAttachment::test_data()],
                quote: Some(proto::Quote::test_data()).into(),
                longText: Some(proto::FilePointer::minimal_test_data()).into(),
                ..Default::default()
            }
        }

        pub(crate) fn test_voice_message_data() -> Self {
            Self {
                attachments: vec![proto::MessageAttachment::test_voice_message_data()],
                longText: None.into(),
                linkPreview: vec![],
                text: None.into(),
                ..Self::test_data()
            }
        }
    }

    impl StandardMessage<FullRecipientData> {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                text: Some(MessageText::from_proto_test_data()),
                reactions: ReactionSet::from_iter([Reaction::from_proto_test_data()]),
                attachments: vec![MessageAttachment::from_proto_test_data()],
                quote: Some(Box::new(Quote::from_proto_test_data())),
                long_text: Some(Box::new(FilePointer::default())),
                link_previews: vec![],
                _limit_construction_to_module: (),
            }
        }
    }

    #[test]
    fn valid_standard_message() {
        assert_eq!(
            proto::StandardMessage::test_data().try_into_with(&TestContext::default()),
            Ok(StandardMessage::from_proto_test_data())
        );
    }

    #[test_case(|x| {
        x.text = None.into();
        x.longText = None.into();
    } => Ok(()); "no text")]
    #[test_case(|x| x.attachments.clear() => Ok(()); "no attachments")]
    #[test_case(|x| x.text = None.into() => Err(ChatItemError::LongTextWithoutBody); "long text without body")]
    #[test_case(|x| {
        x.text = None.into();
        x.longText = None.into();
        x.attachments.clear();
    } => Err(ChatItemError::StandardMessageIsEmpty); "no text or attachments")]
    fn standard_message(modifier: fn(&mut proto::StandardMessage)) -> Result<(), ChatItemError> {
        let mut message = proto::StandardMessage::test_data();
        modifier(&mut message);

        message
            .try_into_with(&TestContext::default())
            .map(|_: StandardMessage<FullRecipientData>| ())
    }
}
