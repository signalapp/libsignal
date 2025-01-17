// Copyright (C) 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
use derive_where::derive_where;

use crate::backup::chat::{MessageText, ReactionError, ReactionSet, TextError};
use crate::backup::file::{FilePointer, FilePointerError};
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::MinimalRecipientData;
use crate::backup::serialize::SerializeOrder;
use crate::backup::time::ReportUnusualTimestamp;
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of a 1:1 story reply message [`proto::DirectStoryReplyMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq + SerializeOrder))]
pub struct DirectStoryReplyMessage<Recipient> {
    pub content: DirectStoryReplyContent,
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub reactions: ReactionSet<Recipient>,
    _limit_construction_to_module: (),
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum DirectStoryReplyContent {
    Text {
        body: MessageText,
        long_text: Option<Box<FilePointer>>,
    },
    Emoji(String),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum DirectStoryReplyError {
    /// story reply has neither textReply nor emoji
    MissingReply,
    /// reply text is missing
    EmptyText,
    /// text: {0}
    Text(TextError),
    /// long text: {0}
    LongText(FilePointerError),
    /// reply emoji is missing
    EmptyEmoji,
    /// invalid reaction: {0}
    Reaction(#[from] ReactionError),
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryFromWith<proto::DirectStoryReplyMessage, C> for DirectStoryReplyMessage<R>
{
    type Error = DirectStoryReplyError;

    fn try_from_with(
        item: proto::DirectStoryReplyMessage,
        context: &C,
    ) -> Result<Self, Self::Error> {
        let proto::DirectStoryReplyMessage {
            reactions,
            reply,
            special_fields: _,
        } = item;

        let reactions = reactions.try_into_with(context)?;

        let content = match reply.ok_or(DirectStoryReplyError::MissingReply)? {
            proto::direct_story_reply_message::Reply::TextReply(
                proto::direct_story_reply_message::TextReply {
                    text,
                    longText,
                    special_fields: _,
                },
            ) => {
                let text = text.into_option().ok_or(DirectStoryReplyError::EmptyText)?;
                let text = MessageText::try_from(text).map_err(DirectStoryReplyError::Text)?;

                let long_text = longText
                    .into_option()
                    .map(|text| text.try_into_with(context))
                    .transpose()
                    .map_err(DirectStoryReplyError::LongText)?;

                DirectStoryReplyContent::Text {
                    body: text,
                    long_text: long_text.map(Box::new),
                }
            }
            proto::direct_story_reply_message::Reply::Emoji(emoji) => {
                if emoji.is_empty() {
                    return Err(DirectStoryReplyError::EmptyEmoji);
                }
                DirectStoryReplyContent::Emoji(emoji)
            }
        };

        Ok(Self {
            content,
            reactions,
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

    impl proto::DirectStoryReplyMessage {
        pub(crate) fn test_data() -> Self {
            Self {
                reactions: vec![proto::Reaction::test_data()],
                reply: Some(proto::direct_story_reply_message::Reply::TextReply(
                    proto::direct_story_reply_message::TextReply {
                        text: Some(proto::Text::test_data()).into(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }
        }
    }

    #[test]
    fn valid_story_reply_message() {
        assert_eq!(
            proto::DirectStoryReplyMessage::test_data().try_into_with(&TestContext::default()),
            Ok(DirectStoryReplyMessage {
                content: DirectStoryReplyContent::Text {
                    body: MessageText::from_proto_test_data(),
                    long_text: None,
                },
                reactions: ReactionSet::from_iter([Reaction::from_proto_test_data()]),
                _limit_construction_to_module: ()
            })
        )
    }

    #[test_case(|x| x.reply = None => Err(DirectStoryReplyError::MissingReply); "missing reply")]
    #[test_case(|x| x.mut_textReply().text = None.into() => Err(DirectStoryReplyError::EmptyText); "empty text")]
    #[test_case(
        |x| x.mut_textReply().text.as_mut().unwrap().bodyRanges.push(proto::BodyRange {
            associatedValue: Some(proto::body_range::AssociatedValue::MentionAci(vec![])),
            ..Default::default()
        }) =>
        Err(DirectStoryReplyError::Text(TextError::MentionInvalidAci));
        "invalid text"
    )]
    #[test_case(|x| x.mut_textReply().longText = Some(proto::FilePointer::test_data()).into() => Ok(()); "long text")]
    #[test_case(|x| x.mut_textReply().longText = Some(Default::default()).into() => Err(DirectStoryReplyError::LongText(FilePointerError::NoLocator)); "invalid long text")]
    #[test_case(|x| *x.mut_emoji() = "".into() => Err(DirectStoryReplyError::EmptyEmoji); "empty emoji")]
    #[test_case(|x| *x.mut_emoji() = "x".into() => Ok(()); "valid emoji")]
    #[test_case(|x| x.reactions.clear() => Ok(()); "no reactions")]
    #[test_case(|x| x.reactions.push(proto::Reaction::default()) => Err(DirectStoryReplyError::Reaction(ReactionError::EmptyEmoji)); "invalid reaction")]
    fn story_reply_message(
        modifier: fn(&mut proto::DirectStoryReplyMessage),
    ) -> Result<(), DirectStoryReplyError> {
        let mut message = proto::DirectStoryReplyMessage::test_data();
        modifier(&mut message);

        message
            .try_into_with(&TestContext::default())
            .map(|_: DirectStoryReplyMessage<FullRecipientData>| ())
    }
}
