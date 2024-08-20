//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::chat::text::{MessageText, TextError};
use crate::backup::file::{MessageAttachment, MessageAttachmentError};
use crate::backup::frame::RecipientId;
use crate::backup::method::Lookup;
use crate::backup::time::Timestamp;
use crate::backup::TryFromWith;
use crate::proto::backup as proto;

/// Validated version of [`proto::Quote`]
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Quote<Recipient> {
    #[serde(bound(serialize = "Recipient: serde::Serialize"))]
    pub author: Recipient,
    pub quote_type: QuoteType,
    pub target_sent_timestamp: Option<Timestamp>,
    pub attachments: Vec<QuotedAttachment>,
    pub text: Option<MessageText>,
    #[serde(skip)]
    _limit_construction_to_module: (),
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum QuoteType {
    Normal,
    GiftBadge,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct QuotedAttachment {
    pub content_type: Option<String>,
    pub file_name: Option<String>,
    pub thumbnail: Option<MessageAttachment>,
    #[serde(skip)]
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum QuoteError {
    /// has unknown author {0:?}
    AuthorNotFound(RecipientId),
    /// "type" is unknown
    TypeUnknown,
    /// text error: {0}
    Text(#[from] TextError),
    /// attachment thumbnail: {0}
    AttachmentThumbnail(#[from] MessageAttachmentError),
    /// attachment thumbnail cannot have flag {0:?}
    AttachmentThumbnailWrongFlag(proto::message_attachment::Flag),
}

impl<R: Clone, C: Lookup<RecipientId, R>> TryFromWith<proto::Quote, C> for Quote<R> {
    type Error = QuoteError;

    fn try_from_with(item: proto::Quote, context: &C) -> Result<Self, Self::Error> {
        let proto::Quote {
            authorId,
            type_,
            targetSentTimestamp,
            text,
            attachments,
            special_fields: _,
        } = item;

        let author_id = RecipientId(authorId);
        let Some(author) = context.lookup(&author_id).cloned() else {
            return Err(QuoteError::AuthorNotFound(author_id));
        };

        let target_sent_timestamp = targetSentTimestamp
            .map(|timestamp| Timestamp::from_millis(timestamp, "Quote.targetSentTimestamp"));
        let quote_type = match type_.enum_value_or_default() {
            proto::quote::Type::UNKNOWN => return Err(QuoteError::TypeUnknown),
            proto::quote::Type::NORMAL => QuoteType::Normal,
            proto::quote::Type::GIFTBADGE => QuoteType::GiftBadge,
        };

        let text = text.into_option().map(|text| text.try_into()).transpose()?;

        let attachments = attachments
            .into_iter()
            .map(QuotedAttachment::try_from)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            author,
            quote_type,
            target_sent_timestamp,
            attachments,
            text,
            _limit_construction_to_module: (),
        })
    }
}

impl TryFrom<proto::quote::QuotedAttachment> for QuotedAttachment {
    type Error = QuoteError;

    fn try_from(value: proto::quote::QuotedAttachment) -> Result<Self, Self::Error> {
        let proto::quote::QuotedAttachment {
            contentType,
            fileName,
            thumbnail,
            special_fields: _,
        } = value;

        let thumbnail = thumbnail
            .into_option()
            .map(MessageAttachment::try_from)
            .transpose()?;

        if let Some(thumbnail) = &thumbnail {
            match thumbnail.flag {
                proto::message_attachment::Flag::NONE
                | proto::message_attachment::Flag::BORDERLESS
                | proto::message_attachment::Flag::GIF => {}
                proto::message_attachment::Flag::VOICE_MESSAGE => {
                    return Err(QuoteError::AttachmentThumbnailWrongFlag(thumbnail.flag));
                }
            }
        }

        Ok(Self {
            content_type: contentType,
            file_name: fileName,
            thumbnail,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use crate::backup::chat::testutil::TestContext;
    use crate::backup::recipient::FullRecipientData;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;

    use super::*;

    impl proto::quote::QuotedAttachment {
        fn test_data() -> Self {
            Self {
                contentType: Some("video/mpeg".into()),
                fileName: Some("test.mpg".into()),
                thumbnail: Some(proto::MessageAttachment::test_data()).into(),
                ..Default::default()
            }
        }
    }

    impl QuotedAttachment {
        fn from_proto_test_data() -> Self {
            Self {
                content_type: Some("video/mpeg".into()),
                file_name: Some("test.mpg".into()),
                thumbnail: Some(MessageAttachment::from_proto_test_data()),
                _limit_construction_to_module: (),
            }
        }
    }

    #[test_case(|_| {} => Ok(()); "valid")]
    #[test_case(|x| x.contentType = None => Ok(()); "no contentType")]
    #[test_case(|x| x.contentType = Some("".into()) => Ok(()); "empty contentType")]
    #[test_case(|x| x.fileName = None => Ok(()); "no fileName")]
    #[test_case(|x| x.fileName = Some("".into()) => Ok(()); "empty fileName")]
    #[test_case(|x| x.thumbnail = None.into() => Ok(()); "no thumbnail")]
    #[test_case(|x| x.thumbnail = Some(proto::MessageAttachment::default()).into() => Err(QuoteError::AttachmentThumbnail(MessageAttachmentError::NoFilePointer)); "invalid thumbnail")]
    #[test_case(|x| x.thumbnail = Some(proto::MessageAttachment {
        flag: proto::message_attachment::Flag::BORDERLESS.into(),
        ..proto::MessageAttachment::test_data()
    }).into() => Ok(()); "borderless thumbnail")]
    #[test_case(|x| x.thumbnail = Some(proto::MessageAttachment {
        flag: proto::message_attachment::Flag::VOICE_MESSAGE.into(),
        ..proto::MessageAttachment::test_data()
    }).into() => Err(QuoteError::AttachmentThumbnailWrongFlag(proto::message_attachment::Flag::VOICE_MESSAGE)); "voice message thumbnail")]
    fn attachment(
        modifier: impl FnOnce(&mut proto::quote::QuotedAttachment),
    ) -> Result<(), QuoteError> {
        let mut attachment = proto::quote::QuotedAttachment::test_data();
        modifier(&mut attachment);
        QuotedAttachment::try_from(attachment).map(|_| ())
    }

    impl proto::Quote {
        pub(crate) fn test_data() -> Self {
            Self {
                authorId: proto::Recipient::TEST_ID,
                type_: proto::quote::Type::NORMAL.into(),
                targetSentTimestamp: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                attachments: vec![proto::quote::QuotedAttachment::test_data()],
                text: Some(proto::Text::test_data()).into(),
                ..Default::default()
            }
        }
    }

    impl Quote<FullRecipientData> {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                text: Some(MessageText::from_proto_test_data()),
                author: TestContext::test_recipient().clone(),
                quote_type: QuoteType::Normal,
                target_sent_timestamp: Some(Timestamp::test_value()),
                attachments: vec![QuotedAttachment::from_proto_test_data()],
                _limit_construction_to_module: (),
            }
        }
    }
}
