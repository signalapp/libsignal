//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::chat::text::{MessageText, TextError};
use crate::backup::frame::RecipientId;
use crate::backup::method::Contains;
use crate::backup::time::Timestamp;
use crate::backup::TryFromWith;
use crate::proto::backup as proto;

/// Validated version of [`proto::Quote`]
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Quote {
    pub author: RecipientId,
    pub quote_type: QuoteType,
    pub target_sent_timestamp: Option<Timestamp>,
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

#[cfg(test)]
mod test {
    use crate::backup::time::testutil::MillisecondsSinceEpoch;

    use super::*;

    impl proto::Quote {
        pub(crate) fn test_data() -> Self {
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

    impl Quote {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                text: Some(MessageText::from_proto_test_data()),
                author: RecipientId(proto::Recipient::TEST_ID),
                quote_type: QuoteType::Normal,
                target_sent_timestamp: Some(Timestamp::test_value()),
                _limit_construction_to_module: (),
            }
        }
    }
}
