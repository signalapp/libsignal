// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::chat::link::LinkPreview;
use crate::backup::chat::quote::Quote;
use crate::backup::chat::text::MessageText;
use crate::backup::chat::{ChatItemError, Reaction};
use crate::backup::file::{FilePointer, MessageAttachment};
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::DestinationKind;
use crate::backup::serialize::{SerializeOrder, UnorderedList};
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of [`proto::StandardMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct StandardMessage<Recipient> {
    pub text: Option<MessageText>,
    pub quote: Option<Quote<Recipient>>,
    pub attachments: Vec<MessageAttachment>,
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub reactions: UnorderedList<Reaction<Recipient>>,
    pub link_previews: Vec<LinkPreview>,
    pub long_text: Option<FilePointer>,
    _limit_construction_to_module: (),
}

impl<R: Clone, C: LookupPair<RecipientId, DestinationKind, R>>
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

        let long_text = longText
            .into_option()
            .map(FilePointer::try_from)
            .transpose()
            .map_err(ChatItemError::LongText)?;

        let attachments = attachments
            .into_iter()
            .map(MessageAttachment::try_from)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            text,
            quote,
            attachments,
            reactions,
            link_previews,
            long_text,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::backup::recipient::FullRecipientData;
    use crate::backup::testutil::TestContext;
    use crate::backup::time::{Duration, Timestamp};

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
                reactions: vec![Reaction::from_proto_test_data()].into(),
                attachments: vec![MessageAttachment::from_proto_test_data()],
                quote: Some(Quote::from_proto_test_data()),
                long_text: Some(FilePointer::default()),
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

    #[test]
    fn reactions_are_sorted_when_serialized() {
        let reaction1 = Reaction {
            sent_timestamp: Timestamp::test_value(),
            ..Reaction::from_proto_test_data()
        };
        let reaction2 = Reaction {
            sent_timestamp: Timestamp::test_value() + Duration::from_millis(1000),
            ..Reaction::from_proto_test_data()
        };

        let message1 = StandardMessage {
            reactions: vec![
                Reaction {
                    sort_order: 10,
                    ..reaction1.clone()
                },
                Reaction {
                    sort_order: 20,
                    ..reaction2.clone()
                },
            ]
            .into(),
            ..StandardMessage::from_proto_test_data()
        };
        let message2 = StandardMessage {
            reactions: vec![
                Reaction {
                    sort_order: 200,
                    ..reaction2
                },
                Reaction {
                    sort_order: 100,
                    ..reaction1
                },
            ]
            .into(),
            ..StandardMessage::from_proto_test_data()
        };

        assert_eq!(
            serde_json::to_string_pretty(&message1).expect("valid"),
            serde_json::to_string_pretty(&message2).expect("valid"),
        );
    }
}
