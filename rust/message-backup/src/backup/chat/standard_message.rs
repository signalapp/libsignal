// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::chat::link::LinkPreview;
use crate::backup::chat::quote::Quote;
use crate::backup::chat::text::MessageText;
use crate::backup::chat::{ChatItemError, Reaction};
use crate::backup::frame::RecipientId;
use crate::backup::method::Contains;
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of [`proto::StandardMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct StandardMessage {
    pub text: Option<MessageText>,
    pub quote: Option<Quote>,
    pub reactions: Vec<Reaction>,
    pub link_previews: Vec<LinkPreview>,
    _limit_construction_to_module: (),
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

#[cfg(test)]
mod test {
    use protobuf::MessageField;

    use crate::backup::chat::testutil::{ProtoHasField, TestContext};

    use super::*;

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

    impl StandardMessage {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                text: Some(MessageText::from_proto_test_data()),
                reactions: vec![Reaction::from_proto_test_data()],
                quote: Some(Quote::from_proto_test_data()),
                link_previews: vec![],
                _limit_construction_to_module: (),
            }
        }
    }

    impl ProtoHasField<Vec<proto::Reaction>> for proto::StandardMessage {
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

    #[test]
    fn valid_standard_message() {
        assert_eq!(
            proto::StandardMessage::test_data().try_into_with(&TestContext::default()),
            Ok(StandardMessage::from_proto_test_data())
        );
    }
}
