// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::chat::{ChatItemError, Reaction};
use crate::backup::frame::RecipientId;
use crate::backup::method::Contains;
use crate::backup::sticker::MessageSticker;
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of [`proto::StickerMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct StickerMessage {
    pub reactions: Vec<Reaction>,
    pub sticker: MessageSticker,
    _limit_construction_to_module: (),
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

#[cfg(test)]
mod test {
    use test_case::test_case;

    use crate::backup::chat::testutil::{
        invalid_reaction, no_reactions, ProtoHasField, TestContext,
    };
    use crate::backup::chat::ReactionError;

    use super::*;

    impl proto::StickerMessage {
        pub(crate) fn test_data() -> Self {
            Self {
                reactions: vec![proto::Reaction::test_data()],
                sticker: Some(proto::Sticker::test_data()).into(),
                ..Default::default()
            }
        }
    }

    impl ProtoHasField<Vec<proto::Reaction>> for proto::StickerMessage {
        fn get_field_mut(&mut self) -> &mut Vec<proto::Reaction> {
            &mut self.reactions
        }
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
}
