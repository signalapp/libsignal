// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
use derive_where::derive_where;

use crate::backup::TryIntoWith;
use crate::backup::chat::{ChatItemError, ReactionSet};
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::MinimalRecipientData;
use crate::backup::serialize::SerializeOrder;
use crate::backup::sticker::MessageSticker;
use crate::backup::time::ReportUnusualTimestamp;
use crate::proto::backup as proto;

/// Validated version of [`proto::StickerMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq + SerializeOrder))]
pub struct StickerMessage<Recipient> {
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub reactions: ReactionSet<Recipient>,
    pub sticker: Box<MessageSticker>,
    _limit_construction_to_module: (),
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryIntoWith<StickerMessage<R>, C> for proto::StickerMessage
{
    type Error = ChatItemError;

    fn try_into_with(self, context: &C) -> Result<StickerMessage<R>, Self::Error> {
        let proto::StickerMessage {
            reactions,
            sticker,
            special_fields: _,
        } = self;

        let reactions = reactions.try_into_with(context)?;

        let sticker = sticker
            .into_option()
            .ok_or(ChatItemError::StickerMessageMissingSticker)?
            .try_into_with(context)?;

        Ok(StickerMessage {
            reactions,
            sticker: Box::new(sticker),
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;
    use crate::backup::chat::ReactionError;
    use crate::backup::recipient::FullRecipientData;
    use crate::backup::testutil::TestContext;

    impl proto::StickerMessage {
        pub(crate) fn test_data() -> Self {
            Self {
                reactions: vec![proto::Reaction::test_data()],
                sticker: Some(proto::Sticker::test_data()).into(),
                ..Default::default()
            }
        }
    }

    #[test_case(|x| x.reactions.clear() => Ok(()); "no reactions")]
    #[test_case(|x| x.reactions.push(Default::default()) => Err(ChatItemError::Reaction(ReactionError::EmptyEmoji)); "invalid reaction")]
    fn sticker_message(modifier: fn(&mut proto::StickerMessage)) -> Result<(), ChatItemError> {
        let mut message = proto::StickerMessage::test_data();
        modifier(&mut message);

        message
            .try_into_with(&TestContext::default())
            .map(|_: StickerMessage<FullRecipientData>| ())
    }
}
