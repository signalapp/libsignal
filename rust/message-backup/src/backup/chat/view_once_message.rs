// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
use derive_where::derive_where;

use crate::backup::chat::{ReactionError, ReactionSet};
use crate::backup::file::{MessageAttachment, MessageAttachmentError};
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::MinimalRecipientData;
use crate::backup::serialize::SerializeOrder;
use crate::backup::time::ReportUnusualTimestamp;
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of a view-once message [`proto::ViewOnceMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq + SerializeOrder))]
pub struct ViewOnceMessage<Recipient> {
    pub attachment: Option<Box<MessageAttachment>>,
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub reactions: ReactionSet<Recipient>,
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ViewOnceMessageError {
    /// attachment: {0}
    Attachment(#[from] MessageAttachmentError),
    /// invalid reaction: {0}
    Reaction(#[from] ReactionError),
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryFromWith<proto::ViewOnceMessage, C> for ViewOnceMessage<R>
{
    type Error = ViewOnceMessageError;

    fn try_from_with(item: proto::ViewOnceMessage, context: &C) -> Result<Self, Self::Error> {
        let proto::ViewOnceMessage {
            attachment,
            reactions,
            special_fields: _,
        } = item;

        let attachment = attachment
            .into_option()
            .map(|attachment| MessageAttachment::try_from_with(attachment, context))
            .transpose()?;

        let reactions = reactions.try_into_with(context)?;

        Ok(Self {
            attachment: attachment.map(Box::new),
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

    impl proto::ViewOnceMessage {
        fn test_data() -> Self {
            Self {
                attachment: Some(proto::MessageAttachment::test_data()).into(),
                reactions: vec![proto::Reaction::test_data()],
                ..Default::default()
            }
        }
    }

    #[test]
    fn valid_view_once_message() {
        assert_eq!(
            proto::ViewOnceMessage::test_data().try_into_with(&TestContext::default()),
            Ok(ViewOnceMessage {
                attachment: Some(MessageAttachment::from_proto_test_data().into()),
                reactions: ReactionSet::from_iter([Reaction::from_proto_test_data()]),
                _limit_construction_to_module: ()
            })
        )
    }

    #[test_case(|x| x.reactions.clear() => Ok(()); "no reactions")]
    #[test_case(|x| x.reactions.push(proto::Reaction::default()) => Err(ViewOnceMessageError::Reaction(ReactionError::EmptyEmoji)); "invalid reaction")]
    #[test_case(|x| x.attachment = None.into() => Ok(()); "already viewed")]
    #[test_case(|x| x.attachment = Some(proto::MessageAttachment::default()).into() => Err(ViewOnceMessageError::Attachment(MessageAttachmentError::NoFilePointer)); "invalid attachment")]
    fn view_once_message(
        modifier: fn(&mut proto::ViewOnceMessage),
    ) -> Result<(), ViewOnceMessageError> {
        let mut message = proto::ViewOnceMessage::test_data();
        modifier(&mut message);

        message
            .try_into_with(&TestContext::default())
            .map(|_: ViewOnceMessage<FullRecipientData>| ())
    }
}
