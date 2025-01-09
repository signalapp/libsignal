//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use derive_where::derive_where;
use intmap::IntMap;

use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::{DestinationKind, MinimalRecipientData};
use crate::backup::serialize::{SerializeOrder, UnorderedList};
use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampError};
use crate::backup::{TryFromWith, TryIntoWith};
use crate::proto::backup as proto;

/// Validated version of [`proto::Reaction`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub struct Reaction<Recipient> {
    pub emoji: String,
    // This field is not generated consistently on all platforms, so we only use it to sort
    // containers of Reactions.
    #[serde(skip)]
    pub sort_order: u64,
    #[serde(bound(serialize = "Recipient: serde::Serialize"))]
    pub author: Recipient,
    pub sent_timestamp: Timestamp,
    _limit_construction_to_module: (),
}

impl<Recipient: SerializeOrder> SerializeOrder for Reaction<Recipient> {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_order
            .cmp(&other.sort_order)
            .then_with(|| self.author.serialize_cmp(&other.author))
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ReactionError {
    /// unknown author {0:?}
    AuthorNotFound(RecipientId),
    /// author {0:?} was a {1:?}, not a contact or self
    InvalidAuthor(RecipientId, DestinationKind),
    /// author {0:?} has neither an ACI nor an E164
    AuthorHasNoAciOrE164(RecipientId),
    /// multiple reactions from {0:?}
    MultipleReactions(RecipientId),
    /// "emoji" is an empty string
    EmptyEmoji,
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryFromWith<proto::Reaction, C> for Reaction<R>
{
    type Error = ReactionError;

    fn try_from_with(item: proto::Reaction, context: &C) -> Result<Self, Self::Error> {
        let proto::Reaction {
            authorId,
            sentTimestamp,
            emoji,
            sortOrder,
            special_fields: _,
        } = item;

        if emoji.is_empty() {
            return Err(ReactionError::EmptyEmoji);
        }

        let author_id = RecipientId(authorId);
        let Some((author_data, author)) = context.lookup_pair(&author_id) else {
            return Err(ReactionError::AuthorNotFound(author_id));
        };
        let author = match author_data {
            MinimalRecipientData::Contact {
                e164: None,
                aci: None,
                pni: _,
            } => Err(ReactionError::AuthorHasNoAciOrE164(author_id)),
            MinimalRecipientData::Contact {
                e164: _,
                aci: _,
                pni: _,
            }
            | MinimalRecipientData::Self_ => Ok(author.clone()),
            MinimalRecipientData::Group { .. }
            | MinimalRecipientData::DistributionList { .. }
            | MinimalRecipientData::ReleaseNotes
            | MinimalRecipientData::CallLink { .. } => Err(ReactionError::InvalidAuthor(
                author_id,
                *author_data.as_ref(),
            )),
        }?;

        let sent_timestamp =
            Timestamp::from_millis(sentTimestamp, "Reaction.sentTimestamp", context)?;

        Ok(Self {
            emoji,
            sort_order: sortOrder,
            author,
            sent_timestamp,
            _limit_construction_to_module: (),
        })
    }
}

#[derive(Debug, serde::Serialize)]
#[derive_where(Default)]
pub struct ReactionSet<Recipient> {
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    reactions: UnorderedList<Reaction<Recipient>>,
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryFromWith<Vec<proto::Reaction>, C> for ReactionSet<R>
{
    type Error = ReactionError;

    fn try_from_with(items: Vec<proto::Reaction>, context: &C) -> Result<Self, Self::Error> {
        let mut existing = IntMap::with_capacity(items.len());
        let mut reactions = Vec::with_capacity(items.len());

        for item in items {
            let author_id = RecipientId(item.authorId);
            if existing.insert(author_id, ()).is_some() {
                return Err(ReactionError::MultipleReactions(author_id));
            }
            reactions.push(item.try_into_with(context)?);
        }

        Ok(Self {
            reactions: reactions.into(),
        })
    }
}

#[cfg(test)]
impl<R> FromIterator<Reaction<R>> for ReactionSet<R> {
    fn from_iter<T: IntoIterator<Item = Reaction<R>>>(iter: T) -> Self {
        // Does not check uniqueness, hence the cfg(test).
        Self {
            reactions: iter.into_iter().collect(),
        }
    }
}

/// Custom implementation of PartialEq to avoid comparing the keys; RecipientIds are not stable
/// across backups.
#[cfg(test)]
impl<R> PartialEq for ReactionSet<R>
where
    R: PartialEq + SerializeOrder,
{
    fn eq(&self, other: &Self) -> bool {
        use itertools::Itertools as _;

        // This is not very efficient because it makes two temporary arrays, but we only use it for
        // tests anyway.
        self.reactions
            .iter()
            .sorted_unstable_by(|a, b| a.serialize_cmp(b))
            .collect_vec()
            == other
                .reactions
                .iter()
                .sorted_unstable_by(|a, b| a.serialize_cmp(b))
                .collect_vec()
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::test_case;

    use super::*;
    use crate::backup::chat::StandardMessage;
    use crate::backup::recipient::FullRecipientData;
    use crate::backup::testutil::TestContext;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;
    use crate::backup::time::Duration;

    impl proto::Reaction {
        pub(crate) fn test_data() -> Self {
            Self {
                emoji: "📲".to_string(),
                sortOrder: 3,
                authorId: proto::Recipient::TEST_ID,
                sentTimestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                ..Default::default()
            }
        }
    }

    impl Reaction<FullRecipientData> {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                emoji: "📲".to_string(),
                sort_order: 3,
                author: TestContext::test_recipient().clone(),
                sent_timestamp: Timestamp::test_value(),
                _limit_construction_to_module: (),
            }
        }
    }

    #[test]
    fn valid_reaction() {
        assert_eq!(
            proto::Reaction::test_data().try_into_with(&TestContext::default()),
            Ok(Reaction::from_proto_test_data())
        )
    }

    #[test_case(
        |x| x.authorId = proto::Recipient::TEST_ID + 2 => Err(ReactionError::AuthorNotFound(RecipientId(proto::Recipient::TEST_ID + 2)));
        "unknown author id"
    )]
    #[test_case(
        |x| x.authorId = TestContext::GROUP_ID.0 => Err(ReactionError::InvalidAuthor(TestContext::GROUP_ID, DestinationKind::Group));
        "invalid author id"
    )]
    #[test_case(
        |x| x.authorId = TestContext::PNI_ONLY_ID.0 => Err(ReactionError::AuthorHasNoAciOrE164(TestContext::PNI_ONLY_ID));
        "pni-only author"
    )]
    #[test_case(
        |x| x.sentTimestamp = MillisecondsSinceEpoch::FAR_FUTURE.0 =>
        Err(ReactionError::InvalidTimestamp(TimestampError("Reaction.sentTimestamp", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid timestamp"
    )]
    fn reaction(modifier: fn(&mut proto::Reaction)) -> Result<(), ReactionError> {
        let mut reaction = proto::Reaction::test_data();
        modifier(&mut reaction);

        reaction
            .try_into_with(&TestContext::default())
            .map(|_: Reaction<FullRecipientData>| ())
    }

    #[test]
    fn duplicate_reactions_are_rejected() {
        assert_matches!(
            ReactionSet::try_from_with(
                vec![proto::Reaction::test_data(), proto::Reaction::test_data()],
                &TestContext::default(),
            ),
            Err(ReactionError::MultipleReactions(TestContext::SELF_ID))
        );

        // Note that having the same sort order is okay. Some clients use timestamps as sort order
        // and it's possible for those to be identical.
        assert_matches!(
            ReactionSet::try_from_with(
                vec![
                    proto::Reaction::test_data(),
                    proto::Reaction {
                        authorId: TestContext::CONTACT_ID.0,
                        ..proto::Reaction::test_data()
                    }
                ],
                &TestContext::default(),
            ),
            Ok(_)
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

        let mut message1 = StandardMessage::from_proto_test_data();
        message1.reactions = ReactionSet::from_iter([
            Reaction {
                sort_order: 10,
                ..reaction1.clone()
            },
            Reaction {
                sort_order: 20,
                ..reaction2.clone()
            },
        ]);

        let mut message2 = StandardMessage::from_proto_test_data();
        // Note that the recipient IDs have been swapped too, to demonstrate that they are not used
        // in sorting.
        message2.reactions = ReactionSet::from_iter([
            Reaction {
                sort_order: 200,
                ..reaction2
            },
            Reaction {
                sort_order: 100,
                ..reaction1
            },
        ]);

        assert_eq!(
            serde_json::to_string_pretty(&message1).expect("valid"),
            serde_json::to_string_pretty(&message2).expect("valid"),
        );
    }
}
