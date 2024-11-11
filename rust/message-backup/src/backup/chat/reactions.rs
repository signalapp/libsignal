//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use itertools::Itertools;

use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::DestinationKind;
use crate::backup::serialize::SerializeOrder;
use crate::backup::time::{ReportUnusualTimestamp, Timestamp};
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
    /// multiple reactions from {0:?}
    MultipleReactions(RecipientId),
    /// "emoji" is an empty string
    EmptyEmoji,
}

impl<R: Clone, C: LookupPair<RecipientId, DestinationKind, R> + ReportUnusualTimestamp>
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
        let Some((&author_kind, author)) = context.lookup_pair(&author_id) else {
            return Err(ReactionError::AuthorNotFound(author_id));
        };
        if !author_kind.is_individual() {
            return Err(ReactionError::InvalidAuthor(author_id, author_kind));
        }
        let author = author.clone();

        let sent_timestamp =
            Timestamp::from_millis(sentTimestamp, "Reaction.sentTimestamp", context);

        Ok(Self {
            emoji,
            sort_order: sortOrder,
            author,
            sent_timestamp,
            _limit_construction_to_module: (),
        })
    }
}

#[derive(Debug)]
pub struct ReactionSet<Recipient> {
    reactions: HashMap<RecipientId, Reaction<Recipient>>,
}

impl<R: Clone, C: LookupPair<RecipientId, DestinationKind, R> + ReportUnusualTimestamp>
    TryFromWith<Vec<proto::Reaction>, C> for ReactionSet<R>
{
    type Error = ReactionError;

    fn try_from_with(items: Vec<proto::Reaction>, context: &C) -> Result<Self, Self::Error> {
        let mut reactions = HashMap::with_capacity(items.len());

        for item in items {
            let author_id = RecipientId(item.authorId);
            let reaction = item.try_into_with(context)?;
            if reactions.insert(author_id, reaction).is_some() {
                return Err(ReactionError::MultipleReactions(author_id));
            }
        }

        Ok(Self { reactions })
    }
}

// ReactionSet serializes like UnorderedList; we don't need to maintain the "map" structure.
impl<R> serde::Serialize for ReactionSet<R>
where
    R: serde::Serialize + SerializeOrder,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut items = self.reactions.values().collect_vec();
        items.sort_by(|l, r| l.serialize_cmp(r));

        serializer.collect_seq(items)
    }
}

impl<R> FromIterator<(RecipientId, Reaction<R>)> for ReactionSet<R> {
    fn from_iter<T: IntoIterator<Item = (RecipientId, Reaction<R>)>>(iter: T) -> Self {
        Self {
            reactions: HashMap::from_iter(iter),
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
        // This is not very efficient because it makes two temporary arrays, but we only use it for
        // tests anyway.
        self.reactions
            .values()
            .sorted_unstable_by(|a, b| a.serialize_cmp(b))
            .collect_vec()
            == other
                .reactions
                .values()
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
            (
                TestContext::SELF_ID,
                Reaction {
                    sort_order: 10,
                    ..reaction1.clone()
                },
            ),
            (
                TestContext::CONTACT_ID,
                Reaction {
                    sort_order: 20,
                    ..reaction2.clone()
                },
            ),
        ]);

        let mut message2 = StandardMessage::from_proto_test_data();
        // Note that the recipient IDs have been swapped too, to demonstrate that they are not used
        // in sorting.
        message2.reactions = ReactionSet::from_iter([
            (
                TestContext::SELF_ID,
                Reaction {
                    sort_order: 200,
                    ..reaction2
                },
            ),
            (
                TestContext::CONTACT_ID,
                Reaction {
                    sort_order: 100,
                    ..reaction1
                },
            ),
        ]);

        assert_eq!(
            serde_json::to_string_pretty(&message1).expect("valid"),
            serde_json::to_string_pretty(&message2).expect("valid"),
        );
    }
}
