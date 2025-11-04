//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::Ordering;
use std::ops::RangeInclusive;

#[cfg(test)]
use derive_where::derive_where;
use intmap::IntMap;
use itertools::Itertools as _;
use unicode_segmentation::UnicodeSegmentation as _;

use crate::backup::TryIntoWith;
use crate::backup::chat::reactions::{ReactionError, ReactionSet};
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::MinimalRecipientData;
use crate::backup::serialize::{SerializeOrder, UnorderedList};
use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampError};
use crate::proto::backup::poll::PollOption as PollOptionProto;
use crate::proto::backup::poll::poll_option::PollVote as PollVoteProto;
use crate::proto::backup::{Poll as PollProto, PollTerminateUpdate as PollTerminateProto};

const POLL_STRING_LENGTH_RANGE: RangeInclusive<usize> = 1..=100;
const MIN_POLL_OPTIONS: usize = 2;

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq))]
pub struct PollVote<Recipient> {
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub voter: Recipient,
    pub vote_count: u32,
    _limit_construction_to_module: (),
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq))]
pub struct PollOption<Recipient> {
    pub option: String,
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub votes: UnorderedList<PollVote<Recipient>>,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq + SerializeOrder))]
pub struct Poll<Recipient> {
    pub question: String,
    pub allow_multiple: bool,
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub options: Vec<PollOption<Recipient>>,
    pub has_ended: bool,
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub reactions: ReactionSet<Recipient>,
    _limit_construction_to_module: (),
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct PollTerminate {
    pub target_sent_timestamp: Timestamp,
    pub question: String,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum PollError {
    /// voter id is not present
    UnknownVoterId,
    /// voter id is not self nor contact
    InvalidVoterId,
    /// {0} size ({1}) is out of bounds
    InvalidPollStringSize(&'static str, usize),
    /// {0} option(s) is too few for a poll
    TooFewOptions(usize),
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
    /// multiple vote records from voters: {0:?}
    NonUniqueVoters(Vec<RecipientId>),
    /// invalid reaction: {0}
    Reaction(#[from] ReactionError),
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryIntoWith<PollVote<R>, C> for PollVoteProto
{
    type Error = PollError;

    fn try_into_with(self, context: &C) -> Result<PollVote<R>, Self::Error> {
        let PollVoteProto {
            voterId,
            voteCount,
            special_fields: _,
        } = self;
        let voter_id = RecipientId(voterId);
        let Some((voter_data, voter)) = context.lookup_pair(&voter_id) else {
            return Err(Self::Error::UnknownVoterId);
        };
        match voter_data {
            MinimalRecipientData::Self_ | MinimalRecipientData::Contact { .. } => {}
            MinimalRecipientData::Group { .. }
            | MinimalRecipientData::DistributionList { .. }
            | MinimalRecipientData::ReleaseNotes
            | MinimalRecipientData::CallLink { .. } => return Err(Self::Error::InvalidVoterId),
        }

        Ok(PollVote {
            voter: voter.clone(),
            vote_count: voteCount,
            _limit_construction_to_module: (),
        })
    }
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryIntoWith<PollOption<R>, C> for PollOptionProto
{
    type Error = PollError;

    fn try_into_with(self, context: &C) -> Result<PollOption<R>, Self::Error> {
        let PollOptionProto {
            option,
            votes,
            special_fields: _,
        } = self;
        validate_poll_string_len(&option, "poll option")?;
        validate_unique_voters(votes.iter().map(|vote| vote.voterId))?;
        let votes = votes
            .into_iter()
            .map(|vote| vote.try_into_with(context))
            .collect::<Result<Vec<_>, _>>()
            .map(UnorderedList)?;
        Ok(PollOption { option, votes })
    }
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryIntoWith<Poll<R>, C> for PollProto
{
    type Error = PollError;

    fn try_into_with(self, context: &C) -> Result<Poll<R>, Self::Error> {
        let PollProto {
            question,
            allowMultiple: allow_multiple,
            options,
            hasEnded: has_ended,
            reactions,
            special_fields: _,
        } = self;
        validate_poll_string_len(&question, "poll question")?;
        if options.len() < MIN_POLL_OPTIONS {
            return Err(Self::Error::TooFewOptions(options.len()));
        }
        // Per option enforcement of unique voters happens inside PollOptionProto::try_with_context,
        // but we need to stash all voter ids in order to enforce single vote per voter if allow_multiple is false.
        let all_voter_ids = options
            .iter()
            .flat_map(|opt| opt.votes.iter().map(|vote| vote.voterId))
            .collect_vec();
        let options = options
            .into_iter()
            .map(|opt| opt.try_into_with(context))
            .collect::<Result<Vec<_>, _>>()?;
        if !allow_multiple {
            validate_unique_voters(all_voter_ids.iter().copied())?;
        }
        let reactions = reactions.try_into_with(context)?;
        Ok(Poll {
            question,
            allow_multiple,
            options,
            has_ended,
            reactions,
            _limit_construction_to_module: (),
        })
    }
}

impl<C: ReportUnusualTimestamp> TryIntoWith<PollTerminate, C> for PollTerminateProto {
    type Error = PollError;

    fn try_into_with(self, context: &C) -> Result<PollTerminate, Self::Error> {
        let PollTerminateProto {
            targetSentTimestamp,
            question,
            special_fields: _,
        } = self;
        validate_poll_string_len(&question, "poll question")?;
        let target_sent_timestamp = Timestamp::from_millis(
            targetSentTimestamp,
            "PollTerminateUpdate.targetSentTimestamp",
            context,
        )?;
        Ok(PollTerminate {
            target_sent_timestamp,
            question,
        })
    }
}

fn validate_poll_string_len(s: &str, description: &'static str) -> Result<(), PollError> {
    let len = s.graphemes(true).count();
    if !POLL_STRING_LENGTH_RANGE.contains(&len) {
        return Err(PollError::InvalidPollStringSize(description, len));
    }
    Ok(())
}

fn validate_unique_voters(ids: impl ExactSizeIterator<Item = u64>) -> Result<(), PollError> {
    let mut hist = IntMap::<_, usize>::with_capacity(ids.len());
    for id in ids {
        let id = RecipientId(id);
        *hist.entry(id).or_default() += 1;
    }
    let non_unique_voters = hist
        .iter()
        .filter_map(|(k, v)| (v > &1).then_some(k))
        .collect_vec();
    if !non_unique_voters.is_empty() {
        return Err(PollError::NonUniqueVoters(non_unique_voters));
    }
    Ok(())
}

impl<R: SerializeOrder> SerializeOrder for PollVote<R> {
    fn serialize_cmp(&self, other: &Self) -> Ordering {
        self.voter.serialize_cmp(&other.voter)
    }
}

impl<R> SerializeOrder for PollOption<R> {
    fn serialize_cmp(&self, other: &Self) -> Ordering {
        self.option.cmp(&other.option)
    }
}

#[cfg(test)]
mod test {
    use std::time::SystemTime;

    use assert_matches::assert_matches;
    use itertools::assert_equal;
    use test_case::test_case;

    use super::*;
    use crate::backup::chat::reactions::Reaction;
    use crate::backup::testutil::TestContext;
    use crate::proto::backup::Reaction as ReactionProto;

    fn poll_vote_proto() -> PollVoteProto {
        PollVoteProto {
            voterId: TestContext::SELF_ID.0,
            voteCount: 42,
            special_fields: Default::default(),
        }
    }

    #[test]
    fn poll_vote_success() {
        let proto = poll_vote_proto();
        let parsed = proto.try_into_with(&TestContext::default());
        assert_matches!(parsed, Ok(PollVote{voter, vote_count: 42, _limit_construction_to_module}) => {
            assert_matches!(voter.as_ref(), MinimalRecipientData::Self_)
        });
    }

    #[test_case(|x| x.voterId = TestContext::SELF_ID.0 => Ok(()); "self voter")]
    #[test_case(|x| x.voterId = TestContext::CONTACT_ID.0 => Ok(()); "contact voter")]
    #[test_case(|x| x.voterId = TestContext::GROUP_ID.0 => Err(PollError::InvalidVoterId); "group voter")]
    #[test_case(|x| x.voterId = TestContext::CALL_LINK_ID.0 => Err(PollError::InvalidVoterId); "call link voter")]
    #[test_case(|x| x.voterId = TestContext::RELEASE_NOTES_ID.0 => Err(PollError::InvalidVoterId); "release notes voter")]
    #[test_case(|x| x.voterId = TestContext::NONEXISTENT_ID.0 => Err(PollError::UnknownVoterId); "nonexistent voter")]
    fn poll_vote(modify: fn(&mut PollVoteProto)) -> Result<(), PollError> {
        let mut vote = PollVoteProto::default();
        modify(&mut vote);
        vote.try_into_with(&TestContext::default()).map(|_| ())
    }

    #[test_case("a" => Ok(()); "lower bound")]
    #[test_case(&format!("{:0100}", 0) => Ok(()); "upper bound")]
    #[test_case("" => Err(PollError::InvalidPollStringSize("test string", 0)); "too short")]
    #[test_case(&format!("{:0101}", 0) => Err(PollError::InvalidPollStringSize("test string", 101)); "too long")]
    #[test_case("🧑‍🧑‍🧒‍🧒🧑‍🧑‍🧒‍🧒🧑‍🧑‍🧒‍🧒🧑‍🧑‍🧒‍🧒🧑‍🧑‍🧒‍🧒" => Ok(()); "grapheme clusters")]
    fn length_check(s: &str) -> Result<(), PollError> {
        validate_poll_string_len(s, "test string")
    }

    fn poll_option_proto(option: &str) -> PollOptionProto {
        PollOptionProto {
            option: option.to_string(),
            votes: vec![poll_vote_proto()],
            special_fields: Default::default(),
        }
    }

    fn poll_proto() -> PollProto {
        PollProto {
            question: "To be or not to be?".to_string(),
            allowMultiple: true,
            options: vec![
                poll_option_proto("that"),
                poll_option_proto("is"),
                poll_option_proto("the"),
                poll_option_proto("question"),
            ],
            hasEnded: false,
            reactions: vec![ReactionProto::test_data()],
            special_fields: Default::default(),
        }
    }

    #[test]
    fn poll_option_success() {
        let proto = poll_option_proto("test");
        let result = proto.clone().try_into_with(&TestContext::default());
        assert_matches!(result, Ok(PollOption{option, votes}) => {
            assert_eq!(option, proto.option);
            let PollVote{voter, vote_count, _limit_construction_to_module} = &votes.0[0];
            assert_eq!(vote_count, &proto.votes[0].voteCount);
            assert_matches!(voter.as_ref(), MinimalRecipientData::Self_);
        });
    }

    #[test]
    fn poll_option_non_unique_voters() {
        let mut proto = poll_option_proto("test");
        let self_vote = &proto.votes[0];
        let contact_vote = {
            let mut vote = poll_vote_proto();
            vote.voterId = TestContext::CONTACT_ID.0;
            vote
        };
        proto.votes = vec![
            self_vote.clone(),
            self_vote.clone(),
            contact_vote.clone(),
            contact_vote,
        ];
        let result = proto.try_into_with(&TestContext::default());
        assert_matches!(result, Err(PollError::NonUniqueVoters(ids)) => {
            assert_equal(ids, [TestContext::CONTACT_ID, TestContext::SELF_ID]);
        });
    }

    #[test]
    fn poll_success() {
        let proto = poll_proto();
        let result = proto.clone().try_into_with(&TestContext::default());
        assert_matches!(
            result,
            Ok(Poll {
                question,
                allow_multiple: true,
                options,
                has_ended: false,
                reactions,
                _limit_construction_to_module
            }) => {
                assert_eq!(question, proto.question);
                let vote = &options[0].votes.0[0];
                let PollVote{voter, vote_count, _limit_construction_to_module} = vote;
                assert_eq!(vote_count, &proto.options[0].votes[0].voteCount);
                assert_matches!(voter.as_ref(), MinimalRecipientData::Self_);
                assert_eq!(reactions, ReactionSet::from_iter([Reaction::from_proto_test_data()]))
            }
        );
    }

    #[test_case(|_| {} => Ok(()); "valid")]
    #[test_case(|x| x.options = vec![] => Err(PollError::TooFewOptions(0)); "not an option")]
    #[test_case(|x| x.options.truncate(1) => Err(PollError::TooFewOptions(1)); "but one option")]
    #[test_case(|x| x.options.truncate(2) => Ok(()); "barely enough choice")]
    #[test_case(|x| x.question = "".to_string() => Err(PollError::InvalidPollStringSize("poll question", 0)); "empty question")]
    #[test_case(|x| x.question = "a".to_string() => Ok(()); "question len lower bound")]
    #[test_case(|x| x.question = format!("{:0100}", 0) => Ok(()); "question len upper bound")]
    #[test_case(|x| x.question = format!("{:0101}", 0) => Err(PollError::InvalidPollStringSize("poll question", 101)); "question too long")]
    #[test_case(|x| x.reactions.clear() => Ok(()); "no reactions")]
    #[test_case(|x| x.reactions.push(ReactionProto::default()) => Err(PollError::Reaction(ReactionError::EmptyEmoji)); "invalid reaction")]
    #[test_case(|x| x.allowMultiple = false => Err(PollError::NonUniqueVoters(vec![TestContext::SELF_ID])); "non unique voters")]
    fn poll(modify: fn(&mut PollProto)) -> Result<(), PollError> {
        let mut poll = poll_proto();
        modify(&mut poll);
        poll.try_into_with(&TestContext::default()).map(|_| ())
    }

    fn poll_terminate_proto() -> PollTerminateProto {
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("valid time")
                .as_millis(),
        )
        .expect("64 bits ought to be enough");
        PollTerminateProto {
            targetSentTimestamp: now_ms,
            question: "To be or not to be".to_string(),
            special_fields: Default::default(),
        }
    }

    #[test]
    fn poll_terminate_success() {
        let proto = poll_terminate_proto();
        let parsed = proto.clone().try_into_with(&TestContext::default());
        assert_matches!(parsed, Ok(PollTerminate{target_sent_timestamp,question}) => {
            assert_eq!(question, proto.question);
            assert_eq!(target_sent_timestamp.as_millis(), proto.targetSentTimestamp);
        });
    }

    #[test_case(|_| {} => Ok(()); "happy path")]
    #[test_case(|x| x.targetSentTimestamp = Timestamp::MAX_SAFE_TIMESTAMP_MS + 1 =>
        Err(PollError::InvalidTimestamp(TimestampError("PollTerminateUpdate.targetSentTimestamp", Timestamp::MAX_SAFE_TIMESTAMP_MS + 1))); "bad timestamp")]
    #[test_case(|x| x.question = "".to_string() => Err(PollError::InvalidPollStringSize("poll question", 0)); "empty question")]
    #[test_case(|x| x.question = "a".to_string() => Ok(()); "question len lower bound")]
    #[test_case(|x| x.question = format!("{:0100}", 0) => Ok(()); "question len upper bound")]
    #[test_case(|x| x.question = format!("{:0101}", 0) => Err(PollError::InvalidPollStringSize("poll question", 101)); "question too long")]
    fn poll_terminate(modify: fn(&mut PollTerminateProto)) -> Result<(), PollError> {
        let mut terminate = poll_terminate_proto();
        modify(&mut terminate);
        terminate.try_into_with(&TestContext::default()).map(|_| ())
    }
}
