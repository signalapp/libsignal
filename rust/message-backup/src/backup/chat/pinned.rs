//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
use derive_where::derive_where;

use crate::backup::TryIntoWith;
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::MinimalRecipientData;
use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampError};
use crate::proto::backup::PinMessageUpdate as PinMessageUpdateProto;
use crate::proto::backup::chat_item::PinDetails as PinDetailsProto;
use crate::proto::backup::chat_item::pin_details::PinExpiry as PinExpiryProto;

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq))]
pub struct PinMessageUpdate<Recipient> {
    pub target_sent_timestamp: Timestamp,
    pub author: Recipient,
    _limit_construction_to_module: (),
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum PinExpiry {
    At(Timestamp),
    Never,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct PinDetails {
    pub pinned_at: Timestamp,
    pub expires: PinExpiry,
    _limit_construction_to_module: (),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum PinMessageError {
    /// author id is not present
    UnknownAuthorId,
    /// author id is not self nor contact
    InvalidAuthorId,
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
    /// pin expiration is not set
    ExpirationNotSet,
    /// pin message expires before it is pinned
    ExpiresBeforeBeingPinned,
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
    TryIntoWith<PinMessageUpdate<R>, C> for PinMessageUpdateProto
{
    type Error = PinMessageError;

    fn try_into_with(self, context: &C) -> Result<PinMessageUpdate<R>, Self::Error> {
        let PinMessageUpdateProto {
            targetSentTimestamp,
            authorId,
            special_fields: _,
        } = self;
        let author_id = RecipientId(authorId);
        let Some((author_data, author)) = context.lookup_pair(&author_id) else {
            return Err(Self::Error::UnknownAuthorId);
        };
        match author_data {
            MinimalRecipientData::Self_ | MinimalRecipientData::Contact { .. } => {}
            MinimalRecipientData::Group { .. }
            | MinimalRecipientData::DistributionList { .. }
            | MinimalRecipientData::ReleaseNotes
            | MinimalRecipientData::CallLink { .. } => return Err(Self::Error::InvalidAuthorId),
        }
        let target_sent_timestamp = Timestamp::from_millis(
            targetSentTimestamp,
            "PinMessageUpdate.targetSentTimestamp",
            context,
        )?;
        Ok(PinMessageUpdate {
            target_sent_timestamp,
            author: author.clone(),
            _limit_construction_to_module: (),
        })
    }
}

impl<C: ReportUnusualTimestamp> TryIntoWith<PinDetails, C> for PinDetailsProto {
    type Error = PinMessageError;

    fn try_into_with(self, context: &C) -> Result<PinDetails, Self::Error> {
        let PinDetailsProto {
            pinnedAtTimestamp,
            pinExpiry,
            special_fields: _,
        } = self;
        let pinned_at =
            Timestamp::from_millis(pinnedAtTimestamp, "PinDetails.pinAtTimestamp", context)?;
        let expires = match pinExpiry {
            Some(PinExpiryProto::PinExpiresAtTimestamp(expiry)) => {
                let expiry = Timestamp::from_millis(
                    expiry,
                    "PinDetails.pinExpiry.pinExpiresAtTimestamp",
                    context,
                )?;
                if expiry < pinned_at {
                    return Err(PinMessageError::ExpiresBeforeBeingPinned);
                }
                PinExpiry::At(expiry)
            }
            Some(PinExpiryProto::PinNeverExpires(true)) => PinExpiry::Never,
            None | Some(PinExpiryProto::PinNeverExpires(false)) => {
                return Err(PinMessageError::ExpirationNotSet);
            }
        };
        Ok(PinDetails {
            pinned_at,
            expires,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::test_case;

    use super::*;
    use crate::backup::recipient::FullRecipientData;
    use crate::backup::testutil::TestContext;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;

    impl PinExpiryProto {
        pub(crate) fn test_data() -> Self {
            PinExpiryProto::PinExpiresAtTimestamp(MillisecondsSinceEpoch::TEST_VALUE.0 + 1)
        }
    }

    impl PinDetailsProto {
        pub(crate) fn test_data() -> Self {
            Self {
                pinnedAtTimestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                pinExpiry: Some(PinExpiryProto::test_data()),
                special_fields: Default::default(),
            }
        }
    }

    impl PinDetails {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                pinned_at: Timestamp::test_value(),
                expires: PinExpiry::At(Timestamp::from_millis_for_testing(
                    MillisecondsSinceEpoch::TEST_VALUE.0 + 1,
                )),
                _limit_construction_to_module: (),
            }
        }
    }

    impl PinMessageUpdateProto {
        pub(crate) fn test_data() -> Self {
            Self {
                targetSentTimestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                authorId: TestContext::SELF_ID.0,
                special_fields: Default::default(),
            }
        }
    }

    impl PinMessageUpdate<FullRecipientData> {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                target_sent_timestamp: Timestamp::test_value(),
                author: TestContext::test_recipient().clone(), // corresponds to Self
                _limit_construction_to_module: (),
            }
        }
    }

    #[test_case(|_| {} => Ok(()); "happy path")]
    #[test_case(|x| x.targetSentTimestamp = Timestamp::INVALID_TIMESTAMP_MS =>
        Err(PinMessageError::InvalidTimestamp(TimestampError("PinMessageUpdate.targetSentTimestamp", Timestamp::INVALID_TIMESTAMP_MS)));
        "invalid timestamp")]
    #[test_case(|x| x.authorId = TestContext::NONEXISTENT_ID.0 => Err(PinMessageError::UnknownAuthorId); "missing author")]
    #[test_case(|x| x.authorId = TestContext::SELF_ID.0 => Ok(()); "author is self")]
    #[test_case(|x| x.authorId = TestContext::CONTACT_ID.0 => Ok(()); "author is contact")]
    #[test_case(|x| x.authorId = TestContext::GROUP_ID.0 => Err(PinMessageError::InvalidAuthorId); "author is group")]
    #[test_case(|x| x.authorId = TestContext::CALL_LINK_ID.0 => Err(PinMessageError::InvalidAuthorId); "author is call link")]
    #[test_case(|x| x.authorId = TestContext::RELEASE_NOTES_ID.0 => Err(PinMessageError::InvalidAuthorId); "author is release notes")]
    fn pin_message_update(modify: fn(&mut PinMessageUpdateProto)) -> Result<(), PinMessageError> {
        let mut update = PinMessageUpdateProto::test_data();
        modify(&mut update);
        update.try_into_with(&TestContext::default()).map(|_| ())
    }

    #[test]
    fn pin_message_update_success() {
        let actual = PinMessageUpdateProto::test_data()
            .try_into_with(&TestContext::default())
            .expect("valid test data");
        assert_eq!(actual, PinMessageUpdate::from_proto_test_data())
    }

    #[test_case(|_| {} => Ok(()); "happy path")]
    #[test_case(|x| x.pinnedAtTimestamp = Timestamp::INVALID_TIMESTAMP_MS =>
        Err(PinMessageError::InvalidTimestamp(TimestampError("PinDetails.pinAtTimestamp", Timestamp::INVALID_TIMESTAMP_MS)));
        "invalid timestamp")]
    #[test_case(|x| x.pinExpiry = None => Err(PinMessageError::ExpirationNotSet); "expiry not set")]
    #[test_case(|x| x.pinExpiry = Some(PinExpiryProto::PinExpiresAtTimestamp(Timestamp::INVALID_TIMESTAMP_MS)) =>
        Err(PinMessageError::InvalidTimestamp(TimestampError("PinDetails.pinExpiry.pinExpiresAtTimestamp", Timestamp::INVALID_TIMESTAMP_MS)));
        "invalid expiry timestamp")]
    #[test_case(|x| x.pinExpiry = Some(PinExpiryProto::PinNeverExpires(false)) => Err(PinMessageError::ExpirationNotSet); "expires never is false")]
    #[test_case(|x| {
        x.pinnedAtTimestamp = Timestamp::MAX_SAFE_TIMESTAMP_MS;
        x.pinExpiry = Some(PinExpiryProto::PinExpiresAtTimestamp(Timestamp::MAX_SAFE_TIMESTAMP_MS-1));
    } => Err(PinMessageError::ExpiresBeforeBeingPinned); "expires before being pinned")]
    fn pin_details(modify: fn(&mut PinDetailsProto)) -> Result<(), PinMessageError> {
        let mut message = PinDetailsProto::test_data();
        modify(&mut message);
        message.try_into_with(&TestContext::default()).map(|_| ())
    }

    #[test]
    fn pin_details_success() {
        let actual = PinDetailsProto::test_data()
            .try_into_with(&TestContext::default())
            .expect("valid test data");
        assert_eq!(actual, PinDetails::from_proto_test_data())
    }

    #[test]
    fn pin_details_concrete_expiration() {
        let original = PinDetailsProto {
            pinExpiry: Some(PinExpiryProto::PinExpiresAtTimestamp(42)),
            ..PinDetailsProto::default()
        };
        let actual = original
            .try_into_with(&TestContext::default())
            .expect("valid test data");
        assert_matches!(actual.expires, PinExpiry::At(timestamp) => {
            assert_eq!(timestamp.as_millis(), 42)
        });
    }

    #[test]
    fn pin_details_never_expires() {
        let original = PinDetailsProto {
            pinExpiry: Some(PinExpiryProto::PinNeverExpires(true)),
            ..PinDetailsProto::default()
        };
        let actual = original
            .try_into_with(&TestContext::default())
            .expect("valid test data");
        assert_matches!(actual.expires, PinExpiry::Never);
    }
}
