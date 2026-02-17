//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::TryIntoWith;
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::{DestinationKind, MinimalRecipientData};
use crate::proto::backup::AdminDeletedMessage as AdminDeletedMessageProto;

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct AdminDeletedMessage<Recipient> {
    pub admin: Recipient,
    _limit_construction_to_module: (),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum AdminDeletedMessageError {
    /// admin id is not present
    UnknownAdminId,
    /// admin id is not self nor contact: {0:?}
    AdminNotSelfNotContact(RecipientId, DestinationKind),
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R>>
    TryIntoWith<AdminDeletedMessage<R>, C> for AdminDeletedMessageProto
{
    type Error = AdminDeletedMessageError;

    fn try_into_with(self, context: &C) -> Result<AdminDeletedMessage<R>, Self::Error> {
        let AdminDeletedMessageProto {
            adminId,
            special_fields: _,
        } = self;
        let admin_id = RecipientId(adminId);
        let Some((admin_data, admin)) = context.lookup_pair(&admin_id) else {
            return Err(Self::Error::UnknownAdminId);
        };
        match admin_data {
            MinimalRecipientData::Self_ | MinimalRecipientData::Contact { .. } => {}
            MinimalRecipientData::Group { .. }
            | MinimalRecipientData::DistributionList { .. }
            | MinimalRecipientData::ReleaseNotes
            | MinimalRecipientData::CallLink { .. } => {
                return Err(Self::Error::AdminNotSelfNotContact(
                    admin_id,
                    *admin_data.as_ref(),
                ));
            }
        }
        Ok(AdminDeletedMessage {
            admin: admin.clone(),
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;
    use crate::backup::recipient::FullRecipientData;
    use crate::backup::testutil::TestContext;

    impl AdminDeletedMessageProto {
        pub(crate) fn test_data() -> Self {
            Self {
                adminId: TestContext::SELF_ID.0,
                special_fields: Default::default(),
            }
        }
    }

    impl AdminDeletedMessage<FullRecipientData> {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                admin: TestContext::test_recipient().clone(), // corresponds to Self
                _limit_construction_to_module: (),
            }
        }
    }

    #[test_case(|_| {} => Ok(()); "happy path")]
    #[test_case(|x| x.adminId = TestContext::NONEXISTENT_ID.0 =>
        Err(AdminDeletedMessageError::UnknownAdminId); "missing admin")]
    #[test_case(|x| x.adminId = TestContext::SELF_ID.0 => Ok(()); "admin is self")]
    #[test_case(|x| x.adminId = TestContext::CONTACT_ID.0 => Ok(()); "admin is contact")]
    #[test_case(|x| x.adminId = TestContext::GROUP_ID.0 =>
        Err(AdminDeletedMessageError::AdminNotSelfNotContact(
                RecipientId(TestContext::GROUP_ID.0),
                DestinationKind::Group
            )); "admin is group")]
    #[test_case(|x| x.adminId = TestContext::CALL_LINK_ID.0 =>
        Err(AdminDeletedMessageError::AdminNotSelfNotContact(
                RecipientId(TestContext::CALL_LINK_ID.0),
                DestinationKind::CallLink
            )); "admin is call link")]
    #[test_case(|x| x.adminId = TestContext::RELEASE_NOTES_ID.0 =>
        Err(AdminDeletedMessageError::AdminNotSelfNotContact(
                RecipientId(TestContext::RELEASE_NOTES_ID.0),
                DestinationKind::ReleaseNotes
            )); "admin is release notes")]
    fn admin_deleted_message(
        modify: fn(&mut AdminDeletedMessageProto),
    ) -> Result<(), AdminDeletedMessageError> {
        let mut message = AdminDeletedMessageProto::test_data();
        modify(&mut message);
        message.try_into_with(&TestContext::default()).map(|_| ())
    }

    #[test]
    fn admin_deleted_message_success() {
        let actual = AdminDeletedMessageProto::test_data()
            .try_into_with(&TestContext::default())
            .expect("valid test data");
        assert_eq!(actual, AdminDeletedMessage::from_proto_test_data())
    }
}
