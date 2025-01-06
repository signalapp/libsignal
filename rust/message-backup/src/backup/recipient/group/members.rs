//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::{Aci, ServiceId, WrongKindOfServiceIdError};

use super::GroupError;
use crate::backup::serialize::{self, SerializeOrder};
use crate::backup::time::{ReportUnusualTimestamp, Timestamp};
use crate::backup::TryFromWith;
use crate::proto::backup as proto;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Role {
    Default,
    Administrator,
}

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct GroupMember {
    #[serde(serialize_with = "serialize::service_id_as_string")]
    pub user_id: Aci,
    pub role: Role,
    pub joined_at_version: u32,
    pub(super) _limit_construction_to_module: (),
}

impl SerializeOrder for GroupMember {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.user_id.cmp(&other.user_id)
    }
}

impl TryFrom<proto::group::Member> for GroupMember {
    type Error = GroupError;

    fn try_from(value: proto::group::Member) -> Result<Self, Self::Error> {
        let proto::group::Member {
            userId,
            role,
            joinedAtVersion,
            special_fields: _,
        } = value;

        let user_id = ServiceId::parse_from_service_id_binary(&userId)
            .ok_or(GroupError::MemberInvalidServiceId { which: "member" })?
            .try_into()
            .map_err(
                |e: WrongKindOfServiceIdError| GroupError::MemberInvalidAci {
                    which: "member",
                    found: e.actual,
                },
            )?;
        let role = match role.enum_value_or_default() {
            proto::group::member::Role::UNKNOWN => return Err(GroupError::MemberRoleUnknown),
            proto::group::member::Role::DEFAULT => Role::Default,
            proto::group::member::Role::ADMINISTRATOR => Role::Administrator,
        };
        let joined_at_version = joinedAtVersion;

        Ok(GroupMember {
            user_id,
            role,
            joined_at_version,
            _limit_construction_to_module: (),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct GroupMemberPendingProfileKey {
    #[serde(serialize_with = "serialize::service_id_as_string")]
    pub user_id: ServiceId,
    pub role: Role,
    pub joined_at_version: u32,
    #[serde(serialize_with = "serialize::service_id_as_string")]
    pub added_by_user_id: Aci,
    pub timestamp: Timestamp,
    pub(super) _limit_construction_to_module: (),
}

impl SerializeOrder for GroupMemberPendingProfileKey {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.user_id.cmp(&other.user_id)
    }
}

impl<C: ReportUnusualTimestamp> TryFromWith<proto::group::MemberPendingProfileKey, C>
    for GroupMemberPendingProfileKey
{
    type Error = GroupError;

    fn try_from_with(
        member: proto::group::MemberPendingProfileKey,
        context: &C,
    ) -> Result<Self, Self::Error> {
        let proto::group::MemberPendingProfileKey {
            member,
            addedByUserId,
            timestamp,
            special_fields: _,
        } = member;

        let proto::group::Member {
            userId,
            role,
            joinedAtVersion,
            special_fields: _,
        } = member
            .into_option()
            .ok_or(GroupError::MemberPendingProfileKeyMissingMember)?;

        let user_id = ServiceId::parse_from_service_id_binary(&userId).ok_or(
            GroupError::MemberInvalidServiceId {
                which: "invited member",
            },
        )?;
        let role = match role.enum_value_or_default() {
            proto::group::member::Role::UNKNOWN => return Err(GroupError::MemberRoleUnknown),
            proto::group::member::Role::DEFAULT => Role::Default,
            proto::group::member::Role::ADMINISTRATOR => Role::Administrator,
        };
        let joined_at_version = joinedAtVersion;

        let added_by_user_id = ServiceId::parse_from_service_id_binary(&addedByUserId)
            .ok_or(GroupError::MemberInvalidServiceId { which: "inviter" })?
            .try_into()
            .map_err(
                |e: WrongKindOfServiceIdError| GroupError::MemberInvalidAci {
                    which: "inviter",
                    found: e.actual,
                },
            )?;

        if added_by_user_id == user_id {
            return Err(GroupError::MemberPendingProfileKeyWasInvitedBySelf);
        }

        let timestamp = Timestamp::from_millis(timestamp, "MemberPendingProfileKey", context)?;

        Ok(GroupMemberPendingProfileKey {
            user_id,
            role,
            joined_at_version,
            added_by_user_id,
            timestamp,
            _limit_construction_to_module: (),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct GroupMemberPendingAdminApproval {
    #[serde(serialize_with = "serialize::service_id_as_string")]
    pub user_id: Aci,
    pub timestamp: Timestamp,
    pub(super) _limit_construction_to_module: (),
}

impl SerializeOrder for GroupMemberPendingAdminApproval {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.user_id.cmp(&other.user_id)
    }
}

impl<C: ReportUnusualTimestamp> TryFromWith<proto::group::MemberPendingAdminApproval, C>
    for GroupMemberPendingAdminApproval
{
    type Error = GroupError;

    fn try_from_with(
        member: proto::group::MemberPendingAdminApproval,
        context: &C,
    ) -> Result<Self, Self::Error> {
        let proto::group::MemberPendingAdminApproval {
            userId,
            timestamp,
            special_fields: _,
        } = member;

        let user_id = ServiceId::parse_from_service_id_binary(&userId)
            .ok_or(GroupError::MemberInvalidServiceId {
                which: "requesting member",
            })?
            .try_into()
            .map_err(
                |e: WrongKindOfServiceIdError| GroupError::MemberInvalidAci {
                    which: "requesting member",
                    found: e.actual,
                },
            )?;
        let timestamp = Timestamp::from_millis(timestamp, "MemberPendingAdminApproval", context)?;

        Ok(GroupMemberPendingAdminApproval {
            user_id,
            timestamp,
            _limit_construction_to_module: (),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct GroupMemberBanned {
    #[serde(serialize_with = "serialize::service_id_as_string")]
    pub user_id: ServiceId,
    pub timestamp: Timestamp,
    pub(super) _limit_construction_to_module: (),
}

impl SerializeOrder for GroupMemberBanned {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.user_id.cmp(&other.user_id)
    }
}

impl<C: ReportUnusualTimestamp> TryFromWith<proto::group::MemberBanned, C> for GroupMemberBanned {
    type Error = GroupError;

    fn try_from_with(member: proto::group::MemberBanned, context: &C) -> Result<Self, Self::Error> {
        let proto::group::MemberBanned {
            userId,
            timestamp,
            special_fields: _,
        } = member;

        let user_id = ServiceId::parse_from_service_id_binary(&userId).ok_or(
            GroupError::MemberInvalidServiceId {
                which: "banned member",
            },
        )?;
        let timestamp = Timestamp::from_millis(timestamp, "MemberBanned", context)?;

        Ok(GroupMemberBanned {
            user_id,
            timestamp,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod tests {
    use libsignal_core::{Pni, ServiceIdKind};
    use test_case::test_case;

    use super::*;
    use crate::backup::testutil::TestContext;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;
    use crate::backup::time::TimestampError;

    impl proto::group::Member {
        pub(crate) fn test_data() -> Self {
            Self {
                userId: proto::Contact::TEST_ACI.to_vec(),
                role: proto::group::member::Role::DEFAULT.into(),
                joinedAtVersion: 1,
                ..Default::default()
            }
        }
    }

    impl GroupMember {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                user_id: Aci::from_uuid_bytes(proto::Contact::TEST_ACI),
                role: Role::Default,
                joined_at_version: 1,
                _limit_construction_to_module: (),
            }
        }
    }

    #[test]
    fn valid_member() {
        assert_eq!(
            GroupMember::try_from(proto::group::Member::test_data()).expect("valid"),
            GroupMember::from_proto_test_data(),
        );
    }

    #[test_case(|x| x.userId = Pni::from_uuid_bytes(proto::Contact::TEST_PNI).service_id_binary() => Err(GroupError::MemberInvalidAci { which: "member", found: ServiceIdKind::Pni }); "PNI userId")]
    #[test_case(|x| x.userId = vec![] => Err(GroupError::MemberInvalidServiceId { which: "member" }); "empty userId")]
    #[test_case(|x| x.role = proto::group::member::Role::ADMINISTRATOR.into() => Ok(()); "administrator")]
    #[test_case(|x| x.role = proto::group::member::Role::UNKNOWN.into() => Err(GroupError::MemberRoleUnknown); "role unknown")]
    fn member(modifier: impl FnOnce(&mut proto::group::Member)) -> Result<(), GroupError> {
        let mut member = proto::group::Member::test_data();
        modifier(&mut member);
        GroupMember::try_from(member).map(|_| ())
    }

    impl proto::group::MemberPendingProfileKey {
        const INVITER_ACI: [u8; 16] = [0xa1; 16];

        pub(crate) fn test_data() -> Self {
            Self {
                member: Some(proto::group::Member::test_data()).into(),
                timestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                addedByUserId: Self::INVITER_ACI.to_vec(),
                ..Default::default()
            }
        }
    }

    impl GroupMemberPendingProfileKey {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                user_id: Aci::from_uuid_bytes(proto::Contact::TEST_ACI).into(),
                role: Role::Default,
                joined_at_version: 1,
                added_by_user_id: Aci::from_uuid_bytes(
                    proto::group::MemberPendingProfileKey::INVITER_ACI,
                ),
                timestamp: Timestamp::test_value(),
                _limit_construction_to_module: (),
            }
        }
    }

    #[test]
    fn valid_member_pending_profile_key() {
        assert_eq!(
            GroupMemberPendingProfileKey::try_from_with(
                proto::group::MemberPendingProfileKey::test_data(),
                &TestContext::default()
            )
            .expect("valid"),
            GroupMemberPendingProfileKey::from_proto_test_data(),
        );
    }

    #[test_case(|x| x.member = None.into() => Err(GroupError::MemberPendingProfileKeyMissingMember); "missing member")]
    #[test_case(|x| x.member.as_mut().unwrap().userId = Pni::from_uuid_bytes(proto::Contact::TEST_PNI).service_id_binary() => Ok(()); "PNI userId")]
    #[test_case(|x| x.member.as_mut().unwrap().userId = vec![] => Err(GroupError::MemberInvalidServiceId { which: "invited member" }); "empty userId")]
    #[test_case(|x| x.member.as_mut().unwrap().role = proto::group::member::Role::ADMINISTRATOR.into() => Ok(()); "administrator")]
    #[test_case(|x| x.member.as_mut().unwrap().role = proto::group::member::Role::UNKNOWN.into() => Err(GroupError::MemberRoleUnknown); "role unknown")]
    #[test_case(|x| x.addedByUserId = Pni::from_uuid_bytes(proto::Contact::TEST_PNI).service_id_binary() => Err(GroupError::MemberInvalidAci { which: "inviter", found: ServiceIdKind::Pni }); "PNI inviter")]
    #[test_case(|x| x.addedByUserId = vec![] => Err(GroupError::MemberInvalidServiceId { which: "inviter" }); "empty inviter")]
    #[test_case(|x| x.addedByUserId = proto::Contact::TEST_ACI.to_vec() => Err(GroupError::MemberPendingProfileKeyWasInvitedBySelf); "self-invite")]
    #[test_case(
        |x| x.timestamp = MillisecondsSinceEpoch::FAR_FUTURE.0 =>
        Err(GroupError::InvalidTimestamp(TimestampError("MemberPendingProfileKey", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid timestamp"
    )]
    fn member_pending_profile_key(
        modifier: impl FnOnce(&mut proto::group::MemberPendingProfileKey),
    ) -> Result<(), GroupError> {
        let mut member = proto::group::MemberPendingProfileKey::test_data();
        modifier(&mut member);
        GroupMemberPendingProfileKey::try_from_with(member, &TestContext::default()).map(|_| ())
    }

    impl proto::group::MemberPendingAdminApproval {
        pub(crate) fn test_data() -> Self {
            Self {
                userId: proto::Contact::TEST_ACI.to_vec(),
                timestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                ..Default::default()
            }
        }
    }

    impl GroupMemberPendingAdminApproval {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                user_id: Aci::from_uuid_bytes(proto::Contact::TEST_ACI),
                timestamp: Timestamp::test_value(),
                _limit_construction_to_module: (),
            }
        }
    }

    #[test]
    fn valid_member_pending_admin_approval() {
        assert_eq!(
            GroupMemberPendingAdminApproval::try_from_with(
                proto::group::MemberPendingAdminApproval::test_data(),
                &TestContext::default()
            )
            .expect("valid"),
            GroupMemberPendingAdminApproval::from_proto_test_data(),
        );
    }

    #[test_case(|x| x.userId = Pni::from_uuid_bytes(proto::Contact::TEST_PNI).service_id_binary() => Err(GroupError::MemberInvalidAci { which: "requesting member", found: ServiceIdKind::Pni }); "PNI userId")]
    #[test_case(|x| x.userId = vec![] => Err(GroupError::MemberInvalidServiceId { which: "requesting member" }); "empty userId")]
    #[test_case(
        |x| x.timestamp = MillisecondsSinceEpoch::FAR_FUTURE.0 =>
        Err(GroupError::InvalidTimestamp(TimestampError("MemberPendingAdminApproval", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid timestamp"
    )]
    fn member_pending_admin_approval(
        modifier: impl FnOnce(&mut proto::group::MemberPendingAdminApproval),
    ) -> Result<(), GroupError> {
        let mut member = proto::group::MemberPendingAdminApproval::test_data();
        modifier(&mut member);
        GroupMemberPendingAdminApproval::try_from_with(member, &TestContext::default()).map(|_| ())
    }

    impl proto::group::MemberBanned {
        pub(crate) fn test_data() -> Self {
            Self {
                userId: proto::Contact::TEST_ACI.to_vec(),
                timestamp: MillisecondsSinceEpoch::TEST_VALUE.0,
                ..Default::default()
            }
        }
    }

    impl GroupMemberBanned {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                user_id: Aci::from_uuid_bytes(proto::Contact::TEST_ACI).into(),
                timestamp: Timestamp::test_value(),
                _limit_construction_to_module: (),
            }
        }
    }

    #[test]
    fn valid_member_banned() {
        assert_eq!(
            GroupMemberBanned::try_from_with(
                proto::group::MemberBanned::test_data(),
                &TestContext::default()
            )
            .expect("valid"),
            GroupMemberBanned::from_proto_test_data(),
        );
    }

    #[test_case(|x| x.userId = Pni::from_uuid_bytes(proto::Contact::TEST_PNI).service_id_binary() => Ok(()); "PNI userId")]
    #[test_case(|x| x.userId = vec![] => Err(GroupError::MemberInvalidServiceId { which: "banned member" }); "empty userId")]
    #[test_case(
        |x| x.timestamp = MillisecondsSinceEpoch::FAR_FUTURE.0 =>
        Err(GroupError::InvalidTimestamp(TimestampError("MemberBanned", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid timestamp"
    )]
    fn member_banned(
        modifier: impl FnOnce(&mut proto::group::MemberBanned),
    ) -> Result<(), GroupError> {
        let mut member = proto::group::MemberBanned::test_data();
        modifier(&mut member);
        GroupMemberBanned::try_from_with(member, &TestContext::default()).map(|_| ())
    }
}
