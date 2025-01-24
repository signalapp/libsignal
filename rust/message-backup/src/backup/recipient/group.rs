//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complains about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use itertools::Itertools as _;
use libsignal_core::ServiceIdKind;
use zkgroup::GroupMasterKeyBytes;

use crate::backup::serialize::{self, UnorderedList};
use crate::backup::time::{Duration, ReportUnusualTimestamp, TimestampError};
use crate::backup::{likely_empty, TryFromWith, TryIntoWith};
use crate::proto::backup as proto;

mod members;
use members::*;

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct GroupSnapshot {
    pub title: Option<String>,
    pub description: Option<String>,
    pub avatar_url: String,
    pub disappearing_messages_timer: Option<Duration>,
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub access_control_attributes: proto::group::access_control::AccessRequired,
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub access_control_members: proto::group::access_control::AccessRequired,
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub access_control_add_from_invite_link: proto::group::access_control::AccessRequired,
    pub version: u32,
    pub members: UnorderedList<GroupMember>,
    pub members_pending_profile_key: UnorderedList<GroupMemberPendingProfileKey>,
    pub members_pending_admin_approval: UnorderedList<GroupMemberPendingAdminApproval>,
    #[serde(with = "hex")]
    pub invite_link_password: Vec<u8>,
    pub announcements_only: bool,
    pub members_banned: UnorderedList<GroupMemberBanned>,
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum GroupError {
    /// master key has wrong number of bytes
    InvalidMasterKey,
    /// missing snapshot
    MissingSnapshot,
    /// {which} blob missing content
    BlobMissingContent { which: &'static str },
    /// {which} blob contained {unexpected} content
    BlobWrongContent {
        which: &'static str,
        unexpected: &'static str,
    },
    /// access control for {which} was {access:?}
    InvalidAccess {
        which: &'static str,
        access: proto::group::access_control::AccessRequired,
    },
    /// {which} user ID was not a valid service ID
    MemberInvalidServiceId { which: &'static str },
    /// {which} user ID should be an ACI, but was {found}
    MemberInvalidAci {
        which: &'static str,
        found: ServiceIdKind,
    },
    /// member role was UNKNOWN
    MemberRoleUnknown,
    /// member profile key was not valid
    MemberInvalidProfileKey,
    /// MemberPendingProfileKey missing nested Member info
    MemberPendingProfileKeyMissingMember,
    /// MemberPendingProfileKey has a profile key
    MemberPendingProfileKeyHasProfileKey,
    /// MemberPendingProfileKey's userId and addedByUserId are the same
    MemberPendingProfileKeyWasInvitedBySelf,
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
}

impl proto::group::group_attribute_blob::Content {
    fn field_name(&self) -> &'static str {
        match self {
            proto::group::group_attribute_blob::Content::Title(_) => "title",
            proto::group::group_attribute_blob::Content::Avatar(_) => "avatar",
            proto::group::group_attribute_blob::Content::DisappearingMessagesDuration(_) => {
                "disappearingMessagesDuration"
            }
            proto::group::group_attribute_blob::Content::DescriptionText(_) => "descriptionText",
        }
    }
}

impl<C: ReportUnusualTimestamp> TryFromWith<proto::group::GroupSnapshot, C> for GroupSnapshot {
    type Error = GroupError;

    fn try_from_with(value: proto::group::GroupSnapshot, context: &C) -> Result<Self, Self::Error> {
        let proto::group::GroupSnapshot {
            title,
            description,
            avatarUrl,
            disappearingMessagesTimer,
            accessControl,
            version,
            members,
            membersPendingProfileKey,
            membersPendingAdminApproval,
            inviteLinkPassword,
            announcements_only,
            members_banned,
            special_fields: _,
        } = value;

        let title = title
            .into_option()
            .map(|blob| {
                let proto::group::GroupAttributeBlob {
                    content,
                    special_fields: _,
                } = blob;
                match content {
                    Some(proto::group::group_attribute_blob::Content::Title(title)) => Ok(title),
                    Some(other) => Err(GroupError::BlobWrongContent {
                        which: "title",
                        unexpected: other.field_name(),
                    }),
                    None => Err(GroupError::BlobMissingContent { which: "title" }),
                }
            })
            .transpose()?;

        let description = description
            .into_option()
            .map(|blob| {
                let proto::group::GroupAttributeBlob {
                    content,
                    special_fields: _,
                } = blob;
                match content {
                    Some(proto::group::group_attribute_blob::Content::DescriptionText(
                        description,
                    )) => Ok(description),
                    Some(other) => Err(GroupError::BlobWrongContent {
                        which: "description",
                        unexpected: other.field_name(),
                    }),
                    None => Err(GroupError::BlobMissingContent {
                        which: "description",
                    }),
                }
            })
            .transpose()?;

        let avatar_url = avatarUrl;

        let disappearing_messages_timer =
            disappearingMessagesTimer
                .into_option()
                .map(|blob| {
                    let proto::group::GroupAttributeBlob {
                        content,
                        special_fields: _,
                    } = blob;
                    match content {
                    Some(proto::group::group_attribute_blob::Content::DisappearingMessagesDuration(
                        duration,
                    )) => Ok(Duration::from_millis(duration.into())),
                    Some(other) => Err(GroupError::BlobWrongContent {
                        which: "disappearingMessagesDuration",
                        unexpected: other.field_name(),
                    }),
                    None => Err(GroupError::BlobMissingContent {
                        which: "disappearingMessagesDuration",
                    }),
                }
                })
                .transpose()?;

        let (
            access_control_attributes,
            access_control_members,
            access_control_add_from_invite_link,
        ) = {
            use proto::group::access_control::AccessRequired;

            // The group server does not seem to enforce that this field is present, which means the
            // default values are all valid.
            let proto::group::AccessControl {
                attributes,
                members,
                addFromInviteLink,
                special_fields: _,
            } = accessControl.unwrap_or_default();

            let attributes = match attributes.enum_value_or_default() {
                access @ (AccessRequired::UNKNOWN
                | AccessRequired::MEMBER
                | AccessRequired::ADMINISTRATOR) => access,
                access @ (AccessRequired::ANY | AccessRequired::UNSATISFIABLE) => {
                    return Err(GroupError::InvalidAccess {
                        which: "attributes",
                        access,
                    });
                }
            };

            let members = match members.enum_value_or_default() {
                access @ (AccessRequired::UNKNOWN
                | AccessRequired::MEMBER
                | AccessRequired::ADMINISTRATOR) => access,
                access @ (AccessRequired::ANY | AccessRequired::UNSATISFIABLE) => {
                    return Err(GroupError::InvalidAccess {
                        which: "members",
                        access,
                    });
                }
            };

            let add_from_invite_link = match addFromInviteLink.enum_value_or_default() {
                access @ (AccessRequired::UNKNOWN
                | AccessRequired::ANY
                | AccessRequired::ADMINISTRATOR
                | AccessRequired::UNSATISFIABLE) => access,
                access @ AccessRequired::MEMBER => {
                    return Err(GroupError::InvalidAccess {
                        which: "addFromInviteLink",
                        access,
                    });
                }
            };

            (attributes, members, add_from_invite_link)
        };

        let invite_link_password = inviteLinkPassword;

        let members = members
            .into_iter()
            .map(GroupMember::try_from)
            .try_collect()?;

        let members_pending_profile_key = likely_empty(membersPendingProfileKey, |iter| {
            iter.map(|m| GroupMemberPendingProfileKey::try_from_with(m, context))
                .try_collect()
        })?;

        let members_pending_admin_approval = likely_empty(membersPendingAdminApproval, |iter| {
            iter.map(|m| GroupMemberPendingAdminApproval::try_from_with(m, context))
                .try_collect()
        })?;

        let members_banned = likely_empty(members_banned, |iter| {
            iter.map(|m| GroupMemberBanned::try_from_with(m, context))
                .try_collect()
        })?;

        Ok(Self {
            title,
            description,
            avatar_url,
            disappearing_messages_timer,
            access_control_attributes,
            access_control_members,
            access_control_add_from_invite_link,
            version,
            members,
            members_pending_profile_key,
            members_pending_admin_approval,
            invite_link_password,
            announcements_only,
            members_banned,
            _limit_construction_to_module: (),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct GroupData {
    #[serde(with = "hex")]
    pub master_key: GroupMasterKeyBytes,
    pub whitelisted: bool,
    pub hide_story: bool,
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub story_send_mode: proto::group::StorySendMode,
    pub snapshot: GroupSnapshot,
    pub blocked: bool,
    _limit_construction_to_module: (),
}

impl<C: ReportUnusualTimestamp> TryFromWith<proto::Group, C> for GroupData {
    type Error = GroupError;
    fn try_from_with(value: proto::Group, context: &C) -> Result<Self, Self::Error> {
        let proto::Group {
            masterKey,
            whitelisted,
            hideStory,
            storySendMode,
            snapshot,
            blocked,
            special_fields: _,
        } = value;

        let master_key = masterKey
            .try_into()
            .map_err(|_| GroupError::InvalidMasterKey)?;

        let story_send_mode = match storySendMode.enum_value_or_default() {
            s @ (proto::group::StorySendMode::DEFAULT
            | proto::group::StorySendMode::DISABLED
            | proto::group::StorySendMode::ENABLED) => s,
        };

        let snapshot = snapshot
            .into_option()
            .ok_or(GroupError::MissingSnapshot)?
            .try_into_with(context)?;

        Ok(GroupData {
            master_key,
            whitelisted,
            hide_story: hideStory,
            story_send_mode,
            snapshot,
            blocked,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use libsignal_core::Aci;
    use test_case::test_case;

    use super::*;
    use crate::backup::testutil::TestContext;
    use crate::proto::backup::group::access_control::AccessRequired;

    impl proto::Group {
        pub(crate) const TEST_MASTER_KEY: GroupMasterKeyBytes = [0x33; 32];

        pub(crate) fn test_data() -> Self {
            Self {
                masterKey: Self::TEST_MASTER_KEY.into(),
                storySendMode: proto::group::StorySendMode::ENABLED.into(),
                snapshot: Some(proto::group::GroupSnapshot {
                    title: Some(proto::group::GroupAttributeBlob {
                        content: Some(proto::group::group_attribute_blob::Content::Title(
                            "Axolotls".to_owned(),
                        )),
                        ..Default::default()
                    })
                    .into(),
                    description: Some(proto::group::GroupAttributeBlob {
                        content: Some(
                            proto::group::group_attribute_blob::Content::DescriptionText(
                                "Endangered! :-(".to_owned(),
                            ),
                        ),
                        ..Default::default()
                    })
                    .into(),
                    avatarUrl: "axolotl.png".to_owned(),
                    disappearingMessagesTimer: Some(proto::group::GroupAttributeBlob {
                        content: Some(
                            proto::group::group_attribute_blob::Content::DisappearingMessagesDuration(
                                5000,
                            ),
                        ),
                        ..Default::default()
                    })
                    .into(),
                    accessControl: Some(proto::group::AccessControl {
                        attributes: proto::group::access_control::AccessRequired::ADMINISTRATOR.into(),
                        members: proto::group::access_control::AccessRequired::MEMBER.into(),
                        addFromInviteLink: proto::group::access_control::AccessRequired::ANY.into(),
                        ..Default::default()
                    })
                    .into(),
                    version: 5,
                    members: vec![proto::group::Member::test_data()],
                    membersPendingProfileKey: vec![
                        proto::group::MemberPendingProfileKey::test_data(),
                    ],
                    membersPendingAdminApproval: vec![
                        proto::group::MemberPendingAdminApproval::test_data(),
                    ],
                    inviteLinkPassword: vec![0x05; 5],
                    announcements_only: true,
                    members_banned: vec![proto::group::MemberBanned::test_data()],
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }
        }
    }

    impl GroupData {
        pub(crate) fn from_proto_test_data() -> Self {
            GroupData {
                master_key: proto::Group::TEST_MASTER_KEY,
                story_send_mode: proto::group::StorySendMode::ENABLED,
                whitelisted: false,
                hide_story: false,
                snapshot: GroupSnapshot {
                    title: Some("Axolotls".to_owned()),
                    description: Some("Endangered! :-(".to_owned()),
                    avatar_url: "axolotl.png".to_owned(),
                    disappearing_messages_timer: Some(Duration::from_millis(5000)),
                    access_control_attributes: AccessRequired::ADMINISTRATOR,
                    access_control_members: AccessRequired::MEMBER,
                    access_control_add_from_invite_link: AccessRequired::ANY,
                    version: 5,
                    members: vec![GroupMember::from_proto_test_data()].into(),
                    members_pending_profile_key: vec![
                        GroupMemberPendingProfileKey::from_proto_test_data(),
                    ]
                    .into(),
                    members_pending_admin_approval: vec![
                        GroupMemberPendingAdminApproval::from_proto_test_data(),
                    ]
                    .into(),
                    invite_link_password: vec![0x05; 5],
                    announcements_only: true,
                    members_banned: vec![GroupMemberBanned::from_proto_test_data()].into(),
                    _limit_construction_to_module: (),
                },
                blocked: false,
                _limit_construction_to_module: (),
            }
        }
    }

    #[test]
    fn valid_group() {
        assert_eq!(
            GroupData::try_from_with(proto::Group::test_data(), &TestContext::default())
                .expect("valid"),
            GroupData::from_proto_test_data(),
        )
    }

    #[test_case(|x| x.masterKey = vec![] => Err(GroupError::InvalidMasterKey); "empty masterKey")]
    #[test_case(|x| x.snapshot = None.into() => Err(GroupError::MissingSnapshot); "missing snapshot")]
    fn group_data(modifier: impl FnOnce(&mut proto::Group)) -> Result<(), GroupError> {
        let mut group = proto::Group::test_data();
        modifier(&mut group);
        GroupData::try_from_with(group, &TestContext::default()).map(|_| ())
    }

    #[test_case(|x| x.title = None.into() => Ok(()); "missing title")]
    #[test_case(|x| x.title = Some(Default::default()).into() => Err(GroupError::BlobMissingContent { which: "title" }); "empty title blob")]
    #[test_case(|x| x.title = x.disappearingMessagesTimer.clone() => Err(GroupError::BlobWrongContent { which: "title", unexpected: "disappearingMessagesDuration" }); "wrong title blob")]
    #[test_case(|x| x.description = None.into() => Ok(()); "missing description")]
    #[test_case(|x| x.description = Some(Default::default()).into() => Err(GroupError::BlobMissingContent { which: "description" }); "empty description blob")]
    #[test_case(|x| x.description = x.disappearingMessagesTimer.clone() => Err(GroupError::BlobWrongContent { which: "description", unexpected: "disappearingMessagesDuration" }); "wrong description blob")]
    #[test_case(|x| x.disappearingMessagesTimer = None.into() => Ok(()); "missing disappearingMessagesDuration")]
    #[test_case(|x| x.disappearingMessagesTimer = Some(Default::default()).into() => Err(GroupError::BlobMissingContent { which: "disappearingMessagesDuration" }); "empty disappearingMessagesDuration blob")]
    #[test_case(|x| x.disappearingMessagesTimer = x.title.clone() => Err(GroupError::BlobWrongContent { which: "disappearingMessagesDuration", unexpected: "title" }); "wrong disappearingMessagesDuration blob")]
    #[test_case(|x| x.accessControl = None.into() => Ok(()); "missing accessControl")]
    #[test_case(|x| x.accessControl.as_mut().unwrap().attributes = AccessRequired::ANY.into() => Err(GroupError::InvalidAccess { which: "attributes", access: AccessRequired::ANY }); "bad attributes AccessRequired")]
    #[test_case(|x| x.accessControl.as_mut().unwrap().members = AccessRequired::ANY.into() => Err(GroupError::InvalidAccess { which: "members", access: AccessRequired::ANY }); "bad members AccessRequired")]
    #[test_case(|x| x.accessControl.as_mut().unwrap().addFromInviteLink = AccessRequired::MEMBER.into() => Err(GroupError::InvalidAccess { which: "addFromInviteLink", access: AccessRequired::MEMBER }); "bad addFromInviteLink AccessRequired")]
    #[test_case(|x| x.inviteLinkPassword = vec![] => Ok(()); "empty invite link password")]
    #[test_case(|x| x.members[0].userId = vec![] => Err(GroupError::MemberInvalidServiceId { which: "member" }); "bad member")]
    fn group_snapshot(
        modifier: impl FnOnce(&mut proto::group::GroupSnapshot),
    ) -> Result<(), GroupError> {
        let mut group = proto::Group::test_data().snapshot.unwrap();
        modifier(&mut group);
        GroupSnapshot::try_from_with(group, &TestContext::default()).map(|_| ())
    }

    #[test]
    fn group_member_lists_sorted_when_serializing() {
        let aci1 = Aci::from_uuid_bytes([0x11; 16]);
        let aci2 = Aci::from_uuid_bytes([0x22; 16]);

        let group1 = GroupSnapshot {
            members: vec![
                GroupMember {
                    user_id: aci1,
                    ..GroupMember::from_proto_test_data()
                },
                GroupMember {
                    user_id: aci2,
                    ..GroupMember::from_proto_test_data()
                },
            ]
            .into(),
            members_pending_profile_key: vec![
                GroupMemberPendingProfileKey {
                    user_id: aci1.into(),
                    ..GroupMemberPendingProfileKey::from_proto_test_data()
                },
                GroupMemberPendingProfileKey {
                    user_id: aci2.into(),
                    ..GroupMemberPendingProfileKey::from_proto_test_data()
                },
            ]
            .into(),
            members_pending_admin_approval: vec![
                GroupMemberPendingAdminApproval {
                    user_id: aci1,
                    ..GroupMemberPendingAdminApproval::from_proto_test_data()
                },
                GroupMemberPendingAdminApproval {
                    user_id: aci2,
                    ..GroupMemberPendingAdminApproval::from_proto_test_data()
                },
            ]
            .into(),
            members_banned: vec![
                GroupMemberBanned {
                    user_id: aci1.into(),
                    ..GroupMemberBanned::from_proto_test_data()
                },
                GroupMemberBanned {
                    user_id: aci2.into(),
                    ..GroupMemberBanned::from_proto_test_data()
                },
            ]
            .into(),
            ..GroupData::from_proto_test_data().snapshot
        };

        let mut group2 = group1.clone();
        group2.members.0.reverse();
        group2.members_pending_profile_key.0.reverse();
        group2.members_pending_admin_approval.0.reverse();
        group2.members_banned.0.reverse();

        assert_eq!(
            serde_json::to_string_pretty(&group1).expect("valid"),
            serde_json::to_string_pretty(&group2).expect("valid"),
        );
    }
}
