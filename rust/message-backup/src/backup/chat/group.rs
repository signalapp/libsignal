// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complaints about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use libsignal_protocol::{Aci, Pni, ServiceId};
use protobuf::{EnumOrUnknown, Message};

use crate::backup::time::Duration;
use crate::proto::backup::{
    self as proto, group_invitation_revoked_update, GenericGroupUpdate, GroupAdminStatusUpdate,
    GroupAnnouncementOnlyChangeUpdate, GroupAttributesAccessLevelChangeUpdate, GroupAvatarUpdate,
    GroupCreationUpdate, GroupDescriptionUpdate, GroupExpirationTimerUpdate,
    GroupInvitationAcceptedUpdate, GroupInvitationDeclinedUpdate, GroupInvitationRevokedUpdate,
    GroupInviteLinkAdminApprovalUpdate, GroupInviteLinkDisabledUpdate,
    GroupInviteLinkEnabledUpdate, GroupInviteLinkResetUpdate, GroupJoinRequestApprovalUpdate,
    GroupJoinRequestCanceledUpdate, GroupJoinRequestUpdate, GroupMemberAddedUpdate,
    GroupMemberJoinedByLinkUpdate, GroupMemberJoinedUpdate, GroupMemberLeftUpdate,
    GroupMemberRemovedUpdate, GroupMembershipAccessLevelChangeUpdate, GroupNameUpdate,
    GroupSelfInvitationRevokedUpdate, GroupSequenceOfRequestsAndCancelsUpdate,
    GroupUnknownInviteeUpdate, GroupV2MigrationDroppedMembersUpdate,
    GroupV2MigrationInvitedMembersUpdate, GroupV2MigrationSelfInvitedUpdate,
    GroupV2MigrationUpdate, SelfInvitedOtherUserToGroupUpdate, SelfInvitedToGroupUpdate,
};

/// Validated version of [`proto::group_change_chat_update::update::Update`].
#[allow(clippy::enum_variant_names)] // names taken from proto message.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum GroupChatUpdate {
    GenericGroupUpdate,
    GroupCreationUpdate,
    GroupNameUpdate,
    GroupAvatarUpdate,
    GroupDescriptionUpdate,
    GroupMembershipAccessLevelChangeUpdate,
    GroupAttributesAccessLevelChangeUpdate,
    GroupAnnouncementOnlyChangeUpdate,
    GroupAdminStatusUpdate,
    GroupMemberLeftUpdate,
    GroupMemberRemovedUpdate,
    SelfInvitedToGroupUpdate,
    SelfInvitedOtherUserToGroupUpdate,
    GroupUnknownInviteeUpdate,
    GroupInvitationAcceptedUpdate,
    GroupInvitationDeclinedUpdate,
    GroupMemberJoinedUpdate,
    GroupMemberAddedUpdate,
    GroupSelfInvitationRevokedUpdate,
    GroupInvitationRevokedUpdate,
    GroupJoinRequestUpdate,
    GroupJoinRequestApprovalUpdate,
    GroupJoinRequestCanceledUpdate,
    GroupInviteLinkResetUpdate,
    GroupInviteLinkEnabledUpdate,
    GroupInviteLinkAdminApprovalUpdate,
    GroupInviteLinkDisabledUpdate,
    GroupMemberJoinedByLinkUpdate,
    GroupV2MigrationUpdate,
    GroupV2MigrationSelfInvitedUpdate,
    GroupV2MigrationInvitedMembersUpdate,
    GroupV2MigrationDroppedMembersUpdate,
    GroupSequenceOfRequestsAndCancelsUpdate,
    GroupExpirationTimerUpdate,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
/// group update: {message}.{field_name}: {field_error}
pub struct GroupUpdateError {
    pub message: &'static str,
    pub field_name: &'static str,
    pub field_error: GroupUpdateFieldError,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum GroupUpdateFieldError {
    /// invalid ACI
    InvalidAci,
    /// invalid binary service ID
    InvalidServiceId,
    /// invitee has {0}
    Invitee(InviteeError),
    /// accessLevel is {0}
    AccessLevelInvalid(&'static str),
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum InviteeError {
    /// invalid inviter ACI
    InviterAci,
    /// invalid ACI for invitee
    InviteeAci,
    /// invalid PNI for invitee
    InviteePni,
}

enum ValidateFieldValue {
    IgnoredField,
    OptionalAci(Option<Vec<u8>>),
    Aci(Vec<u8>),
    ExpiresInMs(u32),
    ServiceId(Vec<u8>),
    Invitees(Vec<group_invitation_revoked_update::Invitee>),
    AccessLevel(EnumOrUnknown<proto::GroupV2AccessLevel>),
}

impl ValidateFieldValue {
    /// Produces [`ValidateFieldValue::IgnoredField`].
    ///
    /// This exists so that call sites can use `ignore::<T>(x)` to both ignore
    /// the value `x` and also add a compile-time assertion of its type that
    /// will break if it changes later.
    #[inline]
    fn ignore<T>(_: T) -> Self {
        Self::IgnoredField
    }
}

impl ValidateFieldValue {
    fn check_value(self) -> Result<(), GroupUpdateFieldError> {
        match self {
            Self::IgnoredField | Self::OptionalAci(None) => (),
            Self::OptionalAci(Some(aci)) | Self::Aci(aci) => {
                let _: Aci = aci
                    .try_into()
                    .map(Aci::from_uuid_bytes)
                    .map_err(|_| GroupUpdateFieldError::InvalidAci)?;
            }
            Self::ExpiresInMs(ms) => {
                let _: Duration = Duration::from_millis(ms.into());
            }
            Self::ServiceId(id) => {
                let _: ServiceId = ServiceId::parse_from_service_id_binary(&id)
                    .ok_or(GroupUpdateFieldError::InvalidServiceId)?;
            }
            Self::Invitees(invitees) => invitees
                .into_iter()
                .try_for_each(
                    |group_invitation_revoked_update::Invitee {
                         inviterAci,
                         inviteeAci,
                         inviteePni,
                         special_fields: _,
                     }| {
                        let _: Option<Aci> = inviterAci
                            .map(|bytes| bytes.try_into().map(Aci::from_uuid_bytes))
                            .transpose()
                            .map_err(|_| InviteeError::InviterAci)?;
                        let _: Option<Aci> = inviteeAci
                            .map(|bytes| bytes.try_into().map(Aci::from_uuid_bytes))
                            .transpose()
                            .map_err(|_| InviteeError::InviteeAci)?;
                        let _: Option<Pni> = inviteePni
                            .map(|bytes| bytes.try_into().map(Pni::from_uuid_bytes))
                            .transpose()
                            .map_err(|_| InviteeError::InviteePni)?;
                        Ok::<_, InviteeError>(())
                    },
                )
                .map_err(GroupUpdateFieldError::Invitee)?,
            Self::AccessLevel(access_level) => match access_level.enum_value_or_default() {
                proto::GroupV2AccessLevel::UNKNOWN => {
                    return Err(GroupUpdateFieldError::AccessLevelInvalid("UNKNOWN"))
                }
                proto::GroupV2AccessLevel::UNSATISFIABLE => {
                    return Err(GroupUpdateFieldError::AccessLevelInvalid("UNSATISFIABLE"))
                }
                proto::GroupV2AccessLevel::ADMINISTRATOR
                | proto::GroupV2AccessLevel::ANY
                | proto::GroupV2AccessLevel::MEMBER => (),
            },
        };
        Ok(())
    }
}

impl TryFrom<proto::group_change_chat_update::update::Update> for GroupChatUpdate {
    type Error = GroupUpdateError;

    fn try_from(
        item: proto::group_change_chat_update::update::Update,
    ) -> Result<Self, Self::Error> {
        use crate::proto::backup::group_change_chat_update::update::Update;
        match item {
            Update::GenericGroupUpdate(m) => m.try_into(),
            Update::GroupCreationUpdate(m) => m.try_into(),
            Update::GroupNameUpdate(m) => m.try_into(),
            Update::GroupAvatarUpdate(m) => m.try_into(),
            Update::GroupDescriptionUpdate(m) => m.try_into(),
            Update::GroupMembershipAccessLevelChangeUpdate(m) => m.try_into(),
            Update::GroupAttributesAccessLevelChangeUpdate(m) => m.try_into(),
            Update::GroupAnnouncementOnlyChangeUpdate(m) => m.try_into(),
            Update::GroupAdminStatusUpdate(m) => m.try_into(),
            Update::GroupMemberLeftUpdate(m) => m.try_into(),
            Update::GroupMemberRemovedUpdate(m) => m.try_into(),
            Update::SelfInvitedToGroupUpdate(m) => m.try_into(),
            Update::SelfInvitedOtherUserToGroupUpdate(m) => m.try_into(),
            Update::GroupUnknownInviteeUpdate(m) => m.try_into(),
            Update::GroupInvitationAcceptedUpdate(m) => m.try_into(),
            Update::GroupInvitationDeclinedUpdate(m) => m.try_into(),
            Update::GroupMemberJoinedUpdate(m) => m.try_into(),
            Update::GroupMemberAddedUpdate(m) => m.try_into(),
            Update::GroupSelfInvitationRevokedUpdate(m) => m.try_into(),
            Update::GroupInvitationRevokedUpdate(m) => m.try_into(),
            Update::GroupJoinRequestUpdate(m) => m.try_into(),
            Update::GroupJoinRequestApprovalUpdate(m) => m.try_into(),
            Update::GroupJoinRequestCanceledUpdate(m) => m.try_into(),
            Update::GroupInviteLinkResetUpdate(m) => m.try_into(),
            Update::GroupInviteLinkEnabledUpdate(m) => m.try_into(),
            Update::GroupInviteLinkAdminApprovalUpdate(m) => m.try_into(),
            Update::GroupInviteLinkDisabledUpdate(m) => m.try_into(),
            Update::GroupMemberJoinedByLinkUpdate(m) => m.try_into(),
            Update::GroupV2MigrationUpdate(m) => m.try_into(),
            Update::GroupV2MigrationSelfInvitedUpdate(m) => m.try_into(),
            Update::GroupV2MigrationInvitedMembersUpdate(m) => m.try_into(),
            Update::GroupV2MigrationDroppedMembersUpdate(m) => m.try_into(),
            Update::GroupSequenceOfRequestsAndCancelsUpdate(m) => m.try_into(),
            Update::GroupExpirationTimerUpdate(m) => m.try_into(),
        }
    }
}

/// Implements `TryFrom<$message>` for [`GroupChatUpdate`].
///
/// The macro takes a sequence of [`ValidateFieldValue`] expressions. The
/// generated [`TryFrom::try_from`] implementation calls
/// [`ValidateFieldValue::check_value`] for each one in sequence. If they all
/// succeed, the appropriate variant of `GroupChatUpdate` is produced. Otherwise
/// the first error is returned. Invocations of this macro need to list all
/// fields in `$message` (besides `special_fields`), otherwise compilation will
/// fail due to inexhaustive pattern matching.
macro_rules! impl_try_from_with_group_change {
    ($message:ident, $($value_fn:ident $(::<$field_type:ty>)? ($field:ident)),*) => {
        impl TryFrom<$message> for GroupChatUpdate {
            type Error = GroupUpdateError;
            fn try_from(
                message: $message,
            ) -> Result<Self, Self::Error> {
                let $message {
                    $($field,)*
                    special_fields: _
                    // Don't use .. so that if a field isn't named, the struct
                    // destructuring  will be incomplete.
                } = message;

                $(
                    ValidateFieldValue::$value_fn $(::<$field_type>)? ($field).check_value().map_err(|field_error| GroupUpdateError {
                        message: $message::NAME,
                        field_name: stringify!($field),
                        field_error,
                    })?;
                )*

                Ok(GroupChatUpdate::$message)
            }
        }
    };
}

impl_try_from_with_group_change!(GenericGroupUpdate, OptionalAci(updaterAci));
impl_try_from_with_group_change!(GroupCreationUpdate, OptionalAci(updaterAci));
impl_try_from_with_group_change!(
    GroupNameUpdate,
    OptionalAci(updaterAci),
    ignore::<Option<String>>(newGroupName)
);
impl_try_from_with_group_change!(
    GroupAvatarUpdate,
    OptionalAci(updaterAci),
    ignore::<bool>(wasRemoved)
);
impl_try_from_with_group_change!(
    GroupDescriptionUpdate,
    OptionalAci(updaterAci),
    ignore::<Option<String>>(newDescription)
);
impl_try_from_with_group_change!(
    GroupMembershipAccessLevelChangeUpdate,
    OptionalAci(updaterAci),
    AccessLevel(accessLevel)
);
impl_try_from_with_group_change!(
    GroupAttributesAccessLevelChangeUpdate,
    OptionalAci(updaterAci),
    AccessLevel(accessLevel)
);
impl_try_from_with_group_change!(
    GroupAnnouncementOnlyChangeUpdate,
    OptionalAci(updaterAci),
    ignore::<bool>(isAnnouncementOnly)
);
impl_try_from_with_group_change!(
    GroupAdminStatusUpdate,
    OptionalAci(updaterAci),
    Aci(memberAci),
    ignore::<bool>(wasAdminStatusGranted)
);
impl_try_from_with_group_change!(GroupMemberLeftUpdate, Aci(aci));
impl_try_from_with_group_change!(
    GroupMemberRemovedUpdate,
    OptionalAci(removerAci),
    Aci(removedAci)
);
impl_try_from_with_group_change!(SelfInvitedToGroupUpdate, OptionalAci(inviterAci));
impl_try_from_with_group_change!(
    SelfInvitedOtherUserToGroupUpdate,
    ServiceId(inviteeServiceId)
);
impl_try_from_with_group_change!(
    GroupUnknownInviteeUpdate,
    OptionalAci(inviterAci),
    ignore::<u32>(inviteeCount)
);
impl_try_from_with_group_change!(
    GroupInvitationAcceptedUpdate,
    OptionalAci(inviterAci),
    Aci(newMemberAci)
);
impl_try_from_with_group_change!(
    GroupInvitationDeclinedUpdate,
    OptionalAci(inviterAci),
    OptionalAci(inviteeAci)
);
impl_try_from_with_group_change!(GroupMemberJoinedUpdate, Aci(newMemberAci));
impl_try_from_with_group_change!(
    GroupMemberAddedUpdate,
    OptionalAci(updaterAci),
    Aci(newMemberAci),
    OptionalAci(inviterAci),
    // TODO check that this field doesn't affect the validity of other fields in
    // the message.
    ignore::<bool>(hadOpenInvitation)
);
impl_try_from_with_group_change!(GroupSelfInvitationRevokedUpdate, OptionalAci(revokerAci));
impl_try_from_with_group_change!(
    GroupInvitationRevokedUpdate,
    OptionalAci(updaterAci),
    Invitees(invitees)
);
impl_try_from_with_group_change!(GroupJoinRequestUpdate, Aci(requestorAci));
impl_try_from_with_group_change!(
    GroupJoinRequestApprovalUpdate,
    Aci(requestorAci),
    OptionalAci(updaterAci),
    ignore::<bool>(wasApproved)
);
impl_try_from_with_group_change!(GroupJoinRequestCanceledUpdate, Aci(requestorAci));
impl_try_from_with_group_change!(GroupInviteLinkResetUpdate, OptionalAci(updaterAci));
impl_try_from_with_group_change!(
    GroupInviteLinkEnabledUpdate,
    OptionalAci(updaterAci),
    ignore::<bool>(linkRequiresAdminApproval)
);
impl_try_from_with_group_change!(
    GroupInviteLinkAdminApprovalUpdate,
    OptionalAci(updaterAci),
    ignore::<bool>(linkRequiresAdminApproval)
);
impl_try_from_with_group_change!(GroupInviteLinkDisabledUpdate, OptionalAci(updaterAci));
impl_try_from_with_group_change!(GroupMemberJoinedByLinkUpdate, Aci(newMemberAci));
impl_try_from_with_group_change!(GroupV2MigrationUpdate,);
impl_try_from_with_group_change!(GroupV2MigrationSelfInvitedUpdate,);
impl_try_from_with_group_change!(
    GroupV2MigrationInvitedMembersUpdate,
    ignore::<u32>(invitedMembersCount)
);
impl_try_from_with_group_change!(
    GroupV2MigrationDroppedMembersUpdate,
    ignore::<u32>(droppedMembersCount)
);
impl_try_from_with_group_change!(
    GroupSequenceOfRequestsAndCancelsUpdate,
    Aci(requestorAci),
    ignore::<u32>(count)
);
impl_try_from_with_group_change!(
    GroupExpirationTimerUpdate,
    OptionalAci(updaterAci),
    ExpiresInMs(expiresInMs)
);

#[cfg(test)]
mod test {
    use test_case::test_case;

    use crate::proto::backup::{group_change_chat_update, group_invitation_revoked_update};

    use super::*;

    const ACI_BYTES: [u8; 16] = [0xaa; 16];
    const ACI: Aci = Aci::from_uuid_bytes(ACI_BYTES);

    const PNI_BYTES: [u8; 16] = [0xbb; 16];
    const PNI: Pni = Pni::from_uuid_bytes(PNI_BYTES);

    fn valid_invitees() -> Vec<group_invitation_revoked_update::Invitee> {
        vec![
            group_invitation_revoked_update::Invitee::default(),
            group_invitation_revoked_update::Invitee {
                inviterAci: Some(ACI_BYTES.into()),
                inviteePni: Some(PNI_BYTES.into()),
                ..Default::default()
            },
        ]
    }

    fn invitee_invalid_aci() -> Vec<group_invitation_revoked_update::Invitee> {
        vec![group_invitation_revoked_update::Invitee {
            inviteeAci: Some(vec![]),
            ..Default::default()
        }]
    }

    fn invitee_pni_service_id_binary() -> Vec<group_invitation_revoked_update::Invitee> {
        vec![group_invitation_revoked_update::Invitee {
            inviteePni: Some(PNI.service_id_binary()),
            ..Default::default()
        }]
    }

    use GroupUpdateFieldError::*;

    #[test_case(ValidateFieldValue::IgnoredField, Ok(()))]
    #[test_case(ValidateFieldValue::Aci(vec![]), Err(InvalidAci))]
    #[test_case(ValidateFieldValue::Aci(ACI.service_id_binary()), Ok(()))]
    #[test_case(ValidateFieldValue::OptionalAci(Some(ACI.service_id_binary())), Ok(()))]
    #[test_case(ValidateFieldValue::OptionalAci(None), Ok(()))]
    #[test_case(ValidateFieldValue::OptionalAci(Some(vec![])), Err(InvalidAci))]
    #[test_case(ValidateFieldValue::Aci(PNI.service_id_binary()), Err(InvalidAci))]
    #[test_case(ValidateFieldValue::OptionalAci(Some(PNI.service_id_binary())), Err(InvalidAci))]
    #[test_case(ValidateFieldValue::ServiceId(ACI.service_id_binary()), Ok(()))]
    #[test_case(ValidateFieldValue::ServiceId(vec![]), Err(InvalidServiceId))]
    #[test_case(ValidateFieldValue::Invitees(valid_invitees()), Ok(()))]
    #[test_case(ValidateFieldValue::Invitees(vec![]), Ok(()))]
    #[test_case(
        ValidateFieldValue::Invitees(invitee_invalid_aci()),
        Err(Invitee(InviteeError::InviteeAci))
    )]
    #[test_case(
        ValidateFieldValue::Invitees(invitee_pni_service_id_binary()),
        Err(Invitee(InviteeError::InviteePni))
    )]
    #[test_case(
        ValidateFieldValue::AccessLevel(EnumOrUnknown::default()),
        Err(AccessLevelInvalid("UNKNOWN"))
    )]
    #[test_case(
        ValidateFieldValue::AccessLevel(proto::GroupV2AccessLevel::UNSATISFIABLE.into()),
        Err(AccessLevelInvalid("UNSATISFIABLE"))
    )]
    fn validate_field_value(
        field: ValidateFieldValue,
        expected: Result<(), GroupUpdateFieldError>,
    ) {
        assert_eq!(field.check_value(), expected)
    }

    #[test]
    fn group_invitation_revoked_update_error_is_legible() {
        let invalid = group_change_chat_update::update::Update::GroupInvitationRevokedUpdate(
            GroupInvitationRevokedUpdate {
                invitees: vec![group_invitation_revoked_update::Invitee {
                    // present but empty inviter ACI field
                    inviterAci: Some(vec![]),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let err = GroupChatUpdate::try_from(invalid).expect_err("unexpected success");
        assert_eq!(
            err.to_string(),
            "group update: GroupInvitationRevokedUpdate.invitees: invitee has invalid inviter ACI"
        );
    }
}
