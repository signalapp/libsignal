// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complaints about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use std::fmt::Debug;
use std::num::NonZeroU32;

use itertools::Itertools as _;
use libsignal_core::{Aci, Pni, ServiceId};
use macro_rules_attribute::macro_rules_derive;
use protobuf::{EnumOrUnknown, Message};

use crate::backup::serialize::UnorderedList;
use crate::backup::time::Duration;
use crate::backup::{serialize, uuid_bytes_to_aci};
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

/// Implements `TryFrom<$MESSAGE>` for [`GroupChatUpdate`].
///
/// This is a custom derive macro (applied via [`macro_rules_derive`]) that is
/// applied to the enum type `GroupChatUpdate`. It assumes each variant has
/// named fields that match the corresponding proto input message (excluding the
/// `special_fields` field). It generates a [`TryFrom::try_from`] implementation
/// that calls [`ValidateFrom::validate_from`] for each field in sequence. If
/// they all succeed, the appropriate variant of `GroupChatUpdate` is produced.
/// Otherwise the first error is returned.
macro_rules! TryFromProto {
    ($( #[$attrs:meta] )*
    pub enum GroupChatUpdate { $(
        $VariantName:ident $({
            $(
                $(#[$_attr: meta])*
                $field:ident : $typ:ty,
            )*
        })?,
    )* }) => {
        // Expand using the next match for each enum variant.
        $(TryFromProto!($VariantName, $($($field),*)? );)*
    };
    ($MESSAGE:ident, $($field:ident),* ) => {
        impl TryFrom<$MESSAGE> for GroupChatUpdate {
            type Error = GroupUpdateError;
            fn try_from(
                message: $MESSAGE,
            ) -> Result<Self, Self::Error> {
                let $MESSAGE {
                    $($field,)*
                    special_fields: _
                    // Don't use .. so that if a field isn't named, the struct
                    // destructuring will be incomplete.
                } = message;

                $(
                    #[allow(non_snake_case)]
                    let $field = ValidateFrom::validate_from($field).map_err(|field_error| GroupUpdateError {
                        message: $MESSAGE::NAME,
                        field_name: stringify!($field),
                        field_error,
                    })?;
                )*

                Ok(GroupChatUpdate::$MESSAGE {$($field),*})
            }
        }
    }

}

/// Validated version of [`proto::group_change_chat_update::update::Update`].
#[allow(clippy::enum_variant_names, non_snake_case)] // names taken from proto message.
#[derive(Debug, serde::Serialize)]
#[macro_rules_derive(TryFromProto)]
#[cfg_attr(test, derive(PartialEq))]
pub enum GroupChatUpdate {
    GenericGroupUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
    },
    GroupCreationUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
    },
    GroupNameUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        newGroupName: NoValidation<Option<String>>,
    },
    GroupAvatarUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        wasRemoved: NoValidation<bool>,
    },
    GroupDescriptionUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        newDescription: NoValidation<Option<String>>,
    },
    GroupMembershipAccessLevelChangeUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        accessLevel: AccessLevel,
    },
    GroupAttributesAccessLevelChangeUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        accessLevel: AccessLevel,
    },
    GroupAnnouncementOnlyChangeUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        isAnnouncementOnly: NoValidation<bool>,
    },
    GroupAdminStatusUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        #[serde(serialize_with = "serialize::service_id_as_string")]
        memberAci: Aci,
        wasAdminStatusGranted: NoValidation<bool>,
    },
    GroupMemberLeftUpdate {
        #[serde(serialize_with = "serialize::service_id_as_string")]
        aci: Aci,
    },
    GroupMemberRemovedUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        removerAci: Option<Aci>,
        #[serde(serialize_with = "serialize::service_id_as_string")]
        removedAci: Aci,
    },
    SelfInvitedToGroupUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        inviterAci: Option<Aci>,
    },
    SelfInvitedOtherUserToGroupUpdate {
        #[serde(serialize_with = "serialize::service_id_as_string")]
        inviteeServiceId: ServiceId,
    },
    GroupUnknownInviteeUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        inviterAci: Option<Aci>,
        inviteeCount: NonZeroU32,
    },
    GroupInvitationAcceptedUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        inviterAci: Option<Aci>,
        #[serde(serialize_with = "serialize::service_id_as_string")]
        newMemberAci: Aci,
    },
    GroupInvitationDeclinedUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        inviterAci: Option<Aci>,
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        inviteeAci: Option<Aci>,
    },
    GroupMemberJoinedUpdate {
        #[serde(serialize_with = "serialize::service_id_as_string")]
        newMemberAci: Aci,
    },
    GroupMemberAddedUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        #[serde(serialize_with = "serialize::service_id_as_string")]
        newMemberAci: Aci,
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        inviterAci: Option<Aci>,
        hadOpenInvitation: NoValidation<bool>,
    },
    GroupSelfInvitationRevokedUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        revokerAci: Option<Aci>,
    },

    GroupInvitationRevokedUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        invitees: UnorderedList<Invitee>,
    },
    GroupJoinRequestUpdate {
        #[serde(serialize_with = "serialize::service_id_as_string")]
        requestorAci: Aci,
    },
    GroupJoinRequestApprovalUpdate {
        #[serde(serialize_with = "serialize::service_id_as_string")]
        requestorAci: Aci,
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        wasApproved: NoValidation<bool>,
    },
    GroupJoinRequestCanceledUpdate {
        #[serde(serialize_with = "serialize::service_id_as_string")]
        requestorAci: Aci,
    },
    GroupInviteLinkResetUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
    },

    GroupInviteLinkEnabledUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        linkRequiresAdminApproval: NoValidation<bool>,
    },

    GroupInviteLinkAdminApprovalUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        linkRequiresAdminApproval: NoValidation<bool>,
    },
    GroupInviteLinkDisabledUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
    },
    GroupMemberJoinedByLinkUpdate {
        #[serde(serialize_with = "serialize::service_id_as_string")]
        newMemberAci: Aci,
    },
    GroupV2MigrationUpdate,
    GroupV2MigrationSelfInvitedUpdate,
    GroupV2MigrationInvitedMembersUpdate {
        invitedMembersCount: NonZeroU32,
    },
    GroupV2MigrationDroppedMembersUpdate {
        droppedMembersCount: NonZeroU32,
    },
    GroupSequenceOfRequestsAndCancelsUpdate {
        #[serde(serialize_with = "serialize::service_id_as_string")]
        requestorAci: Aci,
        count: NonZeroU32,
    },
    GroupExpirationTimerUpdate {
        #[serde(serialize_with = "serialize::optional_service_id_as_string")]
        updaterAci: Option<Aci>,
        expiresInMs: Duration,
    },
}

#[derive(Copy, Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum AccessLevel {
    Any,
    Member,
    Administrator,
}

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Invitee {
    #[serde(serialize_with = "serialize::optional_service_id_as_string")]
    pub inviter: Option<Aci>,
    #[serde(serialize_with = "serialize::optional_service_id_as_string")]
    pub invitee_aci: Option<Aci>,
    #[serde(serialize_with = "serialize::optional_service_id_as_string")]
    pub invitee_pni: Option<Pni>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
/// group update: {message}.{field_name}: {field_error}
pub struct GroupUpdateError {
    pub message: &'static str,
    pub field_name: &'static str,
    pub field_error: GroupUpdateFieldError,
}

#[derive(Copy, Clone, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(transparent)]
pub struct NoValidation<T>(T);

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum GroupUpdateFieldError {
    /// invalid ACI
    InvalidAci,
    /// invalid binary service ID
    InvalidServiceId,
    /// invitee has {0}
    InvalidInvitee(InviteeError),
    /// accessLevel is {0}
    AccessLevelInvalid(&'static str),
    /// inviter ACI is present but hadOpenInvitation is false
    InviterMismatch,
    /// count must be nonzero
    CountMustBeNonzero,
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

/// Module-private crate for conversion to T with error type [`GroupUpdateFieldError`].
///
/// Like `TryFrom`, but module-private since the implementations are specific to
/// group update validation.
trait ValidateFrom<T>: Sized {
    fn validate_from(value: T) -> Result<Self, GroupUpdateFieldError>;
}

impl ValidateFrom<Option<Vec<u8>>> for Option<Aci> {
    fn validate_from(value: Option<Vec<u8>>) -> Result<Self, GroupUpdateFieldError> {
        value
            .map(uuid_bytes_to_aci)
            .transpose()
            .map_err(|crate::backup::InvalidAci| GroupUpdateFieldError::InvalidAci)
    }
}

impl ValidateFrom<Vec<u8>> for Aci {
    fn validate_from(value: Vec<u8>) -> Result<Self, GroupUpdateFieldError> {
        uuid_bytes_to_aci(value)
            .map_err(|crate::backup::InvalidAci| GroupUpdateFieldError::InvalidAci)
    }
}

impl ValidateFrom<Vec<u8>> for ServiceId {
    fn validate_from(value: Vec<u8>) -> Result<Self, GroupUpdateFieldError> {
        ServiceId::parse_from_service_id_binary(&value)
            .ok_or(GroupUpdateFieldError::InvalidServiceId)
    }
}

impl ValidateFrom<u32> for NonZeroU32 {
    fn validate_from(value: u32) -> Result<Self, GroupUpdateFieldError> {
        NonZeroU32::try_from(value).map_err(|_| GroupUpdateFieldError::CountMustBeNonzero)
    }
}

impl<T> ValidateFrom<T> for NoValidation<T> {
    fn validate_from(value: T) -> Result<Self, GroupUpdateFieldError> {
        Ok(Self(value))
    }
}

impl ValidateFrom<EnumOrUnknown<proto::GroupV2AccessLevel>> for AccessLevel {
    fn validate_from(
        value: EnumOrUnknown<proto::GroupV2AccessLevel>,
    ) -> Result<Self, GroupUpdateFieldError> {
        match value.enum_value_or_default() {
            proto::GroupV2AccessLevel::UNKNOWN => {
                Err(GroupUpdateFieldError::AccessLevelInvalid("UNKNOWN"))
            }
            proto::GroupV2AccessLevel::UNSATISFIABLE => {
                Err(GroupUpdateFieldError::AccessLevelInvalid("UNSATISFIABLE"))
            }
            proto::GroupV2AccessLevel::ADMINISTRATOR => Ok(AccessLevel::Administrator),
            proto::GroupV2AccessLevel::ANY => Ok(AccessLevel::Any),
            proto::GroupV2AccessLevel::MEMBER => Ok(AccessLevel::Member),
        }
    }
}

impl ValidateFrom<Vec<proto::group_invitation_revoked_update::Invitee>> for UnorderedList<Invitee> {
    fn validate_from(
        invitees: Vec<proto::group_invitation_revoked_update::Invitee>,
    ) -> Result<Self, GroupUpdateFieldError> {
        if invitees.is_empty() {
            return Err(GroupUpdateFieldError::CountMustBeNonzero);
        }
        invitees
            .into_iter()
            .map(TryInto::try_into)
            .try_collect()
            .map_err(GroupUpdateFieldError::InvalidInvitee)
    }
}

impl ValidateFrom<u64> for Duration {
    fn validate_from(value: u64) -> Result<Self, GroupUpdateFieldError> {
        Ok(Self::from_millis(value))
    }
}

impl TryFrom<proto::group_invitation_revoked_update::Invitee> for Invitee {
    type Error = InviteeError;

    fn try_from(
        value: proto::group_invitation_revoked_update::Invitee,
    ) -> Result<Self, Self::Error> {
        let group_invitation_revoked_update::Invitee {
            inviterAci,
            inviteeAci,
            inviteePni,
            special_fields: _,
        } = value;
        let inviter = inviterAci
            .map(uuid_bytes_to_aci)
            .transpose()
            .map_err(|crate::backup::InvalidAci| InviteeError::InviterAci)?;
        let invitee_aci: Option<Aci> = inviteeAci
            .map(uuid_bytes_to_aci)
            .transpose()
            .map_err(|crate::backup::InvalidAci| InviteeError::InviteeAci)?;
        let invitee_pni = inviteePni
            .map(|bytes| bytes.try_into().map(Pni::from_uuid_bytes))
            .transpose()
            .map_err(|_| InviteeError::InviteePni)?;
        Ok(Invitee {
            inviter,
            invitee_aci,
            invitee_pni,
        })
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
            Update::GroupMemberAddedUpdate(m) => {
                let result = m.try_into()?;

                let Self::GroupMemberAddedUpdate {
                    updaterAci: _,
                    newMemberAci: _,
                    inviterAci,
                    hadOpenInvitation,
                } = result
                else {
                    unreachable!("wrong case constructed for GroupChatUpdate");
                };

                if inviterAci.is_some() && !hadOpenInvitation.0 {
                    return Err(GroupUpdateError {
                        message: "GroupMemberAddedUpdate",
                        field_name: "inviterAci",
                        field_error: GroupUpdateFieldError::InviterMismatch,
                    });
                }

                Ok(result)
            }
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

impl<T: Debug> Debug for NoValidation<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod test {
    use nonzero_ext::nonzero;
    use test_case::test_case;

    use super::*;
    use crate::proto::backup::{group_change_chat_update, group_invitation_revoked_update};

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

    fn validated_invitees() -> UnorderedList<Invitee> {
        vec![
            Invitee {
                inviter: None,
                invitee_aci: None,
                invitee_pni: None,
            },
            Invitee {
                inviter: Some(ACI),
                invitee_pni: Some(PNI),
                invitee_aci: None,
            },
        ]
        .into()
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

    #[test_case(123, Ok(NoValidation(123)); "no validation")]
    #[test_case(123, Ok(nonzero!(123u32)); "non-zero")]
    #[test_case(0, Err::<NonZeroU32, _>(CountMustBeNonzero))]
    #[test_case(vec![], Err::<Aci, _>(InvalidAci))]
    #[test_case(ACI.service_id_binary(), Ok(ACI))]
    #[test_case(Some(ACI.service_id_binary()), Ok(Some(ACI)))]
    #[test_case(None, Ok(None::<Aci>))]
    #[test_case(Some(vec![]), Err::<Option<Aci>, _>(InvalidAci))]
    #[test_case(PNI.service_id_binary(), Err::<Aci, _>(InvalidAci))]
    #[test_case(Some(PNI.service_id_binary()), Err::<Option<Aci>, _>(InvalidAci))]
    #[test_case(ACI.service_id_binary(), Ok(ServiceId::Aci(ACI)))]
    #[test_case(vec![], Err::<ServiceId, _>(InvalidServiceId))]
    #[test_case(valid_invitees(), Ok(validated_invitees()))]
    #[test_case(vec![], Err::<UnorderedList<Invitee>, _>(CountMustBeNonzero))]
    #[test_case(invitee_invalid_aci(), Err::<UnorderedList<Invitee>,_>(InvalidInvitee(InviteeError::InviteeAci)))]
    #[test_case(
        invitee_pni_service_id_binary(),
        Err::<UnorderedList<Invitee>, _>(InvalidInvitee(InviteeError::InviteePni))
    )]
    #[test_case(
        EnumOrUnknown::default(),
        Err::<AccessLevel, _>(AccessLevelInvalid("UNKNOWN"))
    )]
    #[test_case(
        proto::GroupV2AccessLevel::UNSATISFIABLE.into(),
        Err::<AccessLevel, _>(AccessLevelInvalid("UNSATISFIABLE"))
    )]
    fn validate_field_value<V: ValidateFrom<T> + PartialEq + Debug, T>(
        input: T,
        expected: Result<V, GroupUpdateFieldError>,
    ) {
        assert_eq!(V::validate_from(input), expected)
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

    #[test_case(None, false, Ok(()))]
    #[test_case(None, true, Ok(()))]
    #[test_case(Some(ACI), true, Ok(()))]
    #[test_case(Some(ACI), false, Err(GroupUpdateFieldError::InviterMismatch))]
    fn group_member_added_inviter_table(
        inviter: Option<Aci>,
        had_invitation: bool,
        expected: Result<(), GroupUpdateFieldError>,
    ) {
        let update = group_change_chat_update::update::Update::GroupMemberAddedUpdate(
            GroupMemberAddedUpdate {
                newMemberAci: ACI_BYTES.to_vec(),
                hadOpenInvitation: had_invitation,
                inviterAci: inviter.map(|aci| aci.service_id_binary()),
                ..Default::default()
            },
        );

        let result = GroupChatUpdate::try_from(update)
            .map(|_| ())
            .map_err(|e| e.field_error);
        assert_eq!(result, expected);
    }
}
