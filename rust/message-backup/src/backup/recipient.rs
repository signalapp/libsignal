//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::num::NonZeroU64;
use std::sync::Arc;

use derive_where::derive_where;
use itertools::Itertools as _;
use libsignal_core::{Aci, Pni, ServiceIdKind};
use libsignal_protocol::IdentityKey;
use uuid::Uuid;
use zkgroup::ProfileKeyBytes;

use crate::backup::call::{CallLink, CallLinkError};
use crate::backup::frame::RecipientId;
use crate::backup::method::{LookupPair, Method, Store, ValidateOnly};
use crate::backup::serialize::{self, SerializeOrder, UnorderedList};
use crate::backup::time::{ReportUnusualTimestamp, Timestamp};
use crate::backup::{ReferencedTypes, TryFromWith, TryIntoWith};
use crate::proto::backup as proto;
use crate::proto::backup::recipient::Destination as RecipientDestination;

pub(crate) mod group;
use group::*;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum RecipientError {
    /// multiple frames with the same ID
    DuplicateRecipient,
    /// Recipient.destination is a oneof but is empty
    MissingDestination,
    /// invalid {0}
    InvalidServiceId(ServiceIdKind),
    /// invalid e164
    InvalidE164,
    /// profile key is present but invalid
    InvalidProfileKey,
    /// identity key is present but invalid
    InvalidIdentityKey,
    /// missing identity key for contact marked {0:?}
    MissingIdentityKey(proto::contact::IdentityState),
    /// distribution destination has invalid UUID
    InvalidDistributionId,
    /// invalid group: {0}
    InvalidGroup(#[from] GroupError),
    /// contact has neither an ACI, nor a PNI, nor an e164
    ContactHasNoIdentifiers,
    /// contact has a PNI but no e164
    PniWithoutE164,
    /// contact registered value is UNKNOWN
    ContactRegistrationUnknown,
    /// distribution list has privacy mode UNKNOWN
    DistributionListPrivacyUnknown,
    /// distribution list has privacy mode {0:?} but is not "My Story"
    DistributionListPrivacyInvalid(proto::distribution_list::PrivacyMode),
    /// distribution list has members but has privacy ALL
    DistributionListPrivacyAllWithNonemptyMembers,
    /// invalid call link: {0}
    InvalidCallLink(#[from] CallLinkError),
    /// contact has invalid username
    InvalidContactUsername,
    /// DistributionList for My Story should not be deleted
    CannotDeleteMyStory,
    /// DistributionList.item is a oneof but is empty
    DistributionListItemMissing,
    /// distribution list member {0:?} is unknown
    DistributionListMemberUnknown(RecipientId),
    /// distribution list member {0:?} is a {1:?} not a contact
    DistributionListMemberWrongKind(RecipientId, DestinationKind),
}

/// Data kept in-memory from a [`proto::Recipient`] for [`ValidateOnly`] mode.
///
/// This is intentionally the minimal amount of data required to validate later
/// frames.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MinimalRecipientData(DestinationKind);

/// Data kept in-memory from a [`proto::Recipient`] for [`Store`] mode.
///
/// This keeps the full data in memory behind a [`Arc`] so it can be cheaply
/// cloned when referenced by later frames.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FullRecipientData(Arc<Destination<Store>>);

#[derive_where(Debug)]
#[cfg_attr(test,
    derive_where(PartialEq;
        M::Value<ContactData>: PartialEq,
        M::Value<GroupData>: PartialEq,
        M::Value<DistributionListItem<M::RecipientReference>>: PartialEq,
        M::Value<CallLink>: PartialEq
    )
)]
#[derive(serde::Serialize, strum::EnumDiscriminants)]
#[strum_discriminants(name(DestinationKind))]
pub enum Destination<M: Method + ReferencedTypes> {
    Contact(M::Value<ContactData>),
    Group(M::Value<GroupData>),
    DistributionList(M::Value<DistributionListItem<M::RecipientReference>>),
    Self_,
    ReleaseNotes,
    CallLink(M::Value<CallLink>),
}

impl DestinationKind {
    pub fn is_individual(&self) -> bool {
        match self {
            DestinationKind::Contact | DestinationKind::Self_ => true,
            DestinationKind::Group
            | DestinationKind::DistributionList
            | DestinationKind::ReleaseNotes
            | DestinationKind::CallLink => false,
        }
    }
}

impl AsRef<DestinationKind> for DestinationKind {
    fn as_ref(&self) -> &DestinationKind {
        self
    }
}

/// Represents a phone number in E.164 format.
///
/// Due to the changing nature of phone numbers around the world, validation is minimal.
///
/// The ordering should be considered arbitrary; a proper ordering of E164s would use a
/// lexicographic ordering of the decimal digits, but that costs more in CPU. Use the string
/// representation as a sort key if sorting for human consumption.
#[derive(Debug, serde::Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct E164(NonZeroU64);

impl TryFrom<u64> for E164 {
    type Error = <NonZeroU64 as TryFrom<u64>>::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Self(NonZeroU64::try_from(value)?))
    }
}

impl From<E164> for u64 {
    fn from(value: E164) -> Self {
        value.0.into()
    }
}

impl std::fmt::Display for E164 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "+{}", self.0)
    }
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ContactData {
    #[serde(serialize_with = "serialize::optional_service_id_as_string")]
    pub aci: Option<Aci>,
    #[serde(serialize_with = "serialize::optional_service_id_as_string")]
    pub pni: Option<Pni>,
    #[serde(serialize_with = "serialize::optional_hex")]
    pub profile_key: Option<ProfileKeyBytes>,
    pub username: Option<String>,
    pub registration: Registration,
    pub e164: Option<E164>,
    pub blocked: bool,
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub visibility: proto::contact::Visibility,
    pub profile_sharing: bool,
    pub profile_given_name: Option<String>,
    pub profile_family_name: Option<String>,
    pub hide_story: bool,
    #[serde(serialize_with = "serialize::optional_identity_key_hex")]
    pub identity_key: Option<IdentityKey>,
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub identity_state: proto::contact::IdentityState,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum DistributionListItem<Recipient> {
    Deleted {
        distribution_id: Uuid,
        at: Timestamp,
    },
    List {
        distribution_id: Uuid,
        name: String,
        allow_replies: bool,
        #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
        privacy_mode: PrivacyMode<UnorderedList<Recipient>>,
    },
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Registration {
    NotRegistered { unregistered_at: Option<Timestamp> },
    Registered,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum PrivacyMode<RecipientList> {
    OnlyWith(RecipientList),
    AllExcept(RecipientList),
    All,
}

impl AsRef<DestinationKind> for MinimalRecipientData {
    fn as_ref(&self) -> &DestinationKind {
        &self.0
    }
}

impl std::ops::Deref for FullRecipientData {
    type Target = Destination<Store>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: LookupPair<RecipientId, DestinationKind, RecipientId> + ReportUnusualTimestamp>
    TryFromWith<proto::Recipient, C> for MinimalRecipientData
{
    type Error = RecipientError;

    fn try_from_with(item: proto::Recipient, context: &C) -> Result<Self, Self::Error> {
        let destination: Destination<ValidateOnly> = item.try_into_with(context)?;
        Ok(Self(*destination.as_ref()))
    }
}

impl FullRecipientData {
    pub(crate) fn new(data: Destination<Store>) -> Self {
        Self(Arc::new(data))
    }
}

impl AsRef<DestinationKind> for FullRecipientData {
    fn as_ref(&self) -> &DestinationKind {
        self.0.as_ref().as_ref()
    }
}

impl AsRef<Self> for FullRecipientData {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<C: LookupPair<RecipientId, DestinationKind, Self> + ReportUnusualTimestamp>
    TryFromWith<proto::Recipient, C> for FullRecipientData
{
    type Error = RecipientError;

    fn try_from_with(item: proto::Recipient, context: &C) -> Result<Self, Self::Error> {
        item.try_into_with(context).map(Self::new)
    }
}

#[cfg(test)]
impl PartialEq for FullRecipientData {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<M: Method + ReferencedTypes> AsRef<DestinationKind> for Destination<M> {
    fn as_ref(&self) -> &DestinationKind {
        // We cheat by returning static references. That's fine since these are
        // just discriminants; they don't represent the actual data from the
        // enum values.
        match self {
            Destination::Contact(_) => &DestinationKind::Contact,
            Destination::Group(_) => &DestinationKind::Group,
            Destination::DistributionList(_) => &DestinationKind::DistributionList,
            Destination::Self_ => &DestinationKind::Self_,
            Destination::ReleaseNotes => &DestinationKind::ReleaseNotes,
            Destination::CallLink(_) => &DestinationKind::CallLink,
        }
    }
}

impl<
        M: Method + ReferencedTypes,
        C: LookupPair<RecipientId, DestinationKind, M::RecipientReference> + ReportUnusualTimestamp,
    > TryFromWith<proto::Recipient, C> for Destination<M>
{
    type Error = RecipientError;
    fn try_from_with(value: proto::Recipient, context: &C) -> Result<Self, Self::Error> {
        let proto::Recipient {
            id: _,
            destination,
            special_fields: _,
        } = value;

        let destination = destination.ok_or(RecipientError::MissingDestination)?;

        Ok(match destination {
            RecipientDestination::Contact(contact) => {
                Destination::Contact(M::value(contact.try_into_with(context)?))
            }
            RecipientDestination::Group(group) => {
                Destination::Group(M::value(group.try_into_with(context)?))
            }
            RecipientDestination::DistributionList(list) => {
                Destination::DistributionList(M::value(list.try_into_with(context)?))
            }
            RecipientDestination::Self_(proto::Self_ { special_fields: _ }) => Destination::Self_,
            RecipientDestination::ReleaseNotes(proto::ReleaseNotes { special_fields: _ }) => {
                Destination::ReleaseNotes
            }
            RecipientDestination::CallLink(call_link) => {
                Destination::CallLink(M::value(call_link.try_into_with(context)?))
            }
        })
    }
}

impl<C: ReportUnusualTimestamp> TryFromWith<proto::Contact, C> for ContactData {
    type Error = RecipientError;
    fn try_from_with(value: proto::Contact, context: &C) -> Result<Self, Self::Error> {
        let proto::Contact {
            aci,
            pni,
            profileKey,
            username,
            e164,
            blocked,
            visibility,
            registration,
            profileSharing,
            profileGivenName,
            profileFamilyName,
            hideStory,
            identityKey,
            identityState,
            special_fields: _,
        } = value;

        let aci = aci
            .map(TryInto::try_into)
            .transpose()
            .map_err(|_| RecipientError::InvalidServiceId(ServiceIdKind::Aci))?
            .map(Aci::from_uuid_bytes);
        let pni = pni
            .map(TryInto::try_into)
            .transpose()
            .map_err(|_| RecipientError::InvalidServiceId(ServiceIdKind::Pni))?
            .map(Pni::from_uuid_bytes);

        let username = username
            .map(|username| {
                usernames::Username::new(&username)
                    .map_err(|_| RecipientError::InvalidContactUsername)
                    .map(|_| username)
            })
            .transpose()?;

        let profile_key = profileKey
            .map(TryInto::try_into)
            .transpose()
            .map_err(|_| RecipientError::InvalidProfileKey)?;

        let registration = match registration.ok_or(RecipientError::ContactRegistrationUnknown)? {
            proto::contact::Registration::NotRegistered(proto::contact::NotRegistered {
                unregisteredTimestamp,
                special_fields: _,
            }) => Registration::NotRegistered {
                unregistered_at: NonZeroU64::new(unregisteredTimestamp).map(|u| {
                    Timestamp::from_millis(
                        u.get(),
                        "Contact.notRegistered.unregisteredTimestamp",
                        context,
                    )
                }),
            },
            proto::contact::Registration::Registered(proto::contact::Registered {
                special_fields: _,
            }) => Registration::Registered,
        };

        let visibility = match visibility.enum_value_or_default() {
            v @ (proto::contact::Visibility::VISIBLE
            | proto::contact::Visibility::HIDDEN
            | proto::contact::Visibility::HIDDEN_MESSAGE_REQUEST) => v,
        };

        let e164 = e164
            .map(E164::try_from)
            .transpose()
            .map_err(|_| RecipientError::InvalidE164)?;

        match (&aci, &pni, &e164) {
            (None, None, None) => Err(RecipientError::ContactHasNoIdentifiers),
            // There are a few scenarios where a client can learn of a PNI directly,
            // such as a group's invite list. If we decide not to back up such PNIs
            // as Contacts, we can re-enable this check:
            // (_, Some(_), None) => Err(RecipientError::PniWithoutE164),
            _ => Ok(()),
        }?;

        let identity_key = identityKey
            .map(|bytes| IdentityKey::decode(&bytes))
            .transpose()
            .map_err(|_| RecipientError::InvalidIdentityKey)?;

        let identity_state = match identityState.enum_value_or_default() {
            v @ proto::contact::IdentityState::DEFAULT => v,
            v @ (proto::contact::IdentityState::VERIFIED
            | proto::contact::IdentityState::UNVERIFIED) => {
                if identity_key.is_none() {
                    return Err(RecipientError::MissingIdentityKey(v));
                }
                v
            }
        };

        Ok(Self {
            aci,
            pni,
            profile_key,
            registration,
            username,
            e164,
            blocked,
            visibility,
            profile_sharing: profileSharing,
            profile_given_name: profileGivenName,
            profile_family_name: profileFamilyName,
            hide_story: hideStory,
            identity_key,
            identity_state,
        })
    }
}

impl<R: Clone, C: LookupPair<RecipientId, DestinationKind, R> + ReportUnusualTimestamp>
    TryFromWith<proto::DistributionListItem, C> for DistributionListItem<R>
{
    type Error = RecipientError;

    fn try_from_with(value: proto::DistributionListItem, context: &C) -> Result<Self, Self::Error> {
        let proto::DistributionListItem {
            distributionId,
            item,
            special_fields: _,
        } = value;

        const MY_STORY_UUID: Uuid = Uuid::nil();

        let distribution_id = Uuid::from_bytes(
            distributionId
                .try_into()
                .map_err(|_| RecipientError::InvalidDistributionId)?,
        );

        Ok(
            match item.ok_or(RecipientError::DistributionListItemMissing)? {
                proto::distribution_list_item::Item::DeletionTimestamp(deletion_timestamp) => {
                    if distribution_id == MY_STORY_UUID {
                        return Err(RecipientError::CannotDeleteMyStory);
                    }

                    let at = Timestamp::from_millis(
                        deletion_timestamp,
                        "DistributionList.deletionTimestamp",
                        context,
                    );
                    Self::Deleted {
                        distribution_id,
                        at,
                    }
                }
                proto::distribution_list_item::Item::DistributionList(
                    proto::DistributionList {
                        name,
                        allowReplies,
                        privacyMode,
                        memberRecipientIds,
                        special_fields: _,
                    },
                ) => {
                    let members: UnorderedList<R> = memberRecipientIds
                        .into_iter()
                        .map(|id| {
                            let id = RecipientId(id);
                            let (&kind, recipient_reference) = context
                                .lookup_pair(&id)
                                .ok_or(RecipientError::DistributionListMemberUnknown(id))?;
                            match kind {
                                DestinationKind::Contact => Ok(recipient_reference.clone()),
                                DestinationKind::Group
                                | DestinationKind::DistributionList
                                | DestinationKind::Self_
                                | DestinationKind::ReleaseNotes
                                | DestinationKind::CallLink => {
                                    Err(RecipientError::DistributionListMemberWrongKind(id, kind))
                                }
                            }
                        })
                        .try_collect()?;

                    let privacy_mode = match (
                        privacyMode.enum_value_or_default(),
                        distribution_id == MY_STORY_UUID,
                    ) {
                        (proto::distribution_list::PrivacyMode::UNKNOWN, _) => {
                            return Err(RecipientError::DistributionListPrivacyUnknown)
                        }
                        (proto::distribution_list::PrivacyMode::ONLY_WITH, _) => {
                            PrivacyMode::OnlyWith(members)
                        }
                        (proto::distribution_list::PrivacyMode::ALL_EXCEPT, true) => {
                            PrivacyMode::AllExcept(members)
                        }
                        (proto::distribution_list::PrivacyMode::ALL, true) => {
                            if !members.is_empty() {
                                return Err(
                                    RecipientError::DistributionListPrivacyAllWithNonemptyMembers,
                                );
                            }
                            PrivacyMode::All
                        }
                        (privacy, false) => {
                            return Err(RecipientError::DistributionListPrivacyInvalid(privacy));
                        }
                    };

                    Self::List {
                        distribution_id,
                        name,
                        allow_replies: allowReplies,
                        privacy_mode,
                    }
                }
            },
        )
    }
}

#[cfg(test)]
mod test {
    use array_concat::concat_arrays;
    use assert_matches::assert_matches;
    use nonzero_ext::nonzero;
    use protobuf::EnumOrUnknown;
    use test_case::test_case;

    use super::*;
    use crate::backup::method::Store;
    use crate::backup::testutil::TestContext;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;

    impl proto::Recipient {
        pub(crate) const TEST_ID: u64 = TestContext::SELF_ID.0;
        pub(crate) fn test_data() -> Self {
            Self {
                id: Self::TEST_ID,
                destination: Some(proto::recipient::Destination::Self_(Default::default())),
                ..Default::default()
            }
        }
        pub(crate) fn test_data_contact() -> Self {
            Self {
                id: TestContext::CONTACT_ID.0,
                destination: Some(proto::recipient::Destination::Contact(proto::Contact {
                    aci: Some([0xaa; 16].into()),
                    registration: Some(
                        proto::contact::Registration::Registered(Default::default()),
                    ),
                    ..Default::default()
                })),
                ..Default::default()
            }
        }
    }

    impl proto::Contact {
        pub(crate) const TEST_ACI: [u8; 16] = [0xaa; 16];
        pub(crate) const TEST_PNI: [u8; 16] = [0xba; 16];
        pub(crate) const TEST_PROFILE_KEY: ProfileKeyBytes = [0x36; 32];
        pub(crate) const TEST_E164: E164 = E164(nonzero!(16505550101u64));
        pub(crate) const TEST_IDENTITY_KEY_BYTES: [u8; 33] =
            concat_arrays!([0x05 /*type byte*/], [0x01; 32]);

        fn test_data() -> Self {
            Self {
                aci: Some(Self::TEST_ACI.into()),
                pni: Some(Self::TEST_PNI.into()),
                e164: Some(Self::TEST_E164.into()),
                profileKey: Some(Self::TEST_PROFILE_KEY.into()),
                registration: Some(proto::contact::Registration::NotRegistered(
                    Default::default(),
                )),
                username: Some("example.1234".to_owned()),
                profileGivenName: Some("GivenName".to_owned()),
                profileFamilyName: Some("FamilyName".to_owned()),
                identityKey: Some(Self::TEST_IDENTITY_KEY_BYTES.to_vec()),
                identityState: proto::contact::IdentityState::VERIFIED.into(),

                ..Default::default()
            }
        }
    }

    impl proto::DistributionListItem {
        const TEST_CUSTOM_UUID: [u8; 16] = [0x99; 16];
        fn test_data() -> Self {
            Self {
                distributionId: Uuid::nil().into(),
                item: Some(proto::distribution_list_item::Item::DistributionList(
                    proto::DistributionList {
                        privacyMode: proto::distribution_list::PrivacyMode::ALL_EXCEPT.into(),
                        memberRecipientIds: vec![TestContext::CONTACT_ID.0],
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }
        }
    }

    impl ContactData {
        pub(crate) fn from_proto_test_data() -> Self {
            ContactData {
                aci: Some(Aci::from_uuid_bytes(proto::Contact::TEST_ACI)),
                pni: Some(Pni::from_uuid_bytes(proto::Contact::TEST_PNI)),
                profile_key: Some(proto::Contact::TEST_PROFILE_KEY),
                registration: Registration::NotRegistered {
                    unregistered_at: None,
                },
                username: Some("example.1234".to_owned()),
                e164: Some(proto::Contact::TEST_E164),
                blocked: false,
                visibility: proto::contact::Visibility::VISIBLE,
                profile_sharing: false,
                profile_given_name: Some("GivenName".to_owned()),
                profile_family_name: Some("FamilyName".to_owned()),
                hide_story: false,
                identity_key: Some(
                    IdentityKey::decode(&proto::Contact::TEST_IDENTITY_KEY_BYTES).expect("valid"),
                ),
                identity_state: proto::contact::IdentityState::VERIFIED,
            }
        }
    }

    #[test]
    fn requires_destination() {
        let recipient = proto::Recipient {
            destination: None,
            ..proto::Recipient::test_data()
        };

        assert_matches!(
            Destination::<Store>::try_from_with(recipient, &TestContext::default()),
            Err(RecipientError::MissingDestination)
        );
    }

    #[test]
    fn valid_destination_self() {
        let recipient = proto::Recipient::test_data();

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext::default()),
            Ok(Destination::Self_)
        )
    }

    #[test]
    fn valid_destination_contact() {
        let recipient = proto::Recipient {
            destination: Some(proto::Contact::test_data().into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext::default()),
            Ok(Destination::Contact(ContactData::from_proto_test_data()))
        )
    }

    #[test_case(|x| x.aci = None => Ok(()); "no_aci")]
    #[test_case(|x| x.pni = None => Ok(()); "no_pni")]
    #[test_case(|x| {x.aci = None; x.pni = None} => Ok(()); "no_aci_or_pni")]
    #[test_case(|x| {x.pni = None; x.e164 = None} => Ok(()); "no_pni_or_e164")]
    #[test_case(|x| {x.aci = None; x.pni = None; x.e164 = None} => Err(RecipientError::ContactHasNoIdentifiers); "no_aci_or_pni_or_e164")]
    #[test_case(|x| x.aci.as_mut().unwrap().push(0xaa) => Err(RecipientError::InvalidServiceId(ServiceIdKind::Aci)); "invalid_aci")]
    #[test_case(|x| x.pni.as_mut().unwrap().push(0xaa) => Err(RecipientError::InvalidServiceId(ServiceIdKind::Pni)); "invalid_pni")]
    #[test_case(|x| x.profileKey = None => Ok(()); "no_profile_key")]
    #[test_case(|x| x.profileKey.as_mut().unwrap().push(0xaa) => Err(RecipientError::InvalidProfileKey); "invalid_profile_key")]
    #[test_case(|x| x.registration = None => Err(RecipientError::ContactRegistrationUnknown); "registration_unknown")]
    #[test_case(|x| {x.profileGivenName = None; x.profileFamilyName = None} => Ok(()); "profile_no_names")]
    #[test_case(|x| x.visibility = proto::contact::Visibility::HIDDEN.into() => Ok(()); "visibility_hidden")]
    #[test_case(|x| x.visibility = EnumOrUnknown::default() => Ok(()); "visibility_default")]
    #[test_case(|x| x.e164 = Some(0) => Err(RecipientError::InvalidE164); "with_invalid_e164")]
    #[test_case(|x| x.e164 = None => Ok(()); "no_e164")]
    #[test_case(|x| x.identityState = proto::contact::IdentityState::UNVERIFIED.into() => Ok(()); "identity_unverified")]
    #[test_case(|x| x.identityState = proto::contact::IdentityState::DEFAULT.into() => Ok(()); "identity_default")]
    #[test_case(|x| x.identityKey = None => Err(RecipientError::MissingIdentityKey(proto::contact::IdentityState::VERIFIED)); "missing_identity_verified")]
    #[test_case(|x| {
        x.identityKey = None;
        x.identityState = proto::contact::IdentityState::UNVERIFIED.into();
    } => Err(RecipientError::MissingIdentityKey(proto::contact::IdentityState::UNVERIFIED)); "missing_identity_unverified")]
    #[test_case(|x| {
        x.identityKey = None;
        x.identityState = proto::contact::IdentityState::DEFAULT.into();
    } => Ok(()); "missing_identity_default")]
    #[test_case(|x| x.identityKey = Some(vec![]) => Err(RecipientError::InvalidIdentityKey); "invalid_identity_key")]
    fn destination_contact(modifier: fn(&mut proto::Contact)) -> Result<(), RecipientError> {
        let mut contact = proto::Contact::test_data();
        modifier(&mut contact);

        let recipient = proto::Recipient {
            destination: Some(contact.into()),
            ..proto::Recipient::test_data()
        };

        Destination::<Store>::try_from_with(recipient, &TestContext::default()).map(|_| ())
    }

    #[test]
    fn valid_destination_group() {
        let recipient = proto::Recipient {
            destination: Some(proto::Group::test_data().into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext::default()),
            Ok(Destination::Group(GroupData::from_proto_test_data()))
        );
    }

    #[test_case(|x| x.masterKey = vec![] => Err(RecipientError::InvalidGroup(GroupError::InvalidMasterKey)); "invalid master key")]
    #[test_case(|x| x.storySendMode = Default::default() => Ok(()); "default story send mode")]
    fn destination_group(modifier: fn(&mut proto::Group)) -> Result<(), RecipientError> {
        let mut group = proto::Group::test_data();
        modifier(&mut group);

        let recipient = proto::Recipient {
            destination: Some(group.into()),
            ..proto::Recipient::test_data()
        };

        Destination::<Store>::try_from_with(recipient, &TestContext::default()).map(|_| ())
    }

    #[test]
    fn valid_distribution_list() {
        let recipient = proto::Recipient {
            destination: Some(proto::DistributionListItem::test_data().into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext::default()),
            Ok(Destination::DistributionList(DistributionListItem::List {
                distribution_id: Uuid::nil(),
                privacy_mode: PrivacyMode::AllExcept(
                    vec![TestContext::contact_recipient().clone()].into()
                ),
                name: "".to_owned(),
                allow_replies: false,
            }))
        );
    }

    const UNKNOWN_RECIPIENT_ID: RecipientId = RecipientId(9999999999);

    #[test_case(
        |x| x.distributionId = vec![0x55; 50] => Err(RecipientError::InvalidDistributionId);
        "invalid_distribution_id"
    )]
    #[test_case(
        |x| x.mut_distributionList().privacyMode = EnumOrUnknown::default() =>
        Err(RecipientError::DistributionListPrivacyUnknown);
        "privacy_mode_unknown"
    )]
    #[test_case(
        |x| x.mut_distributionList().memberRecipientIds.push(UNKNOWN_RECIPIENT_ID.0) =>
        Err(RecipientError::DistributionListMemberUnknown(UNKNOWN_RECIPIENT_ID));
        "unknown_member"
    )]
    #[test_case(
        |x| x.mut_distributionList().memberRecipientIds.push(TestContext::SELF_ID.0) =>
        Err(RecipientError::DistributionListMemberWrongKind(TestContext::SELF_ID, DestinationKind::Self_));
        "member_is_not_a_contact"
    )]
    #[test_case(
        |x| x.mut_distributionList().privacyMode = proto::distribution_list::PrivacyMode::ALL.into() =>
        Err(RecipientError::DistributionListPrivacyAllWithNonemptyMembers);
        "privacy_mode_all_with_nonempty_members"
    )]
    #[test_case(
        |x| x.distributionId = proto::DistributionListItem::TEST_CUSTOM_UUID.into() => Err(RecipientError::DistributionListPrivacyInvalid(proto::distribution_list::PrivacyMode::ALL_EXCEPT));
        "privacy_mode_for_custom_story"
    )]
    #[test_case(|x| {
        x.distributionId = proto::DistributionListItem::TEST_CUSTOM_UUID.into();
        x.mut_distributionList().privacyMode = proto::distribution_list::PrivacyMode::ONLY_WITH.into();
    } => Ok(()); "valid_privacy_mode_for_custom_story")]
    #[test_case(
        |x| x.set_deletionTimestamp(MillisecondsSinceEpoch::TEST_VALUE.0) => Err(RecipientError::CannotDeleteMyStory);
        "deletion"
    )]
    #[test_case(|x| {
        x.distributionId = proto::DistributionListItem::TEST_CUSTOM_UUID.into();
        x.set_deletionTimestamp(MillisecondsSinceEpoch::TEST_VALUE.0);
    } => Ok(()); "valid_deletion")]
    fn destination_distribution_list(
        modifier: fn(&mut proto::DistributionListItem),
    ) -> Result<(), RecipientError> {
        let mut distribution_list = proto::DistributionListItem::test_data();
        modifier(&mut distribution_list);

        let recipient = proto::Recipient {
            destination: Some(distribution_list.into()),
            ..proto::Recipient::test_data()
        };

        Destination::<Store>::try_from_with(recipient, &TestContext::default()).map(|_| ())
    }
}
