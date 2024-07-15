//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::num::NonZeroU64;
use std::sync::Arc;

use derive_where::derive_where;
use itertools::Itertools as _;
use libsignal_protocol::{Aci, Pni, ServiceIdKind};
use uuid::Uuid;
use zkgroup::{GroupMasterKeyBytes, ProfileKeyBytes};

use crate::backup::call::{CallLink, CallLinkError};
use crate::backup::frame::RecipientId;
use crate::backup::method::{LookupPair, Method, Store, ValidateOnly};
use crate::backup::serialize::{self, SerializeOrder, UnorderedList};
use crate::backup::time::Timestamp;
use crate::backup::{ReferencedTypes, TryFromWith, TryIntoWith};
use crate::proto::backup as proto;
use crate::proto::backup::recipient::Destination as RecipientDestination;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum RecipientError {
    /// multiple frames with the same ID
    DuplicateRecipient,
    /// Recipient.destination is a oneof but is empty
    MissingDestination,
    /// invalid {0}
    InvalidServiceId(ServiceIdKind),
    /// profile key is present but invalid
    InvalidProfileKey,
    /// distribution destination has invalid UUID
    InvalidDistributionId,
    /// master key has wrong number of bytes
    InvalidMasterKey,
    /// contact registered value is UNKNOWN
    ContactRegistrationUnknown,
    /// distribution list has privacy mode UNKNOWN
    DistributionListPrivacyUnknown,
    /// invalid call link: {0}
    InvalidCallLink(#[from] CallLinkError),
    /// contact has invalid username
    InvalidContactUsername,
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

impl AsRef<DestinationKind> for DestinationKind {
    fn as_ref(&self) -> &DestinationKind {
        self
    }
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ContactData {
    #[serde(serialize_with = "serialize::optional_service_id_as_string")]
    pub aci: Option<Aci>,
    #[serde(serialize_with = "serialize::optional_service_id_as_string")]
    pub pni: Option<Pni>,
    pub profile_key: Option<ProfileKeyBytes>,
    pub username: Option<String>,
    pub registration: Registration,
    pub e164: Option<u64>,
    pub blocked: bool,
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub visibility: proto::contact::Visibility,
    pub profile_sharing: bool,
    pub profile_given_name: Option<String>,
    pub profile_family_name: Option<String>,
    pub hide_story: bool,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct GroupData {
    pub master_key: GroupMasterKeyBytes,
    pub whitelisted: bool,
    pub hide_story: bool,
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub story_send_mode: proto::group::StorySendMode,
    #[serde(serialize_with = "serialize::optional_proto_message_as_bytes")]
    pub snapshot: Option<Box<proto::group::GroupSnapshot>>,
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
        privacy_mode: PrivacyMode,
        #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
        members: UnorderedList<Recipient>,
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
pub enum PrivacyMode {
    OnlyWith,
    AllExcept,
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

impl<C: LookupPair<RecipientId, DestinationKind, RecipientId>> TryFromWith<proto::Recipient, C>
    for MinimalRecipientData
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

impl<C: LookupPair<RecipientId, DestinationKind, Self>> TryFromWith<proto::Recipient, C>
    for FullRecipientData
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
        C: LookupPair<RecipientId, DestinationKind, M::RecipientReference>,
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
                Destination::Contact(M::value(contact.try_into()?))
            }
            RecipientDestination::Group(group) => Destination::Group(M::value(group.try_into()?)),
            RecipientDestination::DistributionList(list) => {
                Destination::DistributionList(M::value(list.try_into_with(context)?))
            }
            RecipientDestination::Self_(proto::Self_ { special_fields: _ }) => Destination::Self_,
            RecipientDestination::ReleaseNotes(proto::ReleaseNotes { special_fields: _ }) => {
                Destination::ReleaseNotes
            }
            RecipientDestination::CallLink(call_link) => {
                Destination::CallLink(M::value(call_link.try_into()?))
            }
        })
    }
}

impl TryFrom<proto::Contact> for ContactData {
    type Error = RecipientError;
    fn try_from(value: proto::Contact) -> Result<Self, Self::Error> {
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
                    Timestamp::from_millis(u.get(), "Contact.notRegistered.unregisteredTimestamp")
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
        })
    }
}

impl TryFrom<proto::Group> for GroupData {
    type Error = RecipientError;
    fn try_from(value: proto::Group) -> Result<Self, Self::Error> {
        let proto::Group {
            masterKey,
            whitelisted,
            hideStory,
            storySendMode,
            snapshot,
            special_fields: _,
        } = value;

        let master_key = masterKey
            .try_into()
            .map_err(|_| RecipientError::InvalidMasterKey)?;

        let story_send_mode = match storySendMode.enum_value_or_default() {
            s @ (proto::group::StorySendMode::DEFAULT
            | proto::group::StorySendMode::DISABLED
            | proto::group::StorySendMode::ENABLED) => s,
        };

        // TODO consider additional group snapshot validation.
        let snapshot = snapshot.0;

        Ok(GroupData {
            master_key,
            whitelisted,
            hide_story: hideStory,
            story_send_mode,
            snapshot,
        })
    }
}

impl<R: Clone, C: LookupPair<RecipientId, DestinationKind, R>>
    TryFromWith<proto::DistributionListItem, C> for DistributionListItem<R>
{
    type Error = RecipientError;

    fn try_from_with(value: proto::DistributionListItem, context: &C) -> Result<Self, Self::Error> {
        let proto::DistributionListItem {
            distributionId,
            item,
            special_fields: _,
        } = value;

        let distribution_id = Uuid::from_bytes(
            distributionId
                .try_into()
                .map_err(|_| RecipientError::InvalidDistributionId)?,
        );

        Ok(
            match item.ok_or(RecipientError::DistributionListItemMissing)? {
                proto::distribution_list_item::Item::DeletionTimestamp(deletion_timestamp) => {
                    let at = Timestamp::from_millis(
                        deletion_timestamp,
                        "DistributionList.deletionTimestamp",
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
                    let privacy_mode = PrivacyMode::try_from(privacyMode.enum_value_or_default())?;

                    let members = memberRecipientIds
                        .into_iter()
                        .map(|id| {
                            let id = RecipientId(id);
                            let (kind, recipient_reference) = context
                                .lookup_pair(&id)
                                .ok_or(RecipientError::DistributionListMemberUnknown(id))?;
                            match kind {
                                DestinationKind::Contact => Ok(recipient_reference.clone()),
                                kind @ (DestinationKind::Group
                                | DestinationKind::DistributionList
                                | DestinationKind::Self_
                                | DestinationKind::ReleaseNotes
                                | DestinationKind::CallLink) => {
                                    Err(RecipientError::DistributionListMemberWrongKind(id, *kind))
                                }
                            }
                        })
                        .try_collect()?;

                    Self::List {
                        distribution_id,
                        name,
                        allow_replies: allowReplies,
                        privacy_mode,
                        members,
                    }
                }
            },
        )
    }
}

impl TryFrom<proto::distribution_list::PrivacyMode> for PrivacyMode {
    type Error = RecipientError;

    fn try_from(value: proto::distribution_list::PrivacyMode) -> Result<Self, Self::Error> {
        use proto::distribution_list::PrivacyMode as DistributionPrivacyMode;
        match value {
            DistributionPrivacyMode::UNKNOWN => Err(RecipientError::DistributionListPrivacyUnknown),
            DistributionPrivacyMode::ONLY_WITH => Ok(Self::OnlyWith),
            DistributionPrivacyMode::ALL_EXCEPT => Ok(Self::AllExcept),
            DistributionPrivacyMode::ALL => Ok(Self::All),
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use once_cell::sync::Lazy;
    use protobuf::EnumOrUnknown;
    use test_case::test_case;

    use crate::backup::method::{Contains, Lookup, Store};
    use crate::backup::FullRecipientData;

    use super::*;

    impl proto::Recipient {
        pub(crate) const TEST_ID: u64 = 11111;
        pub(crate) fn test_data() -> Self {
            Self {
                id: Self::TEST_ID,
                destination: Some(proto::recipient::Destination::Self_(Default::default())),
                ..Default::default()
            }
        }
    }

    impl proto::Contact {
        pub(crate) const TEST_ACI: [u8; 16] = [0xaa; 16];
        pub(crate) const TEST_PNI: [u8; 16] = [0xba; 16];
        pub(crate) const TEST_PROFILE_KEY: ProfileKeyBytes = [0x36; 32];

        fn test_data() -> Self {
            Self {
                aci: Some(Self::TEST_ACI.into()),
                pni: Some(Self::TEST_PNI.into()),
                profileKey: Some(Self::TEST_PROFILE_KEY.into()),
                registration: Some(proto::contact::Registration::NotRegistered(
                    Default::default(),
                )),
                username: Some("example.1234".to_owned()),
                profileGivenName: Some("GivenName".to_owned()),
                profileFamilyName: Some("FamilyName".to_owned()),

                ..Default::default()
            }
        }
    }

    impl proto::Group {
        const TEST_MASTER_KEY: GroupMasterKeyBytes = [0x33; 32];

        fn test_data() -> Self {
            Self {
                masterKey: Self::TEST_MASTER_KEY.into(),
                storySendMode: proto::group::StorySendMode::ENABLED.into(),
                ..Self::default()
            }
        }
    }

    impl proto::DistributionListItem {
        const TEST_UUID: [u8; 16] = [0x99; 16];
        fn test_data() -> Self {
            Self {
                distributionId: Self::TEST_UUID.into(),
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
        fn from_proto_test_data() -> Self {
            ContactData {
                aci: Some(Aci::from_uuid_bytes(proto::Contact::TEST_ACI)),
                pni: Some(Pni::from_uuid_bytes(proto::Contact::TEST_PNI)),
                profile_key: Some(proto::Contact::TEST_PROFILE_KEY),
                registration: Registration::NotRegistered {
                    unregistered_at: None,
                },
                username: Some("example.1234".to_owned()),
                e164: None,
                blocked: false,
                visibility: proto::contact::Visibility::VISIBLE,
                profile_sharing: false,
                profile_given_name: Some("GivenName".to_owned()),
                profile_family_name: Some("FamilyName".to_owned()),
                hide_story: false,
            }
        }
    }

    struct TestContext;

    static SELF_RECIPIENT: Lazy<FullRecipientData> =
        Lazy::new(|| FullRecipientData::new(Destination::Self_));
    static CONTACT_RECIPIENT: Lazy<FullRecipientData> = Lazy::new(|| {
        FullRecipientData::new(Destination::Contact(ContactData::from_proto_test_data()))
    });

    impl TestContext {
        const CONTACT_ID: RecipientId = RecipientId(123456789);
        const SELF_ID: RecipientId = RecipientId(1111111111);
    }

    impl Contains<RecipientId> for TestContext {
        fn contains(&self, key: &RecipientId) -> bool {
            key == &Self::CONTACT_ID || key == &Self::SELF_ID
        }
    }

    impl LookupPair<RecipientId, DestinationKind, FullRecipientData> for TestContext {
        fn lookup_pair<'a>(
            &'a self,
            key: &'a RecipientId,
        ) -> Option<(&'a DestinationKind, &'a FullRecipientData)> {
            match *key {
                Self::CONTACT_ID => Some((&DestinationKind::Contact, &CONTACT_RECIPIENT)),
                Self::SELF_ID => Some((&DestinationKind::Self_, &SELF_RECIPIENT)),
                _ => None,
            }
        }
    }

    impl Lookup<RecipientId, FullRecipientData> for TestContext {
        fn lookup(&self, key: &RecipientId) -> Option<&FullRecipientData> {
            match *key {
                Self::CONTACT_ID => Some(&CONTACT_RECIPIENT),
                Self::SELF_ID => Some(&SELF_RECIPIENT),
                _ => None,
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
            Destination::<Store>::try_from_with(recipient, &TestContext),
            Err(RecipientError::MissingDestination)
        );
    }

    #[test]
    fn valid_destination_self() {
        let recipient = proto::Recipient::test_data();

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext),
            Ok(Destination::Self_)
        )
    }

    fn no_aci(input: &mut proto::Contact) {
        input.aci = None;
    }
    fn no_pni(input: &mut proto::Contact) {
        input.pni = None;
    }
    fn no_aci_or_pni(input: &mut proto::Contact) {
        no_aci(input);
        no_pni(input);
    }
    fn no_profile_key(input: &mut proto::Contact) {
        input.profileKey = None;
    }
    fn invalid_aci(input: &mut proto::Contact) {
        input.aci = Some(Vec::from_iter(
            proto::Contact::TEST_ACI.into_iter().chain([0xaa]),
        ));
    }
    fn invalid_pni(input: &mut proto::Contact) {
        input.pni = Some(Vec::from_iter(
            proto::Contact::TEST_PNI.into_iter().chain([0xaa]),
        ));
    }
    fn invalid_profile_key(input: &mut proto::Contact) {
        input.profileKey = Some(Vec::from_iter(
            proto::Contact::TEST_PROFILE_KEY.into_iter().chain([0xaa]),
        ));
    }
    fn registration_unknown(input: &mut proto::Contact) {
        input.registration = None;
    }
    fn profile_no_names(input: &mut proto::Contact) {
        input.profileGivenName = None;
        input.profileFamilyName = None;
    }
    fn visibility_hidden(input: &mut proto::Contact) {
        input.visibility = proto::contact::Visibility::HIDDEN.into();
    }
    fn visibility_default(input: &mut proto::Contact) {
        input.visibility = EnumOrUnknown::default();
    }

    #[test]
    fn valid_destination_contact() {
        let recipient = proto::Recipient {
            destination: Some(proto::Contact::test_data().into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext),
            Ok(Destination::Contact(ContactData::from_proto_test_data()))
        )
    }

    #[test_case(no_aci, Ok(()))]
    #[test_case(no_pni, Ok(()))]
    #[test_case(no_aci_or_pni, Ok(()))]
    #[test_case(invalid_aci, Err(RecipientError::InvalidServiceId(ServiceIdKind::Aci)))]
    #[test_case(invalid_pni, Err(RecipientError::InvalidServiceId(ServiceIdKind::Pni)))]
    #[test_case(no_profile_key, Ok(()))]
    #[test_case(invalid_profile_key, Err(RecipientError::InvalidProfileKey))]
    #[test_case(registration_unknown, Err(RecipientError::ContactRegistrationUnknown))]
    #[test_case(profile_no_names, Ok(()))]
    #[test_case(visibility_hidden, Ok(()))]
    #[test_case(visibility_default, Ok(()))]
    fn destination_contact(
        modifier: fn(&mut proto::Contact),
        expected: Result<(), RecipientError>,
    ) {
        let mut contact = proto::Contact::test_data();
        modifier(&mut contact);

        let recipient = proto::Recipient {
            destination: Some(contact.into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext).map(|_| ()),
            expected
        );
    }

    #[test]
    fn valid_destination_group() {
        let recipient = proto::Recipient {
            destination: Some(proto::Group::test_data().into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext),
            Ok(Destination::Group(GroupData {
                master_key: proto::Group::TEST_MASTER_KEY,
                story_send_mode: proto::group::StorySendMode::ENABLED,
                whitelisted: false,
                hide_story: false,
                snapshot: None,
            }))
        );
    }

    fn invalid_master_key(input: &mut proto::Group) {
        input.masterKey = vec![];
    }
    fn default_story_send_mode(input: &mut proto::Group) {
        input.storySendMode = Default::default();
    }

    #[test_case(invalid_master_key, Err(RecipientError::InvalidMasterKey))]
    #[test_case(default_story_send_mode, Ok(()))]
    fn destination_group(modifier: fn(&mut proto::Group), expected: Result<(), RecipientError>) {
        let mut group = proto::Group::test_data();
        modifier(&mut group);

        let recipient = proto::Recipient {
            destination: Some(group.into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext).map(|_| ()),
            expected
        );
    }

    #[test]
    fn valid_distribution_list() {
        let recipient = proto::Recipient {
            destination: Some(proto::DistributionListItem::test_data().into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext),
            Ok(Destination::DistributionList(DistributionListItem::List {
                distribution_id: Uuid::from_bytes(proto::DistributionListItem::TEST_UUID),
                privacy_mode: PrivacyMode::AllExcept,
                name: "".to_owned(),
                allow_replies: false,
                members: vec![CONTACT_RECIPIENT.clone()].into()
            }))
        );
    }

    const UNKNOWN_RECIPIENT_ID: RecipientId = RecipientId(9999999999);

    fn invalid_distribution_id(input: &mut proto::DistributionListItem) {
        input.distributionId = vec![0x55; proto::DistributionListItem::TEST_UUID.len() * 2];
    }
    fn privacy_mode_unknown(input: &mut proto::DistributionListItem) {
        input.mut_distributionList().privacyMode = EnumOrUnknown::default();
    }
    fn unknown_member(input: &mut proto::DistributionListItem) {
        input.mut_distributionList().memberRecipientIds = vec![UNKNOWN_RECIPIENT_ID.0];
    }
    fn member_is_not_a_contact(input: &mut proto::DistributionListItem) {
        input
            .mut_distributionList()
            .memberRecipientIds
            .push(TestContext::SELF_ID.0);
    }

    #[test_case(invalid_distribution_id, Err(RecipientError::InvalidDistributionId))]
    #[test_case(
        privacy_mode_unknown,
        Err(RecipientError::DistributionListPrivacyUnknown)
    )]
    #[test_case(
        unknown_member,
        Err(RecipientError::DistributionListMemberUnknown(UNKNOWN_RECIPIENT_ID))
    )]
    #[test_case(
        member_is_not_a_contact,
        Err(RecipientError::DistributionListMemberWrongKind(
            TestContext::SELF_ID,
            DestinationKind::Self_
        ))
    )]
    fn destination_distribution_list(
        modifier: fn(&mut proto::DistributionListItem),
        expected: Result<(), RecipientError>,
    ) {
        let mut distribution_list = proto::DistributionListItem::test_data();
        modifier(&mut distribution_list);

        let recipient = proto::Recipient {
            destination: Some(distribution_list.into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            Destination::<Store>::try_from_with(recipient, &TestContext).map(|_| ()),
            expected
        );
    }
}
