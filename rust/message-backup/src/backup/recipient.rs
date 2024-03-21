//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU64;

use derive_where::derive_where;
use libsignal_protocol::{Aci, Pni, ServiceIdKind};
use uuid::Uuid;
use zkgroup::{GroupMasterKeyBytes, ProfileKeyBytes};

use crate::backup::method::{Method, Store};
use crate::backup::time::Timestamp;
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
}

#[derive_where(Debug)]
#[derive_where(PartialEq; M::Value<Destination>: PartialEq)]
pub struct RecipientData<M: Method = Store> {
    pub destination: M::Value<Destination>,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Destination {
    Contact(ContactData),
    Group(GroupData),
    DistributionList(DistributionListData),
    Self_,
    ReleaseNotes,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ContactData {
    pub aci: Option<Aci>,
    pub pni: Option<Pni>,
    pub profile_key: Option<ProfileKeyBytes>,
    pub registered: bool,
}

#[non_exhaustive]
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct GroupData {
    pub master_key: GroupMasterKeyBytes,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct DistributionListData {
    pub distribution_id: Uuid,
    pub privacy_mode: PrivacyMode,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum PrivacyMode {
    OnlyWith,
    AllExcept,
    All,
}

impl<M: Method> TryFrom<proto::Recipient> for RecipientData<M> {
    type Error = RecipientError;
    fn try_from(value: proto::Recipient) -> Result<Self, Self::Error> {
        let proto::Recipient {
            id: _,
            destination,
            special_fields: _,
        } = value;

        let destination = destination.ok_or(RecipientError::MissingDestination)?;

        let destination = match destination {
            RecipientDestination::Contact(contact) => Destination::Contact(contact.try_into()?),
            RecipientDestination::Group(group) => Destination::Group(group.try_into()?),
            RecipientDestination::DistributionList(list) => {
                Destination::DistributionList(list.try_into()?)
            }
            RecipientDestination::Self_(proto::Self_ { special_fields: _ }) => Destination::Self_,
            RecipientDestination::ReleaseNotes(proto::ReleaseNotes { special_fields: _ }) => {
                Destination::ReleaseNotes
            }
        };

        Ok(Self {
            destination: M::value(destination),
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
            registered,
            unregisteredTimestamp,

            // TODO validate these fields
            username: _,
            e164: _,
            blocked: _,
            hidden: _,
            profileSharing: _,
            profileGivenName: _,
            profileFamilyName: _,
            hideStory: _,
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

        let profile_key = profileKey
            .map(TryInto::try_into)
            .transpose()
            .map_err(|_| RecipientError::InvalidProfileKey)?;

        let registered = match registered.enum_value_or_default() {
            proto::contact::Registered::UNKNOWN => {
                return Err(RecipientError::ContactRegistrationUnknown)
            }
            proto::contact::Registered::REGISTERED => true,
            proto::contact::Registered::NOT_REGISTERED => false,
        };

        let _ = NonZeroU64::new(unregisteredTimestamp)
            .map(|u| Timestamp::from_millis(u.get(), "Contact.unregisteredTimestamp"));

        Ok(Self {
            aci,
            pni,
            profile_key,
            registered,
        })
    }
}

impl TryFrom<proto::Group> for GroupData {
    type Error = RecipientError;
    fn try_from(value: proto::Group) -> Result<Self, Self::Error> {
        let proto::Group {
            masterKey,
            // TODO validate these fields.
            whitelisted: _,
            hideStory: _,
            storySendMode: _,
            name: _,
            special_fields: _,
        } = value;

        let master_key = masterKey
            .try_into()
            .map_err(|_| RecipientError::InvalidMasterKey)?;
        Ok(GroupData { master_key })
    }
}

impl TryFrom<proto::DistributionList> for DistributionListData {
    type Error = RecipientError;

    fn try_from(value: proto::DistributionList) -> Result<Self, Self::Error> {
        let proto::DistributionList {
            distributionId,
            privacyMode,
            deletionTimestamp,
            // TODO validate these fields.
            name: _,
            allowReplies: _,
            memberRecipientIds: _,
            special_fields: _,
        } = value;

        let distribution_id = Uuid::from_bytes(
            distributionId
                .try_into()
                .map_err(|_| RecipientError::InvalidDistributionId)?,
        );

        let privacy_mode = PrivacyMode::try_from(privacyMode.enum_value_or_default())?;

        let _ = NonZeroU64::new(deletionTimestamp)
            .map(|u| Timestamp::from_millis(u.get(), "DistributionList.deletionTimestamp"));

        Ok(Self {
            distribution_id,
            privacy_mode,
        })
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
    use protobuf::EnumOrUnknown;
    use test_case::test_case;

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
                registered: proto::contact::Registered::NOT_REGISTERED.into(),
                ..Default::default()
            }
        }
    }

    impl proto::Group {
        const TEST_MASTER_KEY: GroupMasterKeyBytes = [0x33; 32];

        fn test_data() -> Self {
            Self {
                masterKey: Self::TEST_MASTER_KEY.into(),
                ..Self::default()
            }
        }
    }

    impl proto::DistributionList {
        const TEST_UUID: [u8; 16] = [0x99; 16];
        fn test_data() -> Self {
            Self {
                distributionId: Self::TEST_UUID.into(),
                privacyMode: proto::distribution_list::PrivacyMode::ALL_EXCEPT.into(),
                ..Self::default()
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
            RecipientData::<Store>::try_from(recipient),
            Err(RecipientError::MissingDestination)
        );
    }

    #[test]
    fn valid_destination_self() {
        let recipient = proto::Recipient::test_data();

        assert_eq!(
            RecipientData::<Store>::try_from(recipient),
            Ok(RecipientData {
                destination: Destination::Self_
            })
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
        input.registered = EnumOrUnknown::default();
    }

    #[test]
    fn valid_destination_contact() {
        let recipient = proto::Recipient {
            destination: Some(proto::Contact::test_data().into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            RecipientData::<Store>::try_from(recipient),
            Ok(RecipientData {
                destination: Destination::Contact(ContactData {
                    aci: Some(Aci::from_uuid_bytes(proto::Contact::TEST_ACI)),
                    pni: Some(Pni::from_uuid_bytes(proto::Contact::TEST_PNI)),
                    profile_key: Some(proto::Contact::TEST_PROFILE_KEY),
                    registered: false,
                })
            })
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
            RecipientData::<Store>::try_from(recipient).map(|_| ()),
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
            RecipientData::<Store>::try_from(recipient),
            Ok(RecipientData {
                destination: Destination::Group(GroupData {
                    master_key: proto::Group::TEST_MASTER_KEY
                })
            })
        );
    }

    fn invalid_master_key(input: &mut proto::Group) {
        input.masterKey = vec![];
    }

    #[test_case(invalid_master_key, Err(RecipientError::InvalidMasterKey))]
    fn destination_group(modifier: fn(&mut proto::Group), expected: Result<(), RecipientError>) {
        let mut group = proto::Group::test_data();
        modifier(&mut group);

        let recipient = proto::Recipient {
            destination: Some(group.into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            RecipientData::<Store>::try_from(recipient).map(|_| ()),
            expected
        );
    }

    #[test]
    fn valid_distribution_list() {
        let recipient = proto::Recipient {
            destination: Some(proto::DistributionList::test_data().into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            RecipientData::<Store>::try_from(recipient),
            Ok(RecipientData {
                destination: Destination::DistributionList(DistributionListData {
                    distribution_id: Uuid::from_bytes(proto::DistributionList::TEST_UUID),
                    privacy_mode: PrivacyMode::AllExcept,
                })
            })
        );
    }

    fn invalid_distribution_id(input: &mut proto::DistributionList) {
        input.distributionId = vec![0x55; proto::DistributionList::TEST_UUID.len() * 2];
    }
    fn privacy_mode_unknown(input: &mut proto::DistributionList) {
        input.privacyMode = EnumOrUnknown::default();
    }

    #[test_case(invalid_distribution_id, Err(RecipientError::InvalidDistributionId))]
    #[test_case(
        privacy_mode_unknown,
        Err(RecipientError::DistributionListPrivacyUnknown)
    )]
    fn destination_distribution_list(
        modifier: fn(&mut proto::DistributionList),
        expected: Result<(), RecipientError>,
    ) {
        let mut distribution_list = proto::DistributionList::test_data();
        modifier(&mut distribution_list);

        let recipient = proto::Recipient {
            destination: Some(distribution_list.into()),
            ..proto::Recipient::test_data()
        };

        assert_eq!(
            RecipientData::<Store>::try_from(recipient).map(|_| ()),
            expected
        );
    }
}
