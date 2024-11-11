// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
use derive_where::derive_where;
use protobuf::EnumOrUnknown;

use crate::backup::chat::{ChatItemError, ReactionSet};
use crate::backup::file::{FilePointer, FilePointerError};
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::DestinationKind;
use crate::backup::serialize::SerializeOrder;
use crate::backup::time::ReportUnusualTimestamp;
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of [`proto::ContactMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq + SerializeOrder))]
pub struct ContactMessage<Recipient> {
    pub contacts: Vec<ContactAttachment>,
    #[serde(bound(serialize = "Recipient: serde::Serialize + SerializeOrder"))]
    pub reactions: ReactionSet<Recipient>,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::ContactAttachment`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ContactAttachment {
    pub name: Option<proto::contact_attachment::Name>,
    pub number: Vec<proto::contact_attachment::Phone>,
    pub email: Vec<proto::contact_attachment::Email>,
    pub address: Vec<proto::contact_attachment::PostalAddress>,
    pub organization: Option<String>,
    pub avatar: Option<FilePointer>,
    #[serde(skip)]
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ContactAttachmentError {
    /// {0} type is unknown                                                                                                                                                                                                                                                                                                                                                                                                
    UnknownType(&'static str),
    /// avatar: {0}
    Avatar(FilePointerError),
}

impl<R: Clone, C: LookupPair<RecipientId, DestinationKind, R> + ReportUnusualTimestamp>
    TryFromWith<proto::ContactMessage, C> for ContactMessage<R>
{
    type Error = ChatItemError;

    fn try_from_with(item: proto::ContactMessage, context: &C) -> Result<Self, Self::Error> {
        let proto::ContactMessage {
            reactions,
            contact,
            special_fields: _,
        } = item;

        let reactions = reactions.try_into_with(context)?;

        let contacts = contact
            .into_iter()
            .map(|c| c.try_into_with(context))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            contacts,
            reactions,
            _limit_construction_to_module: (),
        })
    }
}

impl<C: ReportUnusualTimestamp> TryFromWith<proto::ContactAttachment, C> for ContactAttachment {
    type Error = ContactAttachmentError;

    fn try_from_with(value: proto::ContactAttachment, context: &C) -> Result<Self, Self::Error> {
        let proto::ContactAttachment {
            name,
            number,
            email,
            address,
            organization,
            avatar,
            special_fields: _,
        } = value;

        if let Some(proto::contact_attachment::Name {
            // Ignore all these fields, but cause a compilation error if
            // they are changed.
            givenName: _,
            familyName: _,
            prefix: _,
            suffix: _,
            middleName: _,
            nickname: _,
            special_fields: _,
        }) = name.as_ref()
        {}

        for proto::contact_attachment::Phone {
            type_,
            value: _,
            label: _,
            special_fields: _,
        } in &number
        {
            if let Some(proto::contact_attachment::phone::Type::UNKNOWN) =
                type_.as_ref().map(EnumOrUnknown::enum_value_or_default)
            {
                return Err(ContactAttachmentError::UnknownType("phone number"));
            }
        }

        for proto::contact_attachment::Email {
            type_,
            value: _,
            label: _,
            special_fields: _,
        } in &email
        {
            if let Some(proto::contact_attachment::email::Type::UNKNOWN) =
                type_.as_ref().map(EnumOrUnknown::enum_value_or_default)
            {
                return Err(ContactAttachmentError::UnknownType("email"));
            }
        }

        for proto::contact_attachment::PostalAddress {
            type_,
            label: _,
            street: _,
            pobox: _,
            neighborhood: _,
            city: _,
            region: _,
            postcode: _,
            country: _,
            special_fields: _,
        } in &address
        {
            if let Some(proto::contact_attachment::postal_address::Type::UNKNOWN) =
                type_.as_ref().map(EnumOrUnknown::enum_value_or_default)
            {
                return Err(ContactAttachmentError::UnknownType("address"));
            }
        }

        let avatar = avatar
            .into_option()
            .map(|file| FilePointer::try_from_with(file, context))
            .transpose()
            .map_err(ContactAttachmentError::Avatar)?;

        Ok(ContactAttachment {
            name: name.into_option(),
            number,
            email,
            address,
            organization,
            avatar,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;
    use crate::backup::chat::{Reaction, ReactionError};
    use crate::backup::recipient::FullRecipientData;
    use crate::backup::testutil::TestContext;

    impl proto::ContactMessage {
        fn test_data() -> Self {
            Self {
                reactions: vec![proto::Reaction::test_data()],
                contact: vec![proto::ContactAttachment::test_data()],
                ..Default::default()
            }
        }
    }

    impl proto::ContactAttachment {
        fn test_data() -> Self {
            Self {
                ..Default::default()
            }
        }
    }

    impl ContactAttachment {
        fn from_proto_test_data() -> Self {
            Self {
                name: None,
                number: vec![],
                email: vec![],
                address: vec![],
                organization: None,
                avatar: None,
                _limit_construction_to_module: (),
            }
        }
    }

    #[test]
    fn valid_contact_message() {
        assert_eq!(
            proto::ContactMessage::test_data().try_into_with(&TestContext::default()),
            Ok(ContactMessage {
                contacts: vec![ContactAttachment::from_proto_test_data()],
                reactions: ReactionSet::from_iter([(
                    TestContext::SELF_ID,
                    Reaction::from_proto_test_data(),
                )]),
                _limit_construction_to_module: ()
            })
        )
    }

    #[test_case(|x| x.reactions.clear() => Ok(()); "no reactions")]
    #[test_case(
        |x| x.reactions.push(proto::Reaction::default()) =>
        Err(ChatItemError::Reaction(ReactionError::EmptyEmoji));
        "invalid reaction"
    )]
    #[test_case(|x| x.contact[0].avatar = Some(proto::FilePointer::test_data()).into() => Ok(()); "with avatar")]
    #[test_case(
        |x| x.contact[0].avatar = Some(proto::FilePointer::default()).into() =>
        Err(ChatItemError::ContactAttachment(ContactAttachmentError::Avatar(
            FilePointerError::NoLocator
        )));
        "with invalid avatar"
    )]
    fn contact_message(modifier: fn(&mut proto::ContactMessage)) -> Result<(), ChatItemError> {
        let mut message = proto::ContactMessage::test_data();
        modifier(&mut message);

        message
            .try_into_with(&TestContext::default())
            .map(|_: ContactMessage<FullRecipientData>| ())
    }
}
