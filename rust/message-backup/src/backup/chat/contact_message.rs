// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use protobuf::EnumOrUnknown;

use crate::backup::chat::{ChatItemError, Reaction};
use crate::backup::frame::RecipientId;
use crate::backup::method::Contains;
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of [`proto::ContactMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ContactMessage {
    pub contacts: Vec<ContactAttachment>,
    pub reactions: Vec<Reaction>,
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
    #[serde(skip)]
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ContactAttachmentError {
    /// {0} type is unknown                                                                                                                                                                                                                                                                                                                                                                                                
    UnknownType(&'static str),
}

impl<R: Contains<RecipientId>> TryFromWith<proto::ContactMessage, R> for ContactMessage {
    type Error = ChatItemError;

    fn try_from_with(item: proto::ContactMessage, context: &R) -> Result<Self, Self::Error> {
        let proto::ContactMessage {
            reactions,
            contact,
            special_fields: _,
        } = item;

        let reactions = reactions
            .into_iter()
            .map(|r| r.try_into_with(context))
            .collect::<Result<_, _>>()?;

        let contacts = contact
            .into_iter()
            .map(|c| c.try_into())
            .collect::<Result<_, _>>()?;

        Ok(Self {
            contacts,
            reactions,
            _limit_construction_to_module: (),
        })
    }
}

impl TryFrom<proto::ContactAttachment> for ContactAttachment {
    type Error = ContactAttachmentError;

    fn try_from(value: proto::ContactAttachment) -> Result<Self, Self::Error> {
        let proto::ContactAttachment {
            name,
            number,
            email,
            address,
            organization,
            special_fields: _,
            // TODO validate this field
            avatar: _,
        } = value;

        if let Some(proto::contact_attachment::Name {
            // Ignore all these fields, but cause a compilation error if
            // they are changed.
            givenName: _,
            familyName: _,
            prefix: _,
            suffix: _,
            middleName: _,
            displayName: _,
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

        Ok(ContactAttachment {
            name: name.into_option(),
            number,
            email,
            address,
            organization,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use crate::backup::chat::testutil::{
        invalid_reaction, no_reactions, ProtoHasField, TestContext,
    };
    use crate::backup::chat::ReactionError;

    use super::*;

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

    impl ProtoHasField<Vec<proto::Reaction>> for proto::ContactMessage {
        fn get_field_mut(&mut self) -> &mut Vec<proto::Reaction> {
            &mut self.reactions
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
                reactions: vec![Reaction::from_proto_test_data()],
                _limit_construction_to_module: ()
            })
        )
    }

    #[test_case(no_reactions, Ok(()))]
    #[test_case(
        invalid_reaction,
        Err(ChatItemError::Reaction(ReactionError::EmptyEmoji))
    )]
    fn contact_message(
        modifier: fn(&mut proto::ContactMessage),
        expected: Result<(), ChatItemError>,
    ) {
        let mut message = proto::ContactMessage::test_data();
        modifier(&mut message);

        let result = message
            .try_into_with(&TestContext::default())
            .map(|_: ContactMessage| ());
        assert_eq!(result, expected);
    }
}
