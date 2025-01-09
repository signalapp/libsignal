// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
use derive_where::derive_where;

use crate::backup::chat::{ChatItemError, ReactionSet};
use crate::backup::file::{FilePointer, FilePointerError};
use crate::backup::frame::RecipientId;
use crate::backup::method::LookupPair;
use crate::backup::recipient::MinimalRecipientData;
use crate::backup::serialize::SerializeOrder;
use crate::backup::time::ReportUnusualTimestamp;
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of [`proto::ContactMessage`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; Recipient: PartialEq + SerializeOrder))]
pub struct ContactMessage<Recipient> {
    pub contact: Box<ContactAttachment>,
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
    pub organization: String,
    pub avatar: Option<FilePointer>,
    #[serde(skip)]
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ContactAttachmentError {
    /// contact message without attachment
    Missing,
    /// {0} type is unknown                                                                                                                                                                                                                                                                                                                                                                                                
    UnknownType(&'static str),
    /// Name is present but empty
    EmptyName,
    /// {0:?} phone number missing value
    PhoneNumberMissingValue(proto::contact_attachment::phone::Type),
    /// {0:?} email missing value
    EmailMissingValue(proto::contact_attachment::email::Type),
    /// {0:?} address is empty
    EmptyAddress(proto::contact_attachment::postal_address::Type),
    /// avatar: {0}
    Avatar(FilePointerError),
}

impl<R: Clone, C: LookupPair<RecipientId, MinimalRecipientData, R> + ReportUnusualTimestamp>
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

        let contact = contact
            .into_option()
            .ok_or(ContactAttachmentError::Missing)?
            .try_into_with(context)?;

        Ok(Self {
            contact: Box::new(contact),
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
            givenName,
            familyName,
            prefix,
            suffix,
            middleName,
            nickname,
            special_fields: _,
        }) = name.as_ref()
        {
            if givenName.is_empty()
                && familyName.is_empty()
                && prefix.is_empty()
                && suffix.is_empty()
                && middleName.is_empty()
                && nickname.is_empty()
            {
                // We could disallow just sending a prefix or suffix, but that seems overly nitpicky.
                return Err(ContactAttachmentError::EmptyName);
            }
        }

        for proto::contact_attachment::Phone {
            type_,
            value,
            label: _,
            special_fields: _,
        } in &number
        {
            let type_ = type_.enum_value_or_default();
            if type_ == proto::contact_attachment::phone::Type::UNKNOWN {
                return Err(ContactAttachmentError::UnknownType("phone number"));
            }
            if value.is_empty() {
                return Err(ContactAttachmentError::PhoneNumberMissingValue(type_));
            }
        }

        for proto::contact_attachment::Email {
            type_,
            value,
            label: _,
            special_fields: _,
        } in &email
        {
            let type_ = type_.enum_value_or_default();
            if type_ == proto::contact_attachment::email::Type::UNKNOWN {
                return Err(ContactAttachmentError::UnknownType("email"));
            }
            if value.is_empty() {
                return Err(ContactAttachmentError::EmailMissingValue(type_));
            }
        }

        for proto::contact_attachment::PostalAddress {
            type_,
            label: _,
            street,
            pobox,
            neighborhood,
            city,
            region,
            postcode,
            country,
            special_fields: _,
        } in &address
        {
            let type_ = type_.enum_value_or_default();
            if type_ == proto::contact_attachment::postal_address::Type::UNKNOWN {
                return Err(ContactAttachmentError::UnknownType("address"));
            }
            if street.is_empty()
                && pobox.is_empty()
                && neighborhood.is_empty()
                && city.is_empty()
                && region.is_empty()
                && postcode.is_empty()
                && country.is_empty()
            {
                return Err(ContactAttachmentError::EmptyAddress(type_));
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
                contact: Some(proto::ContactAttachment::test_data()).into(),
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
                organization: "".to_owned(),
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
                contact: ContactAttachment::from_proto_test_data().into(),
                reactions: ReactionSet::from_iter([Reaction::from_proto_test_data()]),
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
    #[test_case(|x| x.contact = None.into() => Err(ChatItemError::ContactAttachment(ContactAttachmentError::Missing)); "no attachment")]
    #[test_case(|x| x.contact.as_mut().unwrap().avatar = Some(proto::FilePointer::test_data()).into() => Ok(()); "with avatar")]
    #[test_case(
        |x| x.contact.as_mut().unwrap().avatar = Some(proto::FilePointer::default()).into() =>
        Err(ChatItemError::ContactAttachment(ContactAttachmentError::Avatar(
            FilePointerError::NoLocator
        )));
        "with invalid avatar"
    )]
    #[test_case(
        |x| x.contact.as_mut().unwrap().name = Some(Default::default()).into() =>
        Err(ChatItemError::ContactAttachment(ContactAttachmentError::EmptyName));
        "empty name"
    )]
    #[test_case(
        |x| x.contact.as_mut().unwrap().number.push(proto::contact_attachment::Phone {
            type_: proto::contact_attachment::phone::Type::HOME.into(),
            ..Default::default()
        }) =>
        Err(ChatItemError::ContactAttachment(ContactAttachmentError::PhoneNumberMissingValue(proto::contact_attachment::phone::Type::HOME)));
        "empty phone number"
    )]
    #[test_case(
        |x| x.contact.as_mut().unwrap().number.push(proto::contact_attachment::Phone {
            type_: proto::contact_attachment::phone::Type::HOME.into(),
            value: "unvalidated".into(),
            ..Default::default()
        }) =>
        Ok(());
        "empty phone number label"
    )]
    #[test_case(
        |x| x.contact.as_mut().unwrap().email.push(proto::contact_attachment::Email {
            type_: proto::contact_attachment::email::Type::HOME.into(),
            ..Default::default()
        }) =>
        Err(ChatItemError::ContactAttachment(ContactAttachmentError::EmailMissingValue(proto::contact_attachment::email::Type::HOME)));
        "empty email"
    )]
    #[test_case(
        |x| x.contact.as_mut().unwrap().email.push(proto::contact_attachment::Email {
            type_: proto::contact_attachment::email::Type::HOME.into(),
            value: "unvalidated".into(),
            ..Default::default()
        }) =>
        Ok(());
        "empty email label"
    )]
    #[test_case(
        |x| x.contact.as_mut().unwrap().address.push(proto::contact_attachment::PostalAddress {
            type_: proto::contact_attachment::postal_address::Type::HOME.into(),
            ..Default::default()
        }) =>
        Err(ChatItemError::ContactAttachment(ContactAttachmentError::EmptyAddress(proto::contact_attachment::postal_address::Type::HOME)));
        "empty postal address"
    )]
    fn contact_message(modifier: fn(&mut proto::ContactMessage)) -> Result<(), ChatItemError> {
        let mut message = proto::ContactMessage::test_data();
        modifier(&mut message);

        message
            .try_into_with(&TestContext::default())
            .map(|_: ContactMessage<FullRecipientData>| ())
    }
}
