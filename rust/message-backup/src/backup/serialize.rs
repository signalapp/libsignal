//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol::ServiceId;
use serde::ser::{SerializeStruct as _, SerializeTupleVariant as _};
use serde::{Serialize, Serializer};

use crate::proto::backup as proto;

/// Serializes using [`ToString`].
pub(crate) fn to_string<S: Serializer>(t: &impl ToString, s: S) -> Result<S::Ok, S::Error> {
    t.to_string().serialize(s)
}

/// Serializes using [`ServiceId::service_id_string`].
pub(crate) fn service_id_as_string<S: Serializer>(
    id: &(impl Copy + Into<ServiceId>),
    serializer: S,
) -> Result<S::Ok, S::Error> {
    (*id).into().service_id_string().serialize(serializer)
}

/// Serializes using [`ServiceId::service_id_string`].
pub(crate) fn optional_service_id_as_string<S: Serializer>(
    id: &Option<(impl Copy + Into<ServiceId>)>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    (*id)
        .map(|id| id.into().service_id_string())
        .serialize(serializer)
}

/// Serializes [`protobuf::Enum`] types as strings.
pub(crate) fn enum_as_string<S: Serializer>(
    source: &impl protobuf::Enum,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    format!("{source:?}").serialize(serializer)
}

/// Serializes [`protobuf::Message`] types as hex-encoded protobuf wire format.
pub(crate) fn optional_proto_message_as_bytes<S: Serializer, M: protobuf::Message>(
    message: &Option<impl std::ops::Deref<Target = M>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    struct MessageAsHexBytes<T>(T);
    impl<T: protobuf::Message> Serialize for MessageAsHexBytes<&'_ T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::new();
            self.0
                .write_to_vec(&mut bytes)
                .map_err(<S::Error as serde::ser::Error>::custom)?;

            hex::serialize(bytes, serializer)
        }
    }

    message
        .as_deref()
        .map(MessageAsHexBytes)
        .serialize(serializer)
}

impl serde::Serialize for proto::contact_attachment::Name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Self {
            givenName,
            familyName,
            prefix,
            suffix,
            middleName,
            displayName,
            special_fields: _,
        } = self;
        let mut ser = serializer.serialize_struct("Name", 6)?;
        ser.serialize_field("givenName", givenName)?;
        ser.serialize_field("familyName", familyName)?;
        ser.serialize_field("prefix", prefix)?;
        ser.serialize_field("suffix", suffix)?;
        ser.serialize_field("middleName", middleName)?;
        ser.serialize_field("displayName", displayName)?;
        ser.end()
    }
}

impl serde::Serialize for proto::contact_attachment::Phone {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Self {
            value,
            type_,
            label,
            special_fields: _,
        } = self;
        let mut ser = serializer.serialize_struct("Phone", 3)?;
        ser.serialize_field("value", value)?;
        ser.serialize_field("type_", &format!("{:?}", type_))?;
        ser.serialize_field("label", label)?;
        ser.end()
    }
}

impl serde::Serialize for proto::contact_attachment::Email {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Self {
            value,
            type_,
            label,
            special_fields: _,
        } = self;
        let mut ser = serializer.serialize_struct("Email", 3)?;
        ser.serialize_field("value", value)?;
        ser.serialize_field("type_", &format!("{:?}", type_))?;
        ser.serialize_field("label", label)?;
        ser.end()
    }
}

impl serde::Serialize for proto::contact_attachment::PostalAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Self {
            type_,
            label,
            street,
            pobox,
            neighborhood,
            city,
            region,
            postcode,
            country,
            special_fields: _,
        } = self;
        let mut ser = serializer.serialize_struct("PostalAddress", 9)?;
        ser.serialize_field("type_", &format!("{:?}", type_))?;
        ser.serialize_field("label", label)?;
        ser.serialize_field("street", street)?;
        ser.serialize_field("pobox", pobox)?;
        ser.serialize_field("neighborhood", neighborhood)?;
        ser.serialize_field("city", city)?;
        ser.serialize_field("region", region)?;
        ser.serialize_field("postcode", postcode)?;
        ser.serialize_field("country", country)?;
        ser.end()
    }
}

impl serde::Serialize for proto::learned_profile_chat_update::PreviousName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            proto::learned_profile_chat_update::PreviousName::E164(e164) => {
                let mut tv = serializer.serialize_tuple_variant("PreviousName", 0, "E164", 1)?;
                tv.serialize_field(e164)?;
                tv.end()
            }
            proto::learned_profile_chat_update::PreviousName::Username(username) => {
                let mut tv =
                    serializer.serialize_tuple_variant("PreviousName", 1, "Username", 1)?;
                tv.serialize_field(username)?;
                tv.end()
            }
        }
    }
}
