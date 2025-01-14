//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(missing_docs)]

//! Types for identifying an individual Signal client instance.

use std::fmt;

use uuid::Uuid;

/// Known types of [ServiceId].
#[derive(Clone, Copy, Hash, PartialEq, Eq, num_enum::IntoPrimitive, num_enum::TryFromPrimitive)]
#[repr(u8)]
pub enum ServiceIdKind {
    /// An [Aci].
    Aci,
    /// A [Pni].
    Pni,
}

impl fmt::Display for ServiceIdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceIdKind::Aci => f.write_str("ACI"),
            ServiceIdKind::Pni => f.write_str("PNI"),
        }
    }
}

impl fmt::Debug for ServiceIdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// The error returned for a failed "downcast" conversion from a [`ServiceId`] to a specific kind of
/// service ID (e.g. [`Pni`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrongKindOfServiceIdError {
    /// The kind of service ID being converted to.
    pub expected: ServiceIdKind,
    /// The actual kind of the service ID being converted.
    pub actual: ServiceIdKind,
}

/// A service ID with a known type.
///
/// `RAW_KIND` is a raw [ServiceIdKind] (eventually Rust will allow enums as generic parameters).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpecificServiceId<const RAW_KIND: u8>(Uuid);

impl<const KIND: u8> SpecificServiceId<KIND> {
    /// Convenience function to go directly from bytes to a specific kind of service ID.
    ///
    /// Prefer `from(Uuid)` / `Uuid::into` if you already have a strongly-typed UUID.
    #[inline]
    pub const fn from_uuid_bytes(bytes: [u8; 16]) -> Self {
        Self::from_uuid(uuid::Uuid::from_bytes(bytes))
    }

    #[inline]
    const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

// We can go back to derive(Hash) if the uuid crate makes a similar change:
// https://github.com/uuid-rs/uuid/issues/775
impl<const KIND: u8> std::hash::Hash for SpecificServiceId<KIND> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.0.as_bytes());
    }
}

impl<const KIND: u8> SpecificServiceId<KIND>
where
    ServiceId: From<Self>,
    Self: TryFrom<ServiceId>,
{
    /// The standard variable-width binary representation for a Signal service ID.
    ///
    /// This format is not self-delimiting; the length is needed to decode it.
    #[inline]
    pub fn service_id_binary(&self) -> Vec<u8> {
        ServiceId::from(*self).service_id_binary()
    }

    /// The standard fixed-width binary representation for a Signal service ID.
    #[inline]
    pub fn service_id_fixed_width_binary(&self) -> ServiceIdFixedWidthBinaryBytes {
        ServiceId::from(*self).service_id_fixed_width_binary()
    }

    /// The standard string representation for a Signal service ID.
    pub fn service_id_string(&self) -> String {
        ServiceId::from(*self).service_id_string()
    }

    /// Parses from the standard binary representation, returning `None` if invalid.
    #[inline]
    pub fn parse_from_service_id_binary(bytes: &[u8]) -> Option<Self> {
        ServiceId::parse_from_service_id_binary(bytes)?
            .try_into()
            .ok()
    }

    /// Parses from the standard binary representation, returning `None` if invalid.
    #[inline]
    pub fn parse_from_service_id_fixed_width_binary(
        bytes: &ServiceIdFixedWidthBinaryBytes,
    ) -> Option<Self> {
        ServiceId::parse_from_service_id_fixed_width_binary(bytes)?
            .try_into()
            .ok()
    }

    /// Parses from the standard String representation, returning `None` if invalid.
    ///
    /// The UUID parsing is case-insensitive.
    pub fn parse_from_service_id_string(input: &str) -> Option<Self> {
        ServiceId::parse_from_service_id_string(input)?
            .try_into()
            .ok()
    }
}

impl<const KIND: u8> From<Uuid> for SpecificServiceId<KIND> {
    #[inline]
    fn from(value: Uuid) -> Self {
        Self::from_uuid(value)
    }
}

impl<const KIND: u8> From<SpecificServiceId<KIND>> for Uuid {
    #[inline]
    fn from(value: SpecificServiceId<KIND>) -> Self {
        value.0
    }
}

impl<const KIND: u8> fmt::Debug for SpecificServiceId<KIND>
where
    ServiceId: From<Self>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ServiceId::from(*self).fmt(f)
    }
}

/// A service ID representing an ACI ("ACcount Identifier").
///
/// See also [ServiceId].
pub type Aci = SpecificServiceId<{ ServiceIdKind::Aci as u8 }>;

/// A service ID representing a PNI ("Phone Number Identifier").
///
/// See also [ServiceId].
pub type Pni = SpecificServiceId<{ ServiceIdKind::Pni as u8 }>;

/// The fixed-width binary representation of a ServiceId.
///
/// Rarely used. The variable-width format that privileges ACIs is preferred.
pub type ServiceIdFixedWidthBinaryBytes = [u8; 17];

/// A Signal service ID, which can be one of various types.
///
/// Conceptually this is a UUID in a particular "namespace" representing a particular way to reach a
/// user on the Signal service.
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, derive_more::From)]
pub enum ServiceId {
    /// An ACI
    Aci(Aci),
    /// A PNI
    Pni(Pni),
}

impl ServiceId {
    /// The kind of service ID `self` is.
    #[inline]
    pub fn kind(&self) -> ServiceIdKind {
        match self {
            ServiceId::Aci(_) => ServiceIdKind::Aci,
            ServiceId::Pni(_) => ServiceIdKind::Pni,
        }
    }

    /// The standard variable-width binary representation for a Signal service ID.
    ///
    /// This format is not self-delimiting; the length is needed to decode it.
    #[inline]
    pub fn service_id_binary(&self) -> Vec<u8> {
        if let Self::Aci(aci) = self {
            aci.0.as_bytes().to_vec()
        } else {
            self.service_id_fixed_width_binary().to_vec()
        }
    }

    /// The standard fixed-width binary representation for a Signal service ID.
    #[inline]
    pub fn service_id_fixed_width_binary(&self) -> ServiceIdFixedWidthBinaryBytes {
        let mut result = [0; 17];
        result[0] = self.kind().into();
        result[1..].copy_from_slice(self.raw_uuid().as_bytes());
        result
    }

    /// The standard string representation for a Signal service ID.
    pub fn service_id_string(&self) -> String {
        if let Self::Aci(aci) = self {
            aci.0.to_string()
        } else {
            format!("{}:{}", self.kind(), self.raw_uuid())
        }
    }

    /// Parses from the standard binary representation, returning `None` if invalid.
    #[inline]
    pub fn parse_from_service_id_binary(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            16 => Some(Self::Aci(Uuid::from_slice(bytes).ok()?.into())),
            17 => {
                let result = Self::parse_from_service_id_fixed_width_binary(
                    bytes.try_into().expect("already measured"),
                )?;
                if result.kind() == ServiceIdKind::Aci {
                    // The ACI is unmarked in the standard binary format, so this is an error.
                    None
                } else {
                    Some(result)
                }
            }
            _ => None,
        }
    }

    /// Parses from the standard binary representation, returning `None` if invalid.
    #[inline]
    pub fn parse_from_service_id_fixed_width_binary(
        bytes: &ServiceIdFixedWidthBinaryBytes,
    ) -> Option<Self> {
        let uuid = Uuid::from_slice(&bytes[1..]).ok()?;
        match ServiceIdKind::try_from(bytes[0]).ok()? {
            ServiceIdKind::Aci => Some(Self::Aci(uuid.into())),
            ServiceIdKind::Pni => Some(Self::Pni(uuid.into())),
        }
    }

    /// Parses from the standard String representation, returning `None` if invalid.
    ///
    /// The UUID parsing is case-insensitive.
    pub fn parse_from_service_id_string(input: &str) -> Option<Self> {
        fn try_parse_hyphenated(input: &str) -> Option<Uuid> {
            // uuid::Uuid supports multiple UUID formats; we only want to support the "hyphenated"
            // form.
            if input.len() != uuid::fmt::Hyphenated::LENGTH {
                return None;
            }
            Uuid::try_parse(input).ok()
        }

        if let Some(uuid_string) = input.strip_prefix("PNI:") {
            let uuid = try_parse_hyphenated(uuid_string)?;
            Some(Self::Pni(uuid.into()))
        } else {
            let uuid = try_parse_hyphenated(input)?;
            Some(Self::Aci(uuid.into()))
        }
    }

    /// Returns the UUID inside this service ID, discarding the type.
    #[inline]
    pub fn raw_uuid(self) -> Uuid {
        match self {
            ServiceId::Aci(aci) => aci.into(),
            ServiceId::Pni(pni) => pni.into(),
        }
    }

    /// Constructs a [ProtocolAddress] from this service ID and a device ID.
    pub fn to_protocol_address(&self, device_id: DeviceId) -> ProtocolAddress {
        ProtocolAddress::new(self.service_id_string(), device_id)
    }
}

impl fmt::Debug for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}:{}>", self.kind(), self.raw_uuid())
    }
}

impl<const KIND: u8> TryFrom<ServiceId> for SpecificServiceId<KIND> {
    type Error = WrongKindOfServiceIdError;

    #[inline]
    fn try_from(value: ServiceId) -> Result<Self, Self::Error> {
        if u8::from(value.kind()) == KIND {
            Ok(value.raw_uuid().into())
        } else {
            Err(WrongKindOfServiceIdError {
                expected: KIND
                    .try_into()
                    .expect("invalid kind, not covered in ServiceIdKind"),
                actual: value.kind(),
            })
        }
    }
}

impl<const KIND: u8> PartialEq<ServiceId> for SpecificServiceId<KIND>
where
    ServiceId: From<SpecificServiceId<KIND>>,
{
    fn eq(&self, other: &ServiceId) -> bool {
        ServiceId::from(*self) == *other
    }
}

impl<const KIND: u8> PartialEq<SpecificServiceId<KIND>> for ServiceId
where
    ServiceId: From<SpecificServiceId<KIND>>,
{
    fn eq(&self, other: &SpecificServiceId<KIND>) -> bool {
        *self == ServiceId::from(*other)
    }
}

#[cfg(test)]
mod service_id_tests {
    use std::borrow::Borrow;

    use proptest::prelude::*;
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    use super::*;

    #[test]
    fn conversions() {
        let uuid = uuid::uuid!("8c78cd2a-16ff-427d-83dc-1a5e36ce713d");

        let aci = Aci::from(uuid);
        assert_eq!(uuid, Uuid::from(aci));
        let aci_service_id = ServiceId::from(aci);
        assert_eq!(aci, aci_service_id);
        assert_eq!(aci_service_id, aci);
        assert_eq!(Ok(aci), Aci::try_from(aci_service_id));
        assert_eq!(
            Err(WrongKindOfServiceIdError {
                expected: ServiceIdKind::Pni,
                actual: ServiceIdKind::Aci
            }),
            Pni::try_from(aci_service_id)
        );
        assert_eq!(ServiceIdKind::Aci, aci_service_id.kind());

        let pni = Pni::from(uuid);
        assert_eq!(uuid, Uuid::from(pni));
        let pni_service_id = ServiceId::from(pni);
        assert_eq!(pni, pni_service_id);
        assert_eq!(pni_service_id, pni);
        assert_eq!(Ok(pni), Pni::try_from(pni_service_id));
        assert_eq!(
            Err(WrongKindOfServiceIdError {
                expected: ServiceIdKind::Aci,
                actual: ServiceIdKind::Pni
            }),
            Aci::try_from(pni_service_id)
        );
        assert_eq!(ServiceIdKind::Pni, pni_service_id.kind());

        assert_ne!(aci_service_id, pni_service_id);
    }

    #[allow(clippy::too_many_arguments)]
    fn round_trip_test<SerializedOwned, SerializedBorrowed>(
        uuid: Uuid,
        serialize: fn(&ServiceId) -> SerializedOwned,
        serialize_aci: fn(&Aci) -> SerializedOwned,
        serialize_pni: fn(&Pni) -> SerializedOwned,
        deserialize: fn(&SerializedBorrowed) -> Option<ServiceId>,
        deserialize_aci: fn(&SerializedBorrowed) -> Option<Aci>,
        deserialize_pni: fn(&SerializedBorrowed) -> Option<Pni>,
        expected_aci: &SerializedBorrowed,
        expected_pni: &SerializedBorrowed,
    ) where
        SerializedOwned: Borrow<SerializedBorrowed>,
        SerializedBorrowed: Eq + fmt::Debug + ?Sized,
    {
        {
            let aci = Aci::from(uuid);
            let serialized = serialize_aci(&aci);
            assert_eq!(expected_aci, serialized.borrow());
            assert_eq!(
                serialized.borrow(),
                serialize(&ServiceId::from(aci)).borrow()
            );
            let deserialized = deserialize(serialized.borrow()).expect("just serialized");
            assert_eq!(ServiceIdKind::Aci, deserialized.kind());
            assert_eq!(uuid, deserialized.raw_uuid());
            assert_eq!(aci, Aci::try_from(deserialized).expect("type matches"));
            assert_eq!(Some(aci), deserialize_aci(serialized.borrow()));
            assert_eq!(None, deserialize_pni(serialized.borrow()));
        }
        {
            let pni = Pni::from(uuid);
            let serialized = serialize_pni(&pni);
            assert_eq!(expected_pni, serialized.borrow());
            assert_eq!(
                serialized.borrow(),
                serialize(&ServiceId::from(pni)).borrow()
            );
            let deserialized = deserialize(serialized.borrow()).expect("just serialized");
            assert_eq!(ServiceIdKind::Pni, deserialized.kind());
            assert_eq!(uuid, deserialized.raw_uuid());
            assert_eq!(pni, Pni::try_from(deserialized).expect("type matches"));
            assert_eq!(Some(pni), deserialize_pni(serialized.borrow()));
            assert_eq!(None, deserialize_aci(serialized.borrow()));
        }
    }

    fn array_prepend(tag: u8, uuid_bytes: &[u8; 16]) -> [u8; 17] {
        let mut result = [tag; 17];
        result[1..].copy_from_slice(uuid_bytes);
        result
    }

    #[test]
    fn round_trip_service_id_binary() {
        proptest!(|(uuid_bytes: [u8; 16])| {
            let uuid = Uuid::from_bytes(uuid_bytes);
            round_trip_test(
                uuid,
                ServiceId::service_id_binary,
                Aci::service_id_binary,
                Pni::service_id_binary,
                ServiceId::parse_from_service_id_binary,
                Aci::parse_from_service_id_binary,
                Pni::parse_from_service_id_binary,
                uuid.as_bytes(),
                &array_prepend(0x01, uuid.as_bytes()),
            );
        });
    }

    #[test]
    fn round_trip_service_id_fixed_width_binary() {
        proptest!(|(uuid_bytes: [u8; 16])| {
            let uuid = Uuid::from_bytes(uuid_bytes);
            round_trip_test(
                uuid,
                ServiceId::service_id_fixed_width_binary,
                Aci::service_id_fixed_width_binary,
                Pni::service_id_fixed_width_binary,
                ServiceId::parse_from_service_id_fixed_width_binary,
                Aci::parse_from_service_id_fixed_width_binary,
                Pni::parse_from_service_id_fixed_width_binary,
                &array_prepend(0x00, uuid.as_bytes()),
                &array_prepend(0x01, uuid.as_bytes()),
            );
        });
    }

    #[test]
    fn round_trip_service_id_string() {
        proptest!(|(uuid_bytes: [u8; 16])| {
            let uuid = Uuid::from_bytes(uuid_bytes);
            round_trip_test(
                uuid,
                ServiceId::service_id_string,
                Aci::service_id_string,
                Pni::service_id_string,
                ServiceId::parse_from_service_id_string,
                Aci::parse_from_service_id_string,
                Pni::parse_from_service_id_string,
                &uuid.hyphenated().to_string(),
                &format!("PNI:{}", uuid.hyphenated()),
            );
        });
    }

    #[test]
    fn logging() {
        let uuid = uuid::uuid!("8c78cd2a-16ff-427d-83dc-1a5e36ce713d");
        let aci = Aci::from(uuid);
        assert_eq!(
            "<ACI:8c78cd2a-16ff-427d-83dc-1a5e36ce713d>",
            format!("{:?}", aci)
        );
        assert_eq!(
            "<ACI:8c78cd2a-16ff-427d-83dc-1a5e36ce713d>",
            format!("{:?}", ServiceId::from(aci))
        );
        let pni = Pni::from(uuid);
        assert_eq!(
            "<PNI:8c78cd2a-16ff-427d-83dc-1a5e36ce713d>",
            format!("{:?}", pni)
        );
        assert_eq!(
            "<PNI:8c78cd2a-16ff-427d-83dc-1a5e36ce713d>",
            format!("{:?}", ServiceId::from(pni))
        );
    }

    #[test]
    fn case_insensitive() {
        let uuid = uuid::uuid!("8c78cd2a-16ff-427d-83dc-1a5e36ce713d");
        let mut buffer = [0u8; 40]; // exactly fits "PNI:{uuid}"

        let service_id =
            ServiceId::parse_from_service_id_string(uuid.hyphenated().encode_upper(&mut buffer))
                .expect("can decode uppercase");
        assert_eq!(uuid, service_id.raw_uuid());

        let service_id =
            ServiceId::parse_from_service_id_string(uuid.hyphenated().encode_lower(&mut buffer))
                .expect("can decode lowercase");
        assert_eq!(uuid, service_id.raw_uuid());

        buffer[..4].copy_from_slice(b"PNI:");
        uuid.hyphenated().encode_upper(&mut buffer[4..]);
        let service_id = ServiceId::parse_from_service_id_string(
            std::str::from_utf8(&buffer).expect("valid UTF-8"),
        )
        .expect("can decode uppercase PNI");
        assert_eq!(uuid, service_id.raw_uuid());

        uuid.hyphenated().encode_lower(&mut buffer[4..]);
        let service_id = ServiceId::parse_from_service_id_string(
            std::str::from_utf8(&buffer).expect("valid UTF-8"),
        )
        .expect("can decode lowercase PNI");
        assert_eq!(uuid, service_id.raw_uuid());
    }

    #[test]
    fn accepts_ios_system_story_aci() {
        // This is not technically a valid UUID, but we need to handle it anyway, at least on iOS.
        let service_id =
            ServiceId::parse_from_service_id_string("00000000-0000-0000-0000-000000000001")
                .expect("can decode");
        assert_eq!(
            &hex_literal::hex!("00000000 0000 0000 0000 000000000001"),
            service_id.raw_uuid().as_bytes(),
        );
        assert_eq!(ServiceIdKind::Aci, service_id.kind());
    }

    #[test]
    fn rejects_invalid_binary_lengths() {
        let uuid = uuid::uuid!("8c78cd2a-16ff-427d-83dc-1a5e36ce713d");
        assert!(ServiceId::parse_from_service_id_binary(&[]).is_none());
        assert!(ServiceId::parse_from_service_id_binary(&[1]).is_none());
        assert!(ServiceId::parse_from_service_id_binary(&uuid.as_bytes()[1..]).is_none());
        assert!(ServiceId::parse_from_service_id_binary(&[1; 18]).is_none());
    }

    #[test]
    fn rejects_invalid_uuid_strings() {
        assert!(ServiceId::parse_from_service_id_string("").is_none());
        assert!(ServiceId::parse_from_service_id_string("11").is_none());
        assert!(
            ServiceId::parse_from_service_id_string("8c78cd2a16ff427d83dc1a5e36ce713d").is_none()
        );
        assert!(
            ServiceId::parse_from_service_id_string("{8c78cd2a-16ff-427d-83dc-1a5e36ce713d}")
                .is_none()
        );

        assert!(ServiceId::parse_from_service_id_string("PNI:").is_none());
        assert!(ServiceId::parse_from_service_id_string("PNI:11").is_none());
        assert!(
            ServiceId::parse_from_service_id_string("PNI:8c78cd2a16ff427d83dc1a5e36ce713d")
                .is_none()
        );
        assert!(ServiceId::parse_from_service_id_string(
            "PNI:{8c78cd2a-16ff-427d-83dc-1a5e36ce713d}"
        )
        .is_none());
    }

    #[test]
    fn rejects_invalid_types() {
        let uuid = uuid::uuid!("8c78cd2a-16ff-427d-83dc-1a5e36ce713d");
        assert!(
            ServiceId::parse_from_service_id_binary(&array_prepend(0xFF, uuid.as_bytes()))
                .is_none()
        );
        assert!(
            ServiceId::parse_from_service_id_fixed_width_binary(&array_prepend(
                0xFF,
                uuid.as_bytes()
            ))
            .is_none()
        );
        assert!(ServiceId::parse_from_service_id_string("BAD:{uuid}").is_none());
        assert!(ServiceId::parse_from_service_id_string("PNI{uuid}").is_none());
        assert!(ServiceId::parse_from_service_id_string("PNI {uuid}").is_none());
        assert!(ServiceId::parse_from_service_id_string("PNI{uuid} ").is_none());

        // ACIs are only prefixed in the fixed-width format.
        assert!(
            ServiceId::parse_from_service_id_binary(&array_prepend(0x00, uuid.as_bytes()))
                .is_none()
        );
        assert!(ServiceId::parse_from_service_id_string("ACI:{uuid}").is_none());
    }

    #[test]
    fn ordering() {
        let test_uuid = uuid::uuid!("8c78cd2a-16ff-427d-83dc-1a5e36ce713d");

        let mut ids: [ServiceId; 4] = [
            Aci::from_uuid(Uuid::nil()).into(),
            Aci::from_uuid(test_uuid).into(),
            Pni::from_uuid(Uuid::nil()).into(),
            Pni::from_uuid(test_uuid).into(),
        ];
        let original = ids;
        ids.shuffle(&mut thread_rng());
        ids.sort();
        assert_eq!(original, ids);
    }

    #[test]
    fn ordering_consistency() {
        proptest!(|(
            left_uuid_bytes: [u8; 16],
            left_raw_kind in 0..=1,
            right_uuid_bytes: [u8; 16],
            right_raw_kind in 0..=1
        )| {
            let service_id_constructor = |raw_type| match raw_type {
                0 => |uuid: Uuid| ServiceId::Aci(uuid.into()),
                1 => |uuid: Uuid| ServiceId::Pni(uuid.into()),
                _ => unreachable!("unexpected raw type {raw_type}"),
            };

            let left_uuid = Uuid::from_bytes(left_uuid_bytes);
            let left_service_id = service_id_constructor(left_raw_kind)(left_uuid);
            let right_uuid = Uuid::from_bytes(right_uuid_bytes);
            let right_service_id = service_id_constructor(right_raw_kind)(right_uuid);

            assert_eq!(
                left_service_id.cmp(&right_service_id),
                left_service_id.service_id_fixed_width_binary()
                    .cmp(&right_service_id.service_id_fixed_width_binary()),
                "didn't match Service-Id-FixedWidthBinary ordering ({left_service_id:?} vs {right_service_id:?})",
            );

            if left_raw_kind == right_raw_kind {
                assert_eq!(
                    left_service_id.cmp(&right_service_id),
                    left_service_id.service_id_string().cmp(&right_service_id.service_id_string()),
                    "same-kind ServiceIds didn't match Service-Id-String ordering ({left_service_id:?} vs {right_service_id:?})",
                );
            }
        })
    }
}

/// The type used in memory to represent a *device*, i.e. a particular Signal client instance which
/// represents some user.
///
/// Used in [ProtocolAddress].
#[derive(
    Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord, derive_more::From, derive_more::Into,
)]
pub struct DeviceId(u32);

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a unique Signal client instance as `(<user ID>, <device ID>)` pair.
#[derive(Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct ProtocolAddress {
    name: String,
    device_id: DeviceId,
}

impl ProtocolAddress {
    /// Create a new address.
    ///
    /// - `name` defines a user's public identity, and therefore must be globally unique to that
    ///   user.
    /// - Each Signal client instance then has its own `device_id`, which must be unique among
    ///   all clients for that user.
    ///
    ///```
    /// use libsignal_core::{DeviceId, ProtocolAddress};
    ///
    /// // This is a unique id for some user, typically a UUID.
    /// let user_id: String = "04899A85-4C9E-44CC-8428-A02AB69335F1".to_string();
    /// // Each client instance representing that user has a unique device id.
    /// let device_id: DeviceId = 2_u32.into();
    /// let address = ProtocolAddress::new(user_id.clone(), device_id);
    ///
    /// assert!(address.name() == &user_id);
    /// assert!(address.device_id() == device_id);
    ///```
    pub fn new(name: String, device_id: DeviceId) -> Self {
        ProtocolAddress { name, device_id }
    }

    /// A unique identifier for the target user. This is usually a UUID.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// An identifier representing a particular Signal client instance to send to.
    ///
    /// For example, if a user has set up Signal on both their phone and laptop, a particular
    /// message sent to the user will still only go to a single device. So when a user sends a
    /// message to another user at all, they're actually sending a message to *every* device.
    #[inline]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
}

impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.name, self.device_id)
    }
}
