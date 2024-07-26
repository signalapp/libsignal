//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use bincode::Options;
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::ZkGroupDeserializationFailure;

fn zkgroup_bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
}

/// Deserializes a type using the standard zkgroup encoding (based on bincode).
///
/// The type must support [`PartialDefault`] to save on code size.
pub fn deserialize<'a, T: Deserialize<'a> + PartialDefault>(
    bytes: &'a [u8],
) -> Result<T, ZkGroupDeserializationFailure> {
    let mut result = T::partial_default();
    // Use the same encoding options as plain bincode::deserialize, which we used historically,
    // but also reject trailing bytes.
    // See https://docs.rs/bincode/1.3.3/bincode/config/index.html#options-struct-vs-bincode-functions.
    T::deserialize_in_place(
        &mut bincode::Deserializer::from_slice(bytes, zkgroup_bincode_options()),
        &mut result,
    )
    .map_err(|_| ZkGroupDeserializationFailure::new::<T>())?;
    Ok(result)
}

/// Serializes a type using the standard zkgroup encoding (based on bincode).
pub fn serialize<T: Serialize>(value: &T) -> Vec<u8> {
    zkgroup_bincode_options()
        .serialize(value)
        .expect("cannot fail")
}

/// Constant version number `C` as a type.
///
/// Zero-sized type that converts to and from for the value `C` via `Into`,
/// `TryFrom`, [`Serialize`], and [`Deserialize`]. Used for providing a version
/// tag at the beginning of serialized structs.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct VersionByte<const C: u8>;

impl<const C: u8> From<VersionByte<C>> for u8 {
    fn from(VersionByte: VersionByte<C>) -> Self {
        C
    }
}

/// version byte was {found}, not {EXPECTED:?}
#[derive(Copy, Clone, Debug, Eq, PartialEq, displaydoc::Display)]
pub struct VersionMismatchError<const EXPECTED: u8> {
    found: u8,
}

impl<const C: u8> TryFrom<u8> for VersionByte<C> {
    type Error = VersionMismatchError<C>;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        (value == C)
            .then_some(VersionByte::<C>)
            .ok_or(VersionMismatchError::<C> { found: value })
    }
}

impl<const C: u8> Serialize for VersionByte<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u8::serialize(&C, serializer)
    }
}

impl<'de, const C: u8> Deserialize<'de> for VersionByte<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u8::deserialize(deserializer)?;
        v.try_into().map_err(|_| {
            <D::Error as serde::de::Error>::invalid_value(
                serde::de::Unexpected::Unsigned(v.into()),
                &format!("version `{C}`").as_str(),
            )
        })
    }
}

/// Value that always serializes to and from `0u8`.
pub type ReservedByte = VersionByte<0>;

#[cfg(test)]
mod test {
    use std::fmt::Debug;

    use test_case::test_case;

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, PartialDefault)]
    struct WithLeadingByte<T> {
        leading: T,
        string: String,
    }

    impl<T: Default> WithLeadingByte<T> {
        fn test_value() -> Self {
            Self {
                leading: T::default(),
                string: "a string".to_string(),
            }
        }
    }

    type WithReservedByte = WithLeadingByte<ReservedByte>;
    type WithVersionByte = WithLeadingByte<VersionByte<42>>;

    #[test_case(WithReservedByte::test_value(), 0)]
    #[test_case(WithVersionByte::test_value(), 42)]
    fn round_trip<T: Serialize + for<'a> Deserialize<'a> + PartialEq + PartialDefault + Debug>(
        test_value: T,
        expected_first_byte: u8,
    ) {
        let serialized = crate::serialize(&test_value);

        assert_eq!(serialized[0], expected_first_byte);
        let deserialized: T = crate::deserialize(&serialized).expect("can deserialize");

        assert_eq!(deserialized, test_value);
    }

    #[test_case(WithReservedByte::test_value())]
    #[test_case(WithVersionByte::test_value())]
    fn version_byte_wrong<
        T: Serialize + for<'a> Deserialize<'a> + PartialEq + PartialDefault + Debug,
    >(
        test_value: T,
    ) {
        let mut serialized = crate::serialize(&test_value);
        // perturb the first byte.
        serialized[0] += 1;
        crate::deserialize::<T>(&serialized).expect_err("invalid version");
    }

    #[test]
    fn version_byte_error_message() {
        let mut bincode_serialized =
            bincode::serialize(&WithVersionByte::test_value()).expect("should serialize");
        bincode_serialized[0] = 41;

        let error_message =
            bincode::deserialize::<WithVersionByte>(&bincode_serialized).expect_err("should fail");
        assert_eq!(
            error_message.to_string(),
            "invalid value: integer `41`, expected version `42`"
        );
    }
}
