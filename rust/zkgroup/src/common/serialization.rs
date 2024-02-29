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
    .map_err(|_| ZkGroupDeserializationFailure)?;
    Ok(result)
}

/// Serializes a type using the standard zkgroup encoding (based on bincode).
pub fn serialize<T: Serialize>(value: &T) -> Vec<u8> {
    zkgroup_bincode_options()
        .serialize(value)
        .expect("cannot fail")
}
