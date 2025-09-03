//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use libsignal_core::{Aci, DeviceId, ServiceId};

#[derive(Debug, thiserror::Error)]
pub enum ParseHexError<const N: usize> {
    #[error("character {c} at position {index} is not a hex digit")]
    InvalidHexCharacter { c: char, index: usize },
    #[error("got {count} hex digits, expected {} ({N} bytes)",  2 * N)]
    WrongNumberOfDigits { count: usize },
}

pub fn parse_hex_bytes<const N: usize>(input: &str) -> Result<[u8; N], ParseHexError<N>>
where
    [u8; N]: hex::FromHex<Error = hex::FromHexError>,
{
    hex::FromHex::from_hex(input).map_err(|e| match e {
        hex::FromHexError::InvalidHexCharacter { c, index } => {
            ParseHexError::InvalidHexCharacter { c, index }
        }
        hex::FromHexError::InvalidStringLength | hex::FromHexError::OddLength => {
            ParseHexError::WrongNumberOfDigits { count: input.len() }
        }
    })
}

pub fn parse_aci(input: &str) -> Result<Aci, AciParseError> {
    Aci::parse_from_service_id_string(input).ok_or(AciParseError)
}

/// invalid ACI, expected a UUID like "55555555-5555-5555-5555-555555555555"
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub struct AciParseError;

pub fn parse_base64_bytes<const N: usize>(input: &str) -> Result<[u8; N], ParseBase64Error<N>> {
    let bytes = BASE64_STANDARD.decode(input)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| ParseBase64Error::WrongNumberOfBytes { count: bytes.len() })
}

#[derive(Debug, thiserror::Error)]
pub enum ParseBase64Error<const N: usize> {
    #[error("failed to decode: {0}")]
    Decode(#[from] base64::DecodeError),

    #[error("got {count} bytes, expected {N}")]
    WrongNumberOfBytes { count: usize },
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum AddressParseError {
    /// invalid address, expected an ACI and device ID like "55555555-5555-5555-5555-555555555555.3"
    NoSeparator,
    /// invalid service ID
    InvalidServiceId,
    /// invalid device ID
    InvalidDeviceId,
}

pub fn parse_protocol_address<A: TryFrom<ServiceId>>(
    input: &str,
) -> Result<(A, DeviceId), AddressParseError> {
    let (service_id, device_id) = input
        .split_once('.')
        .ok_or(AddressParseError::NoSeparator)?;
    let service_id = ServiceId::parse_from_service_id_string(service_id)
        .and_then(|s| s.try_into().ok())
        .ok_or(AddressParseError::InvalidServiceId)?;
    let device_id = device_id
        .parse()
        .ok()
        .and_then(|d| DeviceId::new(d).ok())
        .ok_or(AddressParseError::InvalidDeviceId)?;
    Ok((service_id, device_id))
}
