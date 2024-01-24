//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol::Aci;

#[derive(Debug, thiserror::Error)]
pub enum ParseHexError<const N: usize> {
    #[error("character {c} at position {index} is not a hex digit")]
    InvalidHexCharacter { c: char, index: usize },
    #[error("got {count} hex digits, expected {}",  2 * N)]
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
