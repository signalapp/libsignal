//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::Aci;

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

#[cfg(test)]
mod test {
    use test_case::test_case;

    #[test_case("abcd", Ok([0xab, 0xcd]))]
    #[test_case("bard", Err("character r at position 2 is not a hex digit"))]
    #[test_case("ab", Err("got 2 hex digits, expected 4 (2 bytes)"))]
    #[test_case("abc", Err("got 3 hex digits, expected 4 (2 bytes)"))]
    fn parse_hex_bytes(input: &str, expected: Result<[u8; 2], &str>) {
        let result = super::parse_hex_bytes(input).map_err(|e| e.to_string());

        assert_eq!(result, expected.map_err(String::from))
    }
}
