//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol::Aci;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ParseHexError<const N: usize> {
    #[error("character {c} at position {index} is not a hex digit")]
    InvalidHexCharacter { c: char, index: usize },
    #[error("got {count} hex digits, expected {}",  2 * N)]
    WrongNumberOfDigits { count: usize },
}

pub(crate) fn parse_hex_bytes<const N: usize>(input: &str) -> Result<[u8; N], ParseHexError<N>>
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

pub(crate) fn parse_aci(input: &str) -> Result<Aci, AciParseError> {
    Aci::parse_from_service_id_string(input).ok_or(AciParseError)
}

/// invalid ACI, expected a UUID like "55555555-5555-5555-5555-555555555555"
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub(crate) struct AciParseError;

pub(crate) enum ParseVerbosity {
    None,
    PrintOneLine,
    PrintPretty,
}

fn print_oneline(message: &dyn std::fmt::Debug) {
    eprintln!("{message:?}")
}

fn print_pretty(message: &dyn std::fmt::Debug) {
    eprintln!("{message:#?}")
}

impl ParseVerbosity {
    pub(crate) fn into_visitor(self) -> Option<fn(&dyn std::fmt::Debug)> {
        match self {
            ParseVerbosity::None => None,
            ParseVerbosity::PrintOneLine => Some(print_oneline),
            ParseVerbosity::PrintPretty => Some(print_pretty),
        }
    }
}

impl From<u8> for ParseVerbosity {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::PrintOneLine,
            2.. => Self::PrintPretty,
        }
    }
}
