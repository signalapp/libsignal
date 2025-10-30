//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::{Aci, Pni, ServiceId};

pub struct Redact<T>(pub T);
impl std::fmt::Display for Redact<&'_ uuid::Uuid> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "********-****-****-****-*********{:03x}",
            u16::from_be_bytes(
                *self
                    .0
                    .as_bytes()
                    .last_chunk()
                    .expect("more than two bytes long")
            ) & 0xFFF
        )
    }
}

impl std::fmt::Display for Redact<&'_ Aci> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Redact(&uuid::Uuid::from(*self.0)).fmt(f)
    }
}

impl std::fmt::Display for Redact<&'_ Pni> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PNI:{}", Redact(&uuid::Uuid::from(*self.0)))
    }
}

impl std::fmt::Display for Redact<&'_ ServiceId> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            ServiceId::Aci(specific_service_id) => Redact(specific_service_id).fmt(f),
            ServiceId::Pni(specific_service_id) => Redact(specific_service_id).fmt(f),
        }
    }
}

/// Redacts all but the last 3 characters of its contents, which are assumed to be hex.
///
/// We keep the last characters rather than the first characters for consistency with the redaction
/// performed by the apps.
pub struct RedactHex<'a>(pub &'a str);
impl std::fmt::Display for RedactHex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let index_of_last_three_digits = self.0.len().saturating_sub(3);
        if index_of_last_three_digits == 0 {
            return write!(f, "{}", &self.0);
        }
        write!(
            f,
            "[REDACTED_HEX: {} skipped]{}",
            index_of_last_three_digits,
            &self.0[index_of_last_three_digits..],
        )
    }
}
/// Implemented for use in DebugStruct etc, but still uses the Display impl.
impl std::fmt::Debug for RedactHex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

/// Redacts all but the last 2 non-padding characters of its contents, which are assumed to be
/// base64 or base64url.
///
/// We usually keep 3 hex digits = 12 bits, so we should keep 2 base64 characters = 14 bits.
///
/// We keep the last characters rather than the first characters for consistency with the redaction
/// performed by the apps.
pub struct RedactBase64<'a>(pub &'a str);
impl std::fmt::Display for RedactBase64<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let index_of_last_two_non_padding_characters = self
            .0
            .rfind(|c| c != '=')
            .unwrap_or_default()
            .saturating_sub(1);
        if index_of_last_two_non_padding_characters == 0 {
            return write!(f, "{}", &self.0);
        }
        write!(
            f,
            "[REDACTED_BASE64: {} skipped]{}",
            index_of_last_two_non_padding_characters,
            &self.0[index_of_last_two_non_padding_characters..],
        )
    }
}

pub struct DebugAsStrOrBytes<'b>(pub &'b [u8]);
impl std::fmt::Debug for DebugAsStrOrBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match std::str::from_utf8(self.0) {
            Ok(s) => s.fmt(f),
            Err(_) => hex::encode(self.0).fmt(f),
        }
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;

    #[test]
    fn redact_uuid() {
        let uuid = uuid::uuid!("8c78cd2a-16ff-427d-83dc-1a5e36ce713d");
        assert_eq!(
            Redact(&uuid).to_string(),
            "********-****-****-****-*********13d"
        );
    }

    #[test_case("" => "")]
    #[test_case("ab" => "ab")]
    #[test_case("abcd" => "[REDACTED_HEX: 1 skipped]bcd")]
    #[test_case("abcdef01" => "[REDACTED_HEX: 5 skipped]f01")]
    fn redact_hex(input: &str) -> String {
        RedactHex(input).to_string()
    }

    #[test_case("" => "")]
    #[test_case("AA" => "AA")]
    #[test_case("BB==" => "BB==")]
    #[test_case("AAA" => "[REDACTED_BASE64: 1 skipped]AA")]
    #[test_case("BBB=" => "[REDACTED_BASE64: 1 skipped]BB=")]
    #[test_case("AAAA" => "[REDACTED_BASE64: 2 skipped]AA")]
    #[test_case("AAAAAA" => "[REDACTED_BASE64: 4 skipped]AA")]
    #[test_case("BBBBBB==" => "[REDACTED_BASE64: 4 skipped]BB==")]
    #[test_case("AAAAAAA" => "[REDACTED_BASE64: 5 skipped]AA")]
    #[test_case("BBBBBBB=" => "[REDACTED_BASE64: 5 skipped]BB=")]
    #[test_case("AAAAAAAA" => "[REDACTED_BASE64: 6 skipped]AA")]
    fn redact_base64(input: &str) -> String {
        RedactBase64(input).to_string()
    }
}
