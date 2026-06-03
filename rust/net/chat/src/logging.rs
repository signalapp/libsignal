//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::{Aci, E164, Pni, ServiceId};
use ref_cast::RefCast as _;

/// Implement Debug for use in DebugStruct etc. using existing Display impl.
macro_rules! impl_debug_from_display {
    ($target:ident < $($args:tt),* >) => {
        impl< $($args)* > std::fmt::Debug for $target< $($args)* >
        where $target< $($args)* >: std::fmt::Display {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self}")
            }
        }
    };
    ($target:ident) => {
        impl std::fmt::Debug for $target where $target: std::fmt::Display {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self}")
            }
        }
    };
}

#[derive(ref_cast::RefCast)]
#[repr(transparent)]
pub struct Redact<T>(pub T);
impl std::fmt::Display for Redact<uuid::Uuid> {
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

impl std::fmt::Display for Redact<Aci> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Redact(uuid::Uuid::from(self.0)).fmt(f)
    }
}

impl std::fmt::Display for Redact<Pni> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PNI:{}", Redact(uuid::Uuid::from(self.0)))
    }
}

impl std::fmt::Display for Redact<ServiceId> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            ServiceId::Aci(specific_service_id) => Redact(specific_service_id).fmt(f),
            ServiceId::Pni(specific_service_id) => Redact(specific_service_id).fmt(f),
        }
    }
}

const MINIMAL_E164_LENGTH: usize = 7;

impl std::fmt::Display for Redact<E164> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0.to_string();
        if s.len() < MINIMAL_E164_LENGTH {
            write!(f, "[short E164]")
        } else {
            write!(f, "E164: [REDACTED]{}", &s[s.len() - 2..])
        }
    }
}

impl<T> std::fmt::Display for Redact<&'_ T>
where
    Redact<T>: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Redact::<T>::ref_cast(self.0).fmt(f)
    }
}

impl_debug_from_display!(Redact<T>);

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
impl_debug_from_display!(RedactHex<'__lifetime>);

/// Hex-encodes a slice of bytes and redacts the result using [`RedactHex`]
pub struct RedactBytesAsHex<'a>(pub &'a [u8]);
impl std::fmt::Display for RedactBytesAsHex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&RedactHex(&hex::encode(self.0)), f)
    }
}
impl_debug_from_display!(RedactBytesAsHex<'__lifetime>);

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

/// A wrapper type allowing an arbitrary function to be used with e.g.
/// [`std::fmt::DebugStruct::field`].
///
/// This can go away if/when [`std::fmt::DebugStruct::field_with`] is stabilized.
///
/// Note the constraint on the wrapped type lives on the struct itself, rather than just its impls.
/// This helps keep usage simple at the call site; without it, using `DebugByCalling` with a closure
/// would require an explicit type for the closure's argument.
pub struct DebugByCalling<T>(pub T)
where
    T: Fn(&mut std::fmt::Formatter<'_>) -> std::fmt::Result;

impl<T> std::fmt::Debug for DebugByCalling<T>
where
    T: Fn(&mut std::fmt::Formatter<'_>) -> std::fmt::Result,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0(f)
    }
}

#[cfg(test)]
mod test {
    use nonzero_ext::nonzero;
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

    #[test_case(E164::new(nonzero!(1u64)) => "[short E164]")]
    #[test_case(E164::new(nonzero!(12345u64)) => "[short E164]")]
    #[test_case(E164::new(nonzero!(123456u64)) => "E164: [REDACTED]56")]
    fn redact_e164(e164: E164) -> String {
        Redact(e164).to_string()
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

    #[test_case(&[] => "\"\""; "empty")]
    #[test_case(b"woot" => "\"woot\""; "valid utf8")]
    #[test_case(&[0xff] => "\"ff\""; "single byte")]
    #[test_case(&[0x8a, 0x8b, 0x8c, 0x8d] => "\"8a8b8c8d\""; "does not redact")]
    fn debug_as_str_of_bytes(bytes: &[u8]) -> String {
        format!("{:?}", DebugAsStrOrBytes(bytes))
    }

    #[test_case(&[] => "")]
    #[test_case(&[0xaa] => "aa")]
    #[test_case(&[0xaa, 0xbb] => "[REDACTED_HEX: 1 skipped]abb")]
    fn redact_bytes_as_hex(bytes: &[u8]) -> String {
        RedactBytesAsHex(bytes).to_string()
    }
}
