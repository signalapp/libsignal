//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::str::FromStr;

use libsignal_net::infra::errors::LogSafeDisplay;

/// A session ID received from the server.
///
/// This type can be infallibly encoded as an URL path segment.
#[derive(Clone, Debug, PartialEq, Eq, derive_more::Deref, serde::Serialize)]
pub struct SessionId(String);

impl SessionId {
    /// Attempts to parse a string as a [`SessionId`].
    ///
    /// Returns an error if the string contains characters that can't appear in
    /// an URL path segment.
    pub fn new(s: String) -> Result<Self, InvalidSessionId> {
        fn validate(s: &str) -> Result<(), InvalidSessionId> {
            let is_allowed_char = |c: u8| {
                c.is_ascii_alphanumeric() || {
                    // Unreserved and sub-delims per RFC 3986.
                    b"-_.~!$&,()*+,;=:@"
                }
                .contains(&c)
            };
            let only_allowed_chars = s.bytes().all(is_allowed_char);

            only_allowed_chars.then_some(()).ok_or(InvalidSessionId)
        }

        validate(&s).map(|()| Self(s.to_string()))
    }

    pub fn as_url_path_segment(&self) -> &str {
        &self.0
    }
}

impl LogSafeDisplay for SessionId {}
impl Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show only a small prefix. This is expected to be base64-encoded so 2
        // characters encodes 3 nibbles of the unencoded value.
        const KEEP_CHARS: usize = 2;
        if self.len() <= KEEP_CHARS {
            return f.write_str(&self.0);
        }

        f.write_str(&self.0[..KEEP_CHARS])?;
        write!(f, "[REDACTED {}]", self.len() - KEEP_CHARS)
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// invalid session ID
pub struct InvalidSessionId;

impl FromStr for SessionId {
    type Err = InvalidSessionId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl TryFrom<String> for SessionId {
    type Error = InvalidSessionId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;

    #[test_case("abc" => matches Ok(()))]
    #[test_case("with space" => matches Err(InvalidSessionId))]
    #[test_case("with-hyphen" => matches Ok(()))]
    fn parse(input: &str) -> Result<(), InvalidSessionId> {
        println!("parsing as SessionId: {input:?}");
        input.parse().map(|SessionId(_)| ())
    }

    #[test]
    fn url_safe_base64_is_valid() {
        // This is likely what the server is returning so make sure it's
        // allowed.
        let _ = SessionId::from_str(base64::alphabet::URL_SAFE.as_str()).expect("is valid");
    }

    #[test]
    fn log_safe_session_id() {
        assert_eq!(
            &SessionId::from_str("somewhat-long-session-id")
                .unwrap()
                .to_string(),
            "so[REDACTED 22]"
        );
        assert_eq!(&SessionId::from_str("id").unwrap().to_string(), "id");
    }
}
