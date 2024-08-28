//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// An implementation of [`log::Log::enabled`] suitable for production Signal apps.
///
/// Apps may apply additional logging filters on top of what libsignal reports.
pub fn log_enabled_in_apps(metadata: &log::Metadata) -> bool {
    let target = metadata.target();
    if target.is_empty() {
        return false;
    }

    let check = |crate_name: &str| {
        // Accept both "crate_name" and "crate_name::something".
        target
            .strip_prefix(crate_name)
            .is_some_and(|remainder| remainder.is_empty() || remainder.starts_with("::"))
    };

    // Use a manual jump table to reduce the number of checks we perform on each log message.
    // (The compiler can optimize some switches on strings, but it's hard to convince it to do
    // something smart for checking prefixes *and* exact matches.)
    match target.as_bytes()[0] {
        // libsignal naming patterns:
        b'l' => target.starts_with("libsignal_"),
        b's' => target.starts_with("signal_"),

        // Other libsignal crates:
        b'a' => check("attest"),
        b'd' => check("device_transfer"),
        b'p' => check("poksho"),
        b'u' => check("usernames"),
        b'z' => check("zkgroup") || check("zkcredential"),

        // mediasan crates (only show warnings and errors):
        b'm' if check("mediasan_common") || check("mp4san") => metadata.level() <= log::Level::Warn,
        b'w' if check("webpsan") => metadata.level() <= log::Level::Warn,

        // Otherwise...
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_matrix;

    use super::*;

    #[test_matrix([
        "libsignal_foo",
        "signal_foo",
        "attest",
        "device_transfer",
        "poksho",
        "usernames",
        "zkgroup",
        "zkcredential"
    ])]
    fn accepted(name: &str) {
        assert!(log_enabled_in_apps(
            &log::Metadata::builder()
                .target(name)
                .level(log::Level::Debug)
                .build()
        ));

        assert!(log_enabled_in_apps(
            &log::Metadata::builder()
                .target(&format!("{name}::foo::bar"))
                .level(log::Level::Debug)
                .build()
        ));
    }

    #[test_matrix(
        ["mp4san", "mediasan_common", "webpsan"],
        [log::Level::Error, log::Level::Warn, log::Level::Info]
    )]
    fn warnings_and_errors_only(name: &str, level: log::Level) {
        debug_assert!(
            log::Level::Error < log::Level::Warn,
            "log levels are ordered with 'higher' = 'more verbose'"
        );
        let expected = level <= log::Level::Warn;

        assert_eq!(
            expected,
            log_enabled_in_apps(&log::Metadata::builder().target(name).level(level).build()),
        );

        assert_eq!(
            expected,
            log_enabled_in_apps(
                &log::Metadata::builder()
                    .target(&format!("{name}::foo::bar"))
                    .level(level)
                    .build()
            ),
        );
    }

    #[test_matrix([
        "",
        "dependency",
        "curve25519_dalek",
        "not a usual target"]
    )]
    fn rejected(name: &str) {
        assert!(!log_enabled_in_apps(
            &log::Metadata::builder()
                .target(name)
                .level(log::Level::Error)
                .build()
        ));

        assert!(!log_enabled_in_apps(
            &log::Metadata::builder()
                .target(&format!("{name}::foo::bar"))
                .level(log::Level::Error)
                .build()
        ));
    }

    // `test_matrix` gets unhappy with "" and "::" in the same list, because neither has any
    // identifier characters.
    #[test]
    fn rejected_double_colon() {
        rejected("::")
    }
}
