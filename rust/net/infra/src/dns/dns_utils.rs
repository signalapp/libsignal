//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

const SIGNAL_DOMAIN_SUFFIX: &str = ".signal.org";

pub(crate) fn log_safe_domain(domain: &str) -> &str {
    match domain {
        "localhost" => domain,
        d if d.ends_with(SIGNAL_DOMAIN_SUFFIX) => d,
        _ => "REDACTED",
    }
}
