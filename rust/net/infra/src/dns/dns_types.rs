//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use tokio::time::Instant;

#[derive(Debug, Clone)]
pub struct Expiring<T> {
    pub data: T,
    pub expiration: Instant,
}

/// Represents the type of the DNS record.
/// Only lists the ones required/supported for our purposes.
///
/// Values for the variants are assigned based on the Resource Record type values
/// from [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2)
/// and [RFC3596](https://datatracker.ietf.org/doc/html/rfc3596#section-2.1)
#[repr(u16)]
#[derive(Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum ResourceType {
    /// An IPv4 host address type
    ///
    /// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
    A = 1,
    /// An IPv6 host address type
    ///
    /// https://datatracker.ietf.org/doc/html/rfc3596#section-2.1
    AAAA = 28,
}
