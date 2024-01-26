//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use itertools::{Either, Itertools};
use std::collections::HashMap;
use std::iter::Map;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use std::vec::IntoIter;

use crate::utils;

const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(1);
const SIGNAL_DOMAIN_SUFFIX: &str = ".signal.org";

#[derive(displaydoc::Display, Debug, thiserror::Error)]
pub enum Error {
    /// DNS lookup failed
    LookupFailed,
}

#[derive(Debug, Default, Clone)]
pub struct LookupResult {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
}

impl IntoIterator for LookupResult {
    type Item = IpAddr;
    type IntoIter = itertools::Interleave<
        Map<IntoIter<Ipv6Addr>, fn(Ipv6Addr) -> IpAddr>,
        Map<IntoIter<Ipv4Addr>, fn(Ipv4Addr) -> IpAddr>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        let v6_into_ipaddr: fn(Ipv6Addr) -> IpAddr = IpAddr::V6;
        let v4_into_ipaddr: fn(Ipv4Addr) -> IpAddr = IpAddr::V4;
        itertools::interleave(
            self.ipv6.into_iter().map(v6_into_ipaddr),
            self.ipv4.into_iter().map(v4_into_ipaddr),
        )
    }
}

impl LookupResult {
    pub fn new(ipv4: Vec<Ipv4Addr>, ipv6: Vec<Ipv6Addr>) -> Self {
        Self { ipv4, ipv6 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct DnsResolver {
    static_map: HashMap<&'static str, LookupResult>,
}

impl DnsResolver {
    pub fn new_with_static_fallback(static_map: HashMap<&'static str, LookupResult>) -> Self {
        Self { static_map }
    }

    pub async fn lookup_ip(&self, hostname: &str) -> Result<LookupResult, Error> {
        utils::timeout(
            RESOLUTION_TIMEOUT,
            Error::LookupFailed,
            self.dns_lookup(hostname),
        )
        .await
        .or_else(|e| {
            if hostname.ends_with(SIGNAL_DOMAIN_SUFFIX) {
                log::warn!(
                    "DNS lookup failed for [{}], falling back to static map. Error: {:?}",
                    hostname,
                    e
                )
            }
            self.static_map
                .get(hostname)
                .ok_or(Error::LookupFailed)
                .cloned()
        })
    }

    async fn dns_lookup<'a>(&self, hostname: &'a str) -> Result<LookupResult, Error> {
        let lookup_result = tokio::net::lookup_host((hostname, 443))
            .await
            .map_err(|_| Error::LookupFailed)?;

        let (ipv4s, ipv6s): (Vec<_>, Vec<_>) =
            lookup_result.into_iter().partition_map(|ip| match ip {
                SocketAddr::V4(v4) => Either::Left(*v4.ip()),
                SocketAddr::V6(v6) => Either::Right(*v6.ip()),
            });
        match LookupResult::new(ipv4s, ipv6s) {
            lookup_result if !lookup_result.is_empty() => Ok(lookup_result),
            _ => Err(Error::LookupFailed),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::infra::dns::LookupResult;
    use const_str::ip_addr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn lookup_result_iterates_in_the_right_order() {
        let ipv4_1 = ip_addr!(v4, "1.1.1.1");
        let ipv4_2 = ip_addr!(v4, "2.2.2.2");
        let ipv4_3 = ip_addr!(v4, "3.3.3.3");
        let ipv6_1 = ip_addr!(v6, "::1");
        let ipv6_2 = ip_addr!(v6, "::2");
        let ipv6_3 = ip_addr!(v6, "::3");

        validate_expected_order(
            vec![ipv4_1, ipv4_2, ipv4_3],
            vec![ipv6_1, ipv6_2, ipv6_3],
            vec![
                IpAddr::V6(ipv6_1),
                IpAddr::V4(ipv4_1),
                IpAddr::V6(ipv6_2),
                IpAddr::V4(ipv4_2),
                IpAddr::V6(ipv6_3),
                IpAddr::V4(ipv4_3),
            ],
        );

        validate_expected_order(
            vec![ipv4_1],
            vec![ipv6_1, ipv6_2, ipv6_3],
            vec![
                IpAddr::V6(ipv6_1),
                IpAddr::V4(ipv4_1),
                IpAddr::V6(ipv6_2),
                IpAddr::V6(ipv6_3),
            ],
        );

        validate_expected_order(
            vec![ipv4_1, ipv4_2, ipv4_3],
            vec![ipv6_1],
            vec![
                IpAddr::V6(ipv6_1),
                IpAddr::V4(ipv4_1),
                IpAddr::V4(ipv4_2),
                IpAddr::V4(ipv4_3),
            ],
        );

        validate_expected_order(
            vec![ipv4_1, ipv4_2, ipv4_3],
            vec![],
            vec![IpAddr::V4(ipv4_1), IpAddr::V4(ipv4_2), IpAddr::V4(ipv4_3)],
        );
    }

    fn validate_expected_order(ipv4s: Vec<Ipv4Addr>, ipv6s: Vec<Ipv6Addr>, expected: Vec<IpAddr>) {
        let lookup_result = LookupResult::new(ipv4s, ipv6s);
        let actual: Vec<IpAddr> = lookup_result.into_iter().collect();
        assert_eq!(expected, actual);
    }
}
