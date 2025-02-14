//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::iter::Map;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice::Iter;
use std::vec::IntoIter;

use crate::DnsSource;

#[derive(Debug, Clone)]
pub struct LookupResult {
    pub(crate) source: DnsSource,
    pub(crate) ipv4: Vec<Ipv4Addr>,
    pub(crate) ipv6: Vec<Ipv6Addr>,
}

impl IntoIterator for LookupResult {
    type Item = IpAddr;
    type IntoIter = itertools::Interleave<
        Map<IntoIter<Ipv6Addr>, fn(Ipv6Addr) -> IpAddr>,
        Map<IntoIter<Ipv4Addr>, fn(Ipv4Addr) -> IpAddr>,
    >;

    /// Returns an iterator that interleaves IPv6 and IPv4 addresses.
    fn into_iter(self) -> Self::IntoIter {
        let v6_into_ipaddr: fn(Ipv6Addr) -> IpAddr = IpAddr::V6;
        let v4_into_ipaddr: fn(Ipv4Addr) -> IpAddr = IpAddr::V4;
        itertools::interleave(
            self.ipv6.into_iter().map(v6_into_ipaddr),
            self.ipv4.into_iter().map(v4_into_ipaddr),
        )
    }
}

impl<'a> IntoIterator for &'a LookupResult {
    type Item = IpAddr;
    type IntoIter = itertools::Interleave<
        Map<Iter<'a, Ipv6Addr>, fn(&Ipv6Addr) -> IpAddr>,
        Map<Iter<'a, Ipv4Addr>, fn(&Ipv4Addr) -> IpAddr>,
    >;

    /// Returns an iterator that interleaves IPv6 and IPv4 addresses.
    fn into_iter(self) -> Self::IntoIter {
        let v6_into_ipaddr: fn(&Ipv6Addr) -> IpAddr = |v| (*v).into();
        let v4_into_ipaddr: fn(&Ipv4Addr) -> IpAddr = |v| (*v).into();
        itertools::interleave(
            self.ipv6.iter().map(v6_into_ipaddr),
            self.ipv4.iter().map(v4_into_ipaddr),
        )
    }
}

impl LookupResult {
    pub fn new(source: DnsSource, ipv4: Vec<Ipv4Addr>, ipv6: Vec<Ipv6Addr>) -> Self {
        Self { source, ipv4, ipv6 }
    }

    pub fn iter(&self) -> <&Self as IntoIterator>::IntoIter {
        self.into_iter()
    }

    pub(crate) fn source(&self) -> DnsSource {
        self.source
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl LookupResult {
    pub fn localhost() -> Self {
        Self::new(
            DnsSource::Static,
            vec![Ipv4Addr::LOCALHOST],
            vec![Ipv6Addr::LOCALHOST],
        )
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use const_str::ip_addr;

    use crate::dns::lookup_result::LookupResult;
    use crate::DnsSource;

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
        let lookup_result = LookupResult::new(DnsSource::Static, ipv4s, ipv6s);
        let actual: Vec<IpAddr> = lookup_result.into_iter().collect();
        assert_eq!(expected, actual);
    }
}
