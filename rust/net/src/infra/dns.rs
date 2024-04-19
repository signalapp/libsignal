//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use itertools::{Either, Itertools};
use std::collections::HashMap;
use std::iter::Map;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::vec::IntoIter;

use crate::infra::DnsSource;
use crate::utils;

const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(1);
const SIGNAL_DOMAIN_SUFFIX: &str = ".signal.org";

#[derive(displaydoc::Display, Debug, thiserror::Error)]
pub enum Error {
    /// DNS lookup failed
    LookupFailed,
}

#[derive(Debug, Clone)]
pub struct LookupResult {
    source: DnsSource,
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
    pub fn new(source: DnsSource, ipv4: Vec<Ipv4Addr>, ipv6: Vec<Ipv6Addr>) -> Self {
        Self { source, ipv4, ipv6 }
    }

    pub(crate) fn source(&self) -> DnsSource {
        self.source
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

#[cfg(test)]
impl LookupResult {
    pub(crate) fn localhost() -> Self {
        Self::new(
            crate::infra::DnsSource::Static,
            vec![Ipv4Addr::LOCALHOST],
            vec![Ipv6Addr::LOCALHOST],
        )
    }
}

#[async_trait]
pub trait DnsLookup {
    async fn dns_lookup<'a>(hostname: &'a str) -> Result<LookupResult, Error>;
}

#[derive(Clone, Default)]
pub struct SystemDnsLookup;

#[async_trait]
impl DnsLookup for SystemDnsLookup {
    async fn dns_lookup<'a>(hostname: &'a str) -> Result<LookupResult, Error> {
        let lookup_result = tokio::net::lookup_host((hostname, 443))
            .await
            .map_err(|_| Error::LookupFailed)?;

        let (ipv4s, ipv6s): (Vec<_>, Vec<_>) =
            lookup_result.into_iter().partition_map(|ip| match ip {
                SocketAddr::V4(v4) => Either::Left(*v4.ip()),
                SocketAddr::V6(v6) => Either::Right(*v6.ip()),
            });
        match LookupResult::new(DnsSource::Lookup, ipv4s, ipv6s) {
            lookup_result if !lookup_result.is_empty() => Ok(lookup_result),
            _ => Err(Error::LookupFailed),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsResolver<D = SystemDnsLookup> {
    /// Static lookup entries.
    ///
    /// Held in an [`Arc`] to make `DnsResolver` cheap to clone.
    static_map: Arc<HashMap<&'static str, LookupResult>>,
    /// Controls if lookup results will contain IPv6 entries.
    ipv6_enabled: bool,
    _marker: PhantomData<D>,
}

impl<D: DnsLookup> DnsResolver<D> {
    pub fn new_with_static_fallback(static_map: HashMap<&'static str, LookupResult>) -> Self {
        DnsResolver {
            static_map: Arc::new(static_map),
            ipv6_enabled: true,
            _marker: PhantomData,
        }
    }

    pub fn set_ipv6_enabled(&mut self, ipv6_enabled: bool) {
        self.ipv6_enabled = ipv6_enabled;
    }

    pub async fn lookup_ip(&self, hostname: &str) -> Result<LookupResult, Error> {
        utils::timeout(
            RESOLUTION_TIMEOUT,
            Error::LookupFailed,
            D::dns_lookup(hostname),
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
        .and_then(|res| match self.ipv6_enabled {
            true => Ok(res),
            false if res.ipv4.is_empty() => Err(Error::LookupFailed),
            false => Ok(LookupResult {
                ipv6: vec![],
                ..res
            }),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::infra::dns::{DnsLookup, DnsResolver, Error, LookupResult};
    use crate::infra::DnsSource;
    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use const_str::ip_addr;
    use std::collections::HashMap;
    use std::future;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    struct TestLookup;

    const IPV4: Ipv4Addr = ip_addr!(v4, "1.1.1.1");
    const IPV6: Ipv6Addr = ip_addr!(v6, "::1");

    const IPV4_ONLY_DOMAIN: &str = "ipv4.signal.org";
    const IPV6_ONLY_DOMAIN: &str = "ipv6.signal.org";
    const DUAL_STACK_DOMAIN: &str = "dual.signal.org";
    const TIMING_OUT_DOMAIN: &str = "time.signal.org";
    const FALLBACK_ONLY_DOMAIN: &str = "fallback.signal.org";

    #[async_trait]
    impl DnsLookup for TestLookup {
        async fn dns_lookup<'a>(hostname: &'a str) -> Result<LookupResult, Error> {
            match hostname {
                IPV4_ONLY_DOMAIN => Ok(LookupResult::new(DnsSource::Test, vec![IPV4], vec![])),
                IPV6_ONLY_DOMAIN => Ok(LookupResult::new(DnsSource::Test, vec![], vec![IPV6])),
                DUAL_STACK_DOMAIN => Ok(LookupResult::new(DnsSource::Test, vec![IPV4], vec![IPV6])),
                TIMING_OUT_DOMAIN => future::pending().await,
                _ => Err(Error::LookupFailed),
            }
        }
    }

    macro_rules! assert_empty {
        ($vec:expr) => {
            assert!($vec.is_empty(), "expected empty vec but have: {:?}", $vec)
        };
    }

    macro_rules! assert_non_empty {
        ($vec:expr) => {
            assert!(!$vec.is_empty())
        };
    }

    #[tokio::test(start_paused = true)]
    async fn test_dns_loopup_without_fallback() {
        let dns_resolver = DnsResolver::<TestLookup>::new_with_static_fallback(HashMap::new());

        let ipv4_only_result = dns_resolver
            .lookup_ip(IPV4_ONLY_DOMAIN)
            .await
            .expect("success");
        assert_non_empty!(ipv4_only_result.ipv4);
        assert_empty!(ipv4_only_result.ipv6);

        let ipv6_only_result = dns_resolver
            .lookup_ip(IPV6_ONLY_DOMAIN)
            .await
            .expect("success");
        assert_empty!(ipv6_only_result.ipv4);
        assert_non_empty!(ipv6_only_result.ipv6);

        let dual_stack_result = dns_resolver
            .lookup_ip(DUAL_STACK_DOMAIN)
            .await
            .expect("success");
        assert_non_empty!(dual_stack_result.ipv4);
        assert_non_empty!(dual_stack_result.ipv6);

        let no_result = dns_resolver.lookup_ip(FALLBACK_ONLY_DOMAIN).await;
        assert_matches!(no_result, Err(Error::LookupFailed));

        let timeout_result = dns_resolver.lookup_ip(TIMING_OUT_DOMAIN).await;
        assert_matches!(timeout_result, Err(Error::LookupFailed));
    }

    #[tokio::test(start_paused = true)]
    async fn test_dns_loopup_fallback() {
        let dns_resolver = DnsResolver::<TestLookup>::new_with_static_fallback(HashMap::from([
            (
                FALLBACK_ONLY_DOMAIN,
                LookupResult::new(DnsSource::Test, vec![IPV4], vec![IPV6]),
            ),
            (
                TIMING_OUT_DOMAIN,
                LookupResult::new(DnsSource::Test, vec![IPV4], vec![IPV6]),
            ),
        ]));

        let result = dns_resolver
            .lookup_ip(FALLBACK_ONLY_DOMAIN)
            .await
            .expect("success");
        assert_non_empty!(result.ipv4);
        assert_non_empty!(result.ipv6);

        let result = dns_resolver
            .lookup_ip(TIMING_OUT_DOMAIN)
            .await
            .expect("success");
        assert_non_empty!(result.ipv4);
        assert_non_empty!(result.ipv6);
    }

    #[tokio::test]
    async fn test_dns_loopup_ipv6_disabled() {
        let mut dns_resolver =
            DnsResolver::<TestLookup>::new_with_static_fallback(HashMap::from([(
                FALLBACK_ONLY_DOMAIN,
                LookupResult::new(DnsSource::Test, vec![IPV4], vec![IPV6]),
            )]));
        dns_resolver.set_ipv6_enabled(false);

        // no changes to ipv4 behavior
        let ipv4_only_result = dns_resolver
            .lookup_ip(IPV4_ONLY_DOMAIN)
            .await
            .expect("success");
        assert_non_empty!(ipv4_only_result.ipv4);
        assert_empty!(ipv4_only_result.ipv6);

        // ipv6 only domain now results in failed lookup
        let ipv6_only_result = dns_resolver.lookup_ip(IPV6_ONLY_DOMAIN).await;
        assert_matches!(ipv6_only_result, Err(Error::LookupFailed));

        // dual stack now only returns ipv4
        let dual_stack_result = dns_resolver
            .lookup_ip(DUAL_STACK_DOMAIN)
            .await
            .expect("success");
        assert_non_empty!(dual_stack_result.ipv4);
        assert_empty!(dual_stack_result.ipv6);

        // fallback also behaves correctly
        let fallback_result = dns_resolver
            .lookup_ip(FALLBACK_ONLY_DOMAIN)
            .await
            .expect("success");
        assert_non_empty!(fallback_result.ipv4);
        assert_empty!(fallback_result.ipv6);
    }

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
