//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{FutureExt as _, StreamExt as _};
use oneshot_broadcast::Sender;
use tokio::time::Instant;

use crate::certs::RootCertificates;
use crate::dns::custom_resolver::CustomDnsResolver;
use crate::dns::dns_errors::Error;
use crate::dns::dns_lookup::{DnsLookup, DnsLookupRequest, StaticDnsMap, SystemDnsLookup};
use crate::dns::dns_transport_doh::{CLOUDFLARE_IPS, DohTransportConnectorFactory};
use crate::dns::dns_types::ResourceType;
use crate::dns::dns_utils::log_safe_domain;
use crate::dns::lookup_result::LookupResult;
use crate::host::Host;
use crate::route::{
    DEFAULT_HTTPS_PORT, HttpRouteFragment, HttpVersion, HttpsTlsRoute, TcpRoute, TlsRoute,
    TlsRouteFragment,
};
use crate::timeouts::{
    DNS_LATER_RESPONSE_GRACE_PERIOD, DNS_SYSTEM_LOOKUP_TIMEOUT, DOH_FALLBACK_LOOKUP_TIMEOUT,
};
use crate::utils::NetworkChangeEvent;
use crate::utils::oneshot_broadcast::{self, Receiver};
use crate::{Alpn, OverrideNagleAlgorithm, utils};

pub mod custom_resolver;
mod dns_errors;
pub mod dns_lookup;
mod dns_message;
pub mod dns_transport_doh;
pub mod dns_transport_udp;
mod dns_types;
pub(crate) mod dns_utils;
pub mod lookup_result;

pub type DnsError = Error;
pub type Result<T> = std::result::Result<T, Error>;

fn has_dns64_prefix(addr: &Ipv6Addr) -> bool {
    /// From "RFC 6052: IPv6 Addressing of IPv4/IPv6 Translators", Section 2.1:  Well-Known Prefix
    const DNS64_WELL_KNOWN_PREFIX: [u8; 12] = {
        let octs = const_str::ip_addr!(v6, "64:ff9b::").octets();
        *octs.first_chunk().unwrap()
    };

    addr.octets().starts_with(&DNS64_WELL_KNOWN_PREFIX)
}

struct DnsResolverState {
    /// Controls if lookup results will contain IPv6 entries.
    ipv6_enabled: bool,
    in_flight_lookups: HashMap<String, Receiver<Result<LookupResult>>>,
}

impl std::fmt::Debug for DnsResolverState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsResolverState")
            .field("ipv6_enabled", &self.ipv6_enabled)
            .field("in_flight_lookups", &self.in_flight_lookups.keys())
            .finish()
    }
}

impl Default for DnsResolverState {
    fn default() -> Self {
        Self {
            ipv6_enabled: true,
            in_flight_lookups: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsResolver {
    lookup_options: Arc<[LookupOption]>,
    state: Arc<Mutex<DnsResolverState>>,
    known_good_results: Arc<HashMap<&'static str, HashSet<IpAddr>>>,
}

/// A single DNS resolution strategy that can be tried.
#[derive(Debug)]
struct LookupOption {
    lookup: Box<dyn DnsLookup>,
    /// How long to wait for the lookup to finish before giving up on it.
    timeout_after: Duration,
}

pub fn build_custom_resolver_cloudflare_doh(
    network_change_event: &NetworkChangeEvent,
    secondary_request_grace_period: Duration,
) -> CustomDnsResolver<HttpsTlsRoute<TlsRoute<TcpRoute<IpAddr>>>, DohTransportConnectorFactory> {
    let (v4, v6) = CLOUDFLARE_IPS;
    let targets = [IpAddr::V6(v6), IpAddr::V4(v4)].map(|ip_addr| {
        let host = Host::Ip(ip_addr);
        HttpsTlsRoute {
            fragment: HttpRouteFragment {
                path_prefix: "".into(),
                front_name: None,
                host_header: Arc::from(host.to_string()),
                http_version: Some(HttpVersion::Http2),
            },
            inner: TlsRoute {
                fragment: TlsRouteFragment {
                    sni: host,
                    root_certs: RootCertificates::Native,
                    alpn: Some(Alpn::Http2),
                    min_protocol_version: Some(boring_signal::ssl::SslVersion::TLS1_2),
                },
                inner: TcpRoute {
                    address: ip_addr,
                    port: DEFAULT_HTTPS_PORT,
                    override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
                },
            },
        }
    });
    CustomDnsResolver::new(
        targets.into(),
        DohTransportConnectorFactory,
        network_change_event,
        secondary_request_grace_period,
    )
}

impl DnsResolver {
    #[cfg(any(test, feature = "test-util"))]
    pub fn new_custom(lookup_options: Vec<(Box<dyn DnsLookup>, Duration)>) -> Self {
        let lookup_options = lookup_options
            .into_iter()
            .map(|(lookup, timeout_after)| LookupOption {
                lookup,
                timeout_after,
            })
            .collect();

        DnsResolver {
            lookup_options,
            state: Default::default(),
            known_good_results: Arc::new(HashMap::new()),
        }
    }

    pub fn new(network_change_event: &NetworkChangeEvent) -> Self {
        Self::new_with_static_fallback(HashMap::new(), network_change_event)
    }

    /// Creates a DNS resolver that will only use a provided static map
    /// to resolve DNS lookups
    #[cfg_attr(feature = "test-util", visibility::make(pub))]
    fn new_from_static_map(static_map: HashMap<&'static str, LookupResult>) -> Self {
        DnsResolver {
            lookup_options: Arc::new([LookupOption {
                lookup: Box::new(StaticDnsMap(static_map)),
                timeout_after: Duration::from_millis(1),
            }]),
            state: Default::default(),
            known_good_results: Arc::new(HashMap::new()),
        }
    }

    /// Creates a DNS resolver with a default resolution strategy
    /// to be used for most of the external use cases
    pub fn new_with_static_fallback(
        static_map: HashMap<&'static str, LookupResult>,
        network_change_event: &NetworkChangeEvent,
    ) -> Self {
        let cloudflare_doh = Box::new(build_custom_resolver_cloudflare_doh(
            network_change_event,
            DNS_LATER_RESPONSE_GRACE_PERIOD,
        ));

        let known_good_results = Arc::new(
            static_map
                .iter()
                .map(|(host, result)| (*host, HashSet::from_iter(result)))
                .collect(),
        );

        let lookup_options = [
            LookupOption {
                lookup: Box::new(SystemDnsLookup),
                timeout_after: DNS_SYSTEM_LOOKUP_TIMEOUT,
            },
            LookupOption {
                lookup: cloudflare_doh,
                timeout_after: DOH_FALLBACK_LOOKUP_TIMEOUT,
            },
            LookupOption {
                lookup: Box::new(StaticDnsMap(static_map)),
                timeout_after: Duration::from_secs(1),
            },
        ];

        DnsResolver {
            lookup_options: lookup_options.into(),
            state: Default::default(),
            known_good_results,
        }
    }

    pub fn set_ipv6_enabled(&self, ipv6_enabled: bool) {
        let mut guard = self.state.lock().expect("not poisoned");
        if guard.ipv6_enabled != ipv6_enabled {
            guard.ipv6_enabled = ipv6_enabled;
            guard.in_flight_lookups.clear();
        }
    }

    pub fn on_network_change(&self, now: Instant) {
        for option in &self.lookup_options[..] {
            option.lookup.on_network_change(now);
        }
    }

    pub async fn lookup_ip(&self, hostname: &str) -> Result<LookupResult> {
        let parse_as_ip_addr = hostname.parse().ok().or_else(|| {
            let hostname = hostname.strip_prefix('[')?;
            let hostname = hostname.strip_suffix(']')?;
            Ipv6Addr::from_str(hostname).ok().map(std::net::IpAddr::V6)
        });
        if let Some(addr) = parse_as_ip_addr {
            let (ipv4, ipv6) = match addr {
                std::net::IpAddr::V4(ip) => (vec![ip], vec![]),
                std::net::IpAddr::V6(ip) => (vec![], vec![ip]),
            };
            return Ok(LookupResult { ipv4, ipv6 });
        }
        match self.start_or_join_lookup(hostname).val().await {
            Ok(r) => r,
            Err(_) => {
                log::warn!("Lookup task dropped before publishing the result");
                Err(Error::LookupFailed)
            }
        }
    }

    fn start_or_join_lookup(&self, hostname: &str) -> Receiver<Result<LookupResult>> {
        let mut guard = self.state.lock().expect("not poisoned");
        let ipv6_enabled = guard.ipv6_enabled;
        guard
            .in_flight_lookups
            .entry(hostname.to_string())
            .or_insert_with(|| {
                let (tx, rx) = oneshot_broadcast::channel();
                self.spawn_lookup(hostname.to_string(), tx, ipv6_enabled);
                rx
            })
            .clone()
    }

    fn spawn_lookup(
        &self,
        hostname: String,
        result_sender: Sender<Result<LookupResult>>,
        ipv6_enabled: bool,
    ) {
        let Self {
            lookup_options,
            state,
            known_good_results,
        } = self.clone();
        tokio::spawn(async move {
            let request = DnsLookupRequest {
                hostname: Arc::from(hostname.as_str()),
                ipv6_enabled,
            };

            let successful_lookups = futures_util::stream::iter(lookup_options.iter())
                .filter_map(|lookup_option| lookup_option.attempt(request.clone()).map(Result::ok));
            let mut perform_lookups = std::pin::pin!(successful_lookups);

            let result = perform_lookups
                .next()
                .await
                .ok_or(Error::LookupFailed)
                .and_then(|res| match ipv6_enabled {
                    true => Ok(res),
                    false if res.ipv4.is_empty() => Err(Error::RequestedIpTypeNotFound),
                    false => Ok(LookupResult {
                        ipv6: vec![],
                        ..res
                    }),
                });

            let log_safe_hostname = log_safe_domain(&hostname);

            if let Ok(lookup) = &result {
                if let Some(expected) = known_good_results.get(hostname.as_str()) {
                    let mut unexpected =
                        lookup.iter().filter(|ip| !expected.contains(ip)).peekable();

                    if unexpected.peek().is_some() {
                        let dns64_suffix = if unexpected
                            .any(|ip| matches!(ip, IpAddr::V6(v6) if has_dns64_prefix(&v6)))
                        {
                            " with DNS64 prefix"
                        } else {
                            ""
                        };

                        log::warn!(
                            "DNS resolution for domain [{log_safe_hostname}] returned unexpected result {dns64_suffix}",
                        );
                    }
                }

                if lookup.ipv6.iter().any(has_dns64_prefix) {
                    log::info!("Detected DNS64 in use for domain [{log_safe_hostname}]",);
                }
            }

            state
                .lock()
                .expect("not poisoned")
                .in_flight_lookups
                .remove(&hostname);
            if result_sender.send(result).is_err() {
                log::debug!("No DNS result listeners left for domain [{log_safe_hostname}]",);
            }
        });
    }
}

impl LookupOption {
    async fn attempt(&self, request: DnsLookupRequest) -> Result<LookupResult> {
        let Self {
            lookup,
            timeout_after,
        } = self;
        let started_at = Instant::now();
        let log_safe_domain = log_safe_domain(&request.hostname).to_string();
        let result =
            utils::timeout(*timeout_after, Error::Timeout, lookup.dns_lookup(request)).await;
        match &result {
            Ok(_) => {
                log::debug!(
                    "Resolved domain [{}] after {:.3?}",
                    log_safe_domain,
                    started_at.elapsed(),
                );
            }
            Err(error) => {
                log::warn!(
                    "Failed to resolve domain [{}] after {:.3?}: {}",
                    log_safe_domain,
                    started_at.elapsed(),
                    error,
                );
            }
        }
        result
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::future;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use const_str::ip_addr;

    use super::*;
    use crate::dns::dns_lookup::DnsLookupRequest;
    use crate::dns::{DnsLookup, DnsResolver, Error, LookupResult, StaticDnsMap};
    use crate::utils::{sleep_and_catch_up, timed};

    const IPV4: Ipv4Addr = ip_addr!(v4, "192.0.2.1");
    const IPV6: Ipv6Addr = ip_addr!(v6, "3fff::1");

    const CUSTOM_DOMAIN: &str = "custom.signal.org";
    const IPV4_ONLY_DOMAIN: &str = "ipv4.signal.org";
    const IPV6_ONLY_DOMAIN: &str = "ipv6.signal.org";
    const DUAL_STACK_DOMAIN: &str = "dual.signal.org";
    const TIMING_OUT_DOMAIN: &str = "time.signal.org";
    const FALLBACK_ONLY_DOMAIN: &str = "fallback.signal.org";

    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);

    impl From<Ipv4Addr> for LookupResult {
        fn from(value: Ipv4Addr) -> Self {
            LookupResult::new(vec![value], vec![])
        }
    }

    impl From<Ipv6Addr> for LookupResult {
        fn from(value: Ipv6Addr) -> Self {
            LookupResult::new(vec![], vec![value])
        }
    }

    impl From<(Ipv4Addr, Ipv6Addr)> for LookupResult {
        fn from(value: (Ipv4Addr, Ipv6Addr)) -> Self {
            LookupResult::new(vec![value.0], vec![value.1])
        }
    }

    #[derive(Clone, Debug)]
    struct TestLookup {
        delay: Duration,
        custom_domain_result: Result<LookupResult>,
        requests_log: Arc<Mutex<Vec<DnsLookupRequest>>>,
    }

    impl TestLookup {
        fn standard_responses(delay: Duration) -> Box<Self> {
            Box::new(Self {
                delay,
                custom_domain_result: Err(Error::LookupFailed),
                requests_log: Default::default(),
            })
        }

        fn with_custom_response<T: Into<LookupResult>>(
            delay: Duration,
            custom_domain_result: T,
        ) -> Box<Self> {
            Box::new(Self {
                delay,
                custom_domain_result: Ok(custom_domain_result.into()),
                requests_log: Default::default(),
            })
        }

        fn log_request(&self, request: DnsLookupRequest) {
            let mut guard = self.requests_log.lock().expect("not poisoned");
            guard.push(request);
        }

        fn logged_requests(&self) -> Vec<DnsLookupRequest> {
            let guard = self.requests_log.lock().expect("not poisoned");
            guard.clone()
        }
    }

    #[async_trait]
    impl DnsLookup for TestLookup {
        async fn dns_lookup(&self, request: DnsLookupRequest) -> Result<LookupResult> {
            self.log_request(request.clone());
            tokio::time::sleep(self.delay).await;
            match request.hostname.as_ref() {
                IPV4_ONLY_DOMAIN => Ok(IPV4.into()),
                IPV6_ONLY_DOMAIN => Ok(IPV6.into()),
                DUAL_STACK_DOMAIN => Ok((IPV4, IPV6).into()),
                CUSTOM_DOMAIN => self.custom_domain_result.clone(),
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
    async fn test_dns_lookup_without_fallback() {
        let dns_resolver = DnsResolver::new_custom(vec![(
            TestLookup::standard_responses(Duration::ZERO),
            ATTEMPT_TIMEOUT,
        )]);

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
    async fn test_dns_lookup_fallback() {
        let static_dns_map = StaticDnsMap(HashMap::from([
            (FALLBACK_ONLY_DOMAIN, (IPV4, IPV6).into()),
            (TIMING_OUT_DOMAIN, (IPV4, IPV6).into()),
        ]));
        let dns_resolver = DnsResolver::new_custom(vec![
            (
                TestLookup::standard_responses(Duration::ZERO),
                ATTEMPT_TIMEOUT,
            ),
            (Box::new(static_dns_map), ATTEMPT_TIMEOUT),
        ]);

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

    #[tokio::test(start_paused = true)]
    async fn test_fallback_timing() {
        // We have two resolvers chained together:
        //   1. The primary resolver with a timeout of two seconds, that take three seconds to return an IPv6 result.
        //   2. The fallback resolver with a timeout of two seconds, that returns an IPv4 result immediately.
        //
        // Thus, we expect that we get an IPv4 result from the fallback resolver almost immediately
        //   after the primary lookup times out.
        let primary_timeout = Duration::from_secs(2);
        let fallback_timeout = Duration::from_secs(2);
        let primary_lookup = TestLookup::with_custom_response(Duration::from_secs(3), IPV6);
        let fallback_lookup = TestLookup::with_custom_response(Duration::ZERO, IPV4);

        let resolver = Arc::new(DnsResolver::new_custom(vec![
            (primary_lookup, primary_timeout),
            (fallback_lookup, fallback_timeout),
        ]));

        let (elapsed, result) = timed(resolver.lookup_ip(CUSTOM_DOMAIN)).await;

        assert_eq!(
            result.unwrap().ipv4,
            vec![IPV4],
            "Fallback lookup did not return expected IPv4 result"
        );
        assert!(
            primary_timeout == elapsed,
            "Lookup timing was incorrect. Expected: primary_timeout ({primary_timeout:?}) == elapsed ({elapsed:?})",
        );
    }

    #[tokio::test]
    async fn test_dns_lookup_ipv6_disabled() {
        let static_dns_map =
            StaticDnsMap(HashMap::from([(FALLBACK_ONLY_DOMAIN, (IPV4, IPV6).into())]));
        let dns_resolver = DnsResolver::new_custom(vec![
            (
                TestLookup::standard_responses(Duration::ZERO),
                ATTEMPT_TIMEOUT,
            ),
            (Box::new(static_dns_map), ATTEMPT_TIMEOUT),
        ]);
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
        assert_matches!(ipv6_only_result, Err(Error::RequestedIpTypeNotFound));

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

    #[tokio::test(start_paused = true)]
    async fn test_ipv6_enabled_flag_is_passed_with_request() {
        let test_lookup = TestLookup::standard_responses(Duration::ZERO);
        let dns_resolver = DnsResolver::new_custom(vec![(test_lookup.clone(), ATTEMPT_TIMEOUT)]);

        let _ = dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await;
        dns_resolver.set_ipv6_enabled(false);
        let _ = dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await;
        dns_resolver.set_ipv6_enabled(true);
        let _ = dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await;
        assert_matches!(
            test_lookup.logged_requests().as_slice(),
            [
                DnsLookupRequest {
                    ipv6_enabled: true,
                    ..
                },
                DnsLookupRequest {
                    ipv6_enabled: false,
                    ..
                },
                DnsLookupRequest {
                    ipv6_enabled: true,
                    ..
                },
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_flag_value_used_from_the_time_of_request() {
        let lookup_time = ATTEMPT_TIMEOUT / 2;
        let flag_change_time = lookup_time / 2;

        let dns_resolver = DnsResolver::new_custom(vec![(
            TestLookup::standard_responses(lookup_time),
            ATTEMPT_TIMEOUT,
        )]);

        // starting the lookup with the `ipv6_enabled` flag set to `true`
        let dns_resolver_clone = dns_resolver.clone();
        let lookup_result_handle =
            tokio::spawn(async move { dns_resolver_clone.lookup_ip(DUAL_STACK_DOMAIN).await });

        // changing the flag
        tokio::time::sleep(flag_change_time).await;
        dns_resolver.set_ipv6_enabled(false);

        // dual stack now only returns ipv4
        let dual_stack_result = lookup_result_handle
            .await
            .expect("successfully joined spawned task")
            .expect("successful lookup result");
        // mid-lookup flag change should've not affected the result
        assert_non_empty!(dual_stack_result.ipv4);
        assert_non_empty!(dual_stack_result.ipv6);
    }

    #[tokio::test(start_paused = true)]
    async fn test_in_flight_requests_respect_ipv6_flag_value() {
        let lookup_time = ATTEMPT_TIMEOUT / 2;
        let flag_change_time = lookup_time / 2;

        let test_lookup = TestLookup::standard_responses(lookup_time);
        let dns_resolver = DnsResolver::new_custom(vec![(test_lookup.clone(), ATTEMPT_TIMEOUT)]);

        // starting the lookup with the `ipv6_enabled` flag set to `true`
        let dns_resolver_clone = dns_resolver.clone();
        tokio::spawn(async move { dns_resolver_clone.lookup_ip(DUAL_STACK_DOMAIN).await });

        // changing the flag
        tokio::time::sleep(flag_change_time).await;
        dns_resolver.set_ipv6_enabled(false);

        // starting another lookup to the same domain
        let dns_resolver_clone = dns_resolver.clone();
        tokio::spawn(async move { dns_resolver_clone.lookup_ip(DUAL_STACK_DOMAIN).await });

        sleep_and_catch_up(Duration::ZERO).await;

        // checking that the resolver sent both requests to the `DnsLookup`
        // instead of merging them into one
        assert_matches!(
            test_lookup.logged_requests().as_slice(),
            [
                DnsLookupRequest {
                    ipv6_enabled: true,
                    ..
                },
                DnsLookupRequest {
                    ipv6_enabled: false,
                    ..
                },
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_lookup_sequence() {
        let timing_out = ATTEMPT_TIMEOUT * 2;
        let normal_delay = ATTEMPT_TIMEOUT / 2;
        let short_delay = ATTEMPT_TIMEOUT / 10;

        let ip_1 = ip_addr!(v4, "192.0.2.1");
        let ip_2 = ip_addr!(v4, "192.0.2.2");
        let ip_3 = ip_addr!(v4, "192.0.2.3");

        async fn assert_expected_result(
            lookup_options: Vec<Box<dyn DnsLookup>>,
            expected: Option<Ipv4Addr>,
        ) {
            let dns_resolver = DnsResolver::new_custom(
                lookup_options
                    .into_iter()
                    .map(|lookup| (lookup, ATTEMPT_TIMEOUT))
                    .collect(),
            );
            let actual = dns_resolver.lookup_ip(CUSTOM_DOMAIN).await;
            match expected {
                Some(ip) => assert_eq!(&[ip], actual.unwrap().ipv4.as_slice()),
                None => assert_matches!(actual, Err(Error::LookupFailed)),
            }
        }

        // the domain checked in `assert_expected_result` is `CUSTOM_DOMAIN`
        // `TestLookup::with_custom_response()` configures the response,
        // while `TestLookup::standard_responses` will result in a lookup error

        assert_expected_result(
            vec![
                TestLookup::with_custom_response(normal_delay, ip_1),
                TestLookup::with_custom_response(short_delay, ip_2),
                TestLookup::with_custom_response(timing_out, ip_3),
            ],
            Some(ip_1),
        )
        .await;

        assert_expected_result(
            vec![
                TestLookup::with_custom_response(timing_out, ip_1),
                TestLookup::with_custom_response(normal_delay, ip_2),
                TestLookup::with_custom_response(short_delay, ip_3),
            ],
            Some(ip_2),
        )
        .await;

        assert_expected_result(
            vec![
                TestLookup::with_custom_response(timing_out, ip_1),
                TestLookup::with_custom_response(timing_out, ip_2),
                TestLookup::with_custom_response(short_delay, ip_3),
            ],
            Some(ip_3),
        )
        .await;

        assert_expected_result(
            vec![
                TestLookup::standard_responses(short_delay),
                TestLookup::with_custom_response(normal_delay, ip_2),
                TestLookup::with_custom_response(short_delay, ip_3),
            ],
            Some(ip_2),
        )
        .await;

        assert_expected_result(
            vec![
                TestLookup::standard_responses(short_delay),
                TestLookup::standard_responses(normal_delay),
                TestLookup::with_custom_response(short_delay, ip_3),
            ],
            Some(ip_3),
        )
        .await;

        assert_expected_result(
            vec![
                TestLookup::standard_responses(short_delay),
                TestLookup::standard_responses(normal_delay),
                TestLookup::standard_responses(normal_delay),
            ],
            None,
        )
        .await;

        assert_expected_result(
            vec![
                TestLookup::standard_responses(short_delay),
                TestLookup::with_custom_response(timing_out, ip_2),
            ],
            None,
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_request_joins_in_flight_request() {
        let response_delay = ATTEMPT_TIMEOUT / 2;
        let test_lookup = TestLookup::standard_responses(response_delay);
        let dns_resolver = Arc::new(DnsResolver::new_custom(vec![(
            test_lookup.clone(),
            ATTEMPT_TIMEOUT,
        )]));

        // starting a few requests all within the timeframe of receiving the first response
        let join_handlers: Vec<_> = [Duration::ZERO, response_delay / 4, response_delay / 2]
            .into_iter()
            .map(|request_delay| {
                let dns_resolver = dns_resolver.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(request_delay).await;
                    dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await
                })
            })
            .collect();

        // all requests should complete successfully with the same result
        for jh in join_handlers {
            assert_eq!(&[IPV4], jh.await.unwrap().unwrap().ipv4.as_slice())
        }
        // making sure that the `test_lookup` have only seen one request
        assert_matches!(test_lookup.logged_requests().as_slice(), [_]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_starting_new_lookup_if_previous_done() {
        let response_delay = ATTEMPT_TIMEOUT / 2;
        let test_lookup = TestLookup::standard_responses(response_delay);
        let dns_resolver = Arc::new(DnsResolver::new_custom(vec![(
            test_lookup.clone(),
            ATTEMPT_TIMEOUT,
        )]));
        let _ = dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await.unwrap();
        let _ = dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await.unwrap();
        // making sure that the `test_lookup` have only seen one request
        assert_matches!(test_lookup.logged_requests().as_slice(), [_, _]);
    }
}
