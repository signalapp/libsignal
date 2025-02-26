//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
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
use crate::dns::dns_transport_doh::{DohTransport, CLOUDFLARE_IPS};
use crate::dns::dns_types::ResourceType;
use crate::dns::dns_utils::log_safe_domain;
use crate::dns::lookup_result::LookupResult;
use crate::host::Host;
use crate::route::{
    HttpRouteFragment, HttpsTlsRoute, TcpRoute, TlsRoute, TlsRouteFragment, DEFAULT_HTTPS_PORT,
};
use crate::timeouts::{DNS_FALLBACK_LOOKUP_TIMEOUTS, DNS_SYSTEM_LOOKUP_TIMEOUT};
use crate::utils::oneshot_broadcast::{self, Receiver};
use crate::utils::{self, ObservableEvent};
use crate::Alpn;

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

#[derive(Clone, Debug)]
pub struct DnsResolver {
    lookup_options: Arc<[LookupOption]>,
    state: Arc<Mutex<DnsResolverState>>,
}

/// A single DNS resolution strategy that can be tried.
#[derive(Debug)]
struct LookupOption {
    lookup: Box<dyn DnsLookup>,
    /// How long to wait for the lookup to finish before giving up on it.
    timeout_after: Duration,
}

pub fn build_custom_resolver_cloudflare_doh(
    network_change_event: &ObservableEvent,
) -> CustomDnsResolver<DohTransport> {
    let (v4, v6) = CLOUDFLARE_IPS;
    let targets = [IpAddr::V6(v6), IpAddr::V4(v4)].map(|ip_addr| {
        let host = Host::Ip(ip_addr);
        HttpsTlsRoute {
            fragment: HttpRouteFragment {
                path_prefix: "".into(),
                front_name: None,
                host_header: Arc::from(host.to_string()),
            },
            inner: TlsRoute {
                fragment: TlsRouteFragment {
                    sni: host,
                    root_certs: RootCertificates::Native,
                    alpn: Some(Alpn::Http2),
                },
                inner: TcpRoute {
                    address: ip_addr,
                    port: DEFAULT_HTTPS_PORT,
                },
            },
        }
    });
    CustomDnsResolver::<DohTransport>::new(targets.into(), network_change_event)
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
        }
    }

    pub fn new(network_change_event: &ObservableEvent) -> Self {
        Self::new_with_static_fallback(HashMap::new(), network_change_event)
    }

    /// Creates a DNS resolver that will only use a provided static map
    /// to resolve DNS lookups
    #[cfg_attr(feature = "test-util", visibility::make(pub))]
    pub(crate) fn new_from_static_map(static_map: HashMap<&'static str, LookupResult>) -> Self {
        DnsResolver {
            lookup_options: Arc::new([LookupOption {
                lookup: Box::new(StaticDnsMap(static_map)),
                timeout_after: Duration::from_millis(1),
            }]),
            state: Default::default(),
        }
    }

    /// Creates a DNS resolver with a default resolution strategy
    /// to be used for most of the external use cases
    pub fn new_with_static_fallback(
        static_map: HashMap<&'static str, LookupResult>,
        network_change_event: &ObservableEvent,
    ) -> Self {
        let cloudflare_doh = Box::new(build_custom_resolver_cloudflare_doh(network_change_event));

        let cloudflare_fallback_options =
            DNS_FALLBACK_LOOKUP_TIMEOUTS
                .iter()
                .copied()
                .map(|timeout_after| LookupOption {
                    lookup: cloudflare_doh.clone(),
                    timeout_after,
                });

        let lookup_options = [LookupOption {
            lookup: Box::new(SystemDnsLookup),
            timeout_after: DNS_SYSTEM_LOOKUP_TIMEOUT,
        }]
        .into_iter()
        .chain(cloudflare_fallback_options)
        .chain([LookupOption {
            lookup: Box::new(StaticDnsMap(static_map)),
            timeout_after: Duration::from_secs(1),
        }])
        .collect();
        DnsResolver {
            lookup_options,
            state: Default::default(),
        }
    }

    pub fn set_ipv6_enabled(&self, ipv6_enabled: bool) {
        let mut guard = self.state.lock().expect("not poisoned");
        if guard.ipv6_enabled != ipv6_enabled {
            guard.ipv6_enabled = ipv6_enabled;
            guard.in_flight_lookups.clear();
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
            return Ok(LookupResult {
                source: super::DnsSource::Static,
                ipv4,
                ipv6,
            });
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

            state
                .lock()
                .expect("not poisoned")
                .in_flight_lookups
                .remove(&hostname);
            if result_sender.send(result).is_err() {
                log::debug!(
                    "No DNS result listeners left for domain [{}]",
                    log_safe_domain(&hostname)
                );
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
                    "Resolved domain [{}] after {:?}",
                    log_safe_domain,
                    started_at.elapsed(),
                );
            }
            Err(error) => {
                log::warn!(
                    "Failed to resolve domain [{}] after {:?}: {}",
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
    use crate::utils::sleep_and_catch_up;
    use crate::DnsSource;

    const IPV4: Ipv4Addr = ip_addr!(v4, "1.1.1.1");
    const IPV6: Ipv6Addr = ip_addr!(v6, "::1");

    const CUSTOM_DOMAIN: &str = "custom.signal.org";
    const IPV4_ONLY_DOMAIN: &str = "ipv4.signal.org";
    const IPV6_ONLY_DOMAIN: &str = "ipv6.signal.org";
    const DUAL_STACK_DOMAIN: &str = "dual.signal.org";
    const TIMING_OUT_DOMAIN: &str = "time.signal.org";
    const FALLBACK_ONLY_DOMAIN: &str = "fallback.signal.org";

    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);

    impl From<Ipv4Addr> for LookupResult {
        fn from(value: Ipv4Addr) -> Self {
            LookupResult::new(DnsSource::Test, vec![value], vec![])
        }
    }

    impl From<Ipv6Addr> for LookupResult {
        fn from(value: Ipv6Addr) -> Self {
            LookupResult::new(DnsSource::Test, vec![], vec![value])
        }
    }

    impl From<(Ipv4Addr, Ipv6Addr)> for LookupResult {
        fn from(value: (Ipv4Addr, Ipv6Addr)) -> Self {
            LookupResult::new(DnsSource::Test, vec![value.0], vec![value.1])
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

        let ip_1 = ip_addr!(v4, "2.2.2.1");
        let ip_2 = ip_addr!(v4, "2.2.2.2");
        let ip_3 = ip_addr!(v4, "2.2.2.3");

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
