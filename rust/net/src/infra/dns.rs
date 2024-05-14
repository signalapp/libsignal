//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::{stream, StreamExt};
use std::collections::HashMap;
use std::future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nonzero_ext::nonzero;
use oneshot_broadcast::Sender;
use tokio::time::Instant;

use crate::infra::certs::RootCertificates;
use crate::infra::dns::custom_resolver::CustomDnsResolver;
use crate::infra::dns::dns_errors::Error;
use crate::infra::dns::dns_lookup::{DnsLookup, DnsLookupRequest, StaticDnsMap, SystemDnsLookup};
use crate::infra::dns::dns_transport_doh::{DohTransport, CLOUDFLARE_NS};
use crate::infra::dns::dns_types::ResourceType;
use crate::infra::dns::dns_utils::oneshot_broadcast::Receiver;
use crate::infra::dns::dns_utils::{log_safe_domain, oneshot_broadcast};
use crate::infra::dns::lookup_result::LookupResult;
use crate::infra::{ConnectionParams, HttpRequestDecoratorSeq, RouteType};
use crate::utils;

pub mod custom_resolver;
mod dns_errors;
pub mod dns_lookup;
mod dns_message;
pub mod dns_transport_doh;
pub mod dns_transport_udp;
mod dns_types;
mod dns_utils;
pub mod lookup_result;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Default)]
pub struct DnsResolver {
    /// Controls if lookup results will contain IPv6 entries.
    ipv6_enabled: bool,
    lookup_options: Arc<Vec<(Box<dyn DnsLookup>, Duration)>>,
    in_flight_lookups: Arc<Mutex<HashMap<String, Receiver<Result<LookupResult>>>>>,
}

impl DnsResolver {
    #[cfg(test)]
    pub(crate) fn new_custom(lookup_options: Vec<(Box<dyn DnsLookup>, Duration)>) -> Self {
        DnsResolver {
            ipv6_enabled: true,
            lookup_options: Arc::new(lookup_options),
            in_flight_lookups: Default::default(),
        }
    }

    /// Creates a DNS resolver that will only use a provided static map
    /// to resolve DNS lookups
    pub(crate) fn new_from_static_map(static_map: HashMap<&'static str, LookupResult>) -> Self {
        DnsResolver {
            ipv6_enabled: true,
            lookup_options: Arc::new(vec![(
                Box::new(StaticDnsMap(static_map)),
                Duration::from_millis(1),
            )]),
            in_flight_lookups: Default::default(),
        }
    }

    /// Creates a DNS resolver with a default resolution strategy
    /// to be used for most of the external use cases
    pub fn new_with_static_fallback(static_map: HashMap<&'static str, LookupResult>) -> Self {
        let connection_params = ConnectionParams::new(
            RouteType::Direct,
            CLOUDFLARE_NS,
            CLOUDFLARE_NS,
            nonzero!(443u16),
            HttpRequestDecoratorSeq::default(),
            RootCertificates::Native,
        );
        let custom_resolver = Box::new(CustomDnsResolver::<DohTransport>::new(connection_params));
        DnsResolver {
            ipv6_enabled: true,
            lookup_options: Arc::new(vec![
                (Box::new(SystemDnsLookup), Duration::from_secs(2)),
                (custom_resolver.clone(), Duration::from_secs(5)),
                (custom_resolver.clone(), Duration::from_secs(10)),
                (custom_resolver.clone(), Duration::from_secs(15)),
                (Box::new(StaticDnsMap(static_map)), Duration::from_secs(1)),
            ]),
            in_flight_lookups: Default::default(),
        }
    }

    pub fn set_ipv6_enabled(&mut self, ipv6_enabled: bool) {
        self.ipv6_enabled = ipv6_enabled;
    }

    pub async fn lookup_ip(&self, hostname: &str) -> Result<LookupResult> {
        match self.start_or_join_lookup(hostname).val().await {
            Ok(r) => r,
            Err(_) => {
                log::warn!("Lookup task dropped before publishing the result");
                Err(Error::LookupFailed)
            }
        }
    }

    fn start_or_join_lookup(&self, hostname: &str) -> Receiver<Result<LookupResult>> {
        let mut guard = self.in_flight_lookups.lock().expect("not poisoned");
        match guard.get(hostname) {
            None => {
                let (tx, rx) = oneshot_broadcast::channel();
                guard.insert(hostname.to_string(), rx.clone());
                self.spawn_lookup(hostname.to_string(), tx);
                rx
            }
            Some(r) => r.clone(),
        }
    }

    fn spawn_lookup(&self, hostname: String, result_sender: Sender<Result<LookupResult>>) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let request = DnsLookupRequest {
                hostname: Arc::from(hostname.as_str()),
                ipv6_enabled: self_clone.ipv6_enabled,
            };
            let sequence = self_clone
                .lookup_options
                .iter()
                .map(|(lookup, timeout)| attempt(request.clone(), lookup.as_ref(), *timeout));

            let result = stream::iter(sequence)
                .then(|task| task)
                .boxed()
                .filter_map(|result| future::ready(result.ok()))
                .next()
                .await
                .ok_or(Error::LookupFailed)
                .and_then(|res| match self_clone.ipv6_enabled {
                    true => Ok(res),
                    false if res.ipv4.is_empty() => Err(Error::RequestedIpTypeNotFound),
                    false => Ok(LookupResult {
                        ipv6: vec![],
                        ..res
                    }),
                });
            self_clone.clear_in_flight_map(hostname.as_str());
            if result_sender.send(result).is_err() {
                log::debug!(
                    "No DNS result listeners left for domain [{}]",
                    log_safe_domain(hostname.as_str())
                );
            }
        });
    }

    fn clear_in_flight_map(&self, hostname: &str) {
        let mut guard = self.in_flight_lookups.lock().expect("not poisoned");
        guard.remove(hostname);
    }
}

async fn attempt<T: DnsLookup + ?Sized>(
    request: DnsLookupRequest,
    lookup_strategy: &T,
    timeout: Duration,
) -> Result<LookupResult> {
    let started_at = Instant::now();
    let log_safe_domain = log_safe_domain(&request.hostname).to_string();
    let result = utils::timeout(timeout, Error::Timeout, lookup_strategy.dns_lookup(request)).await;
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

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;
    use std::future;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use const_str::ip_addr;

    use crate::infra::dns::custom_resolver::test::{
        ok_query_result_ipv4, respond_after_timeout, TestDnsTransportWithOneResponse,
    };
    use crate::infra::dns::dns_lookup::DnsLookupRequest;
    use crate::infra::dns::{DnsLookup, DnsResolver, Error, LookupResult, StaticDnsMap};
    use crate::infra::DnsSource;

    const IPV4: Ipv4Addr = ip_addr!(v4, "1.1.1.1");
    const IPV6: Ipv6Addr = ip_addr!(v6, "::1");

    const IPV4_ONLY_DOMAIN: &str = "ipv4.signal.org";
    const IPV6_ONLY_DOMAIN: &str = "ipv6.signal.org";
    const DUAL_STACK_DOMAIN: &str = "dual.signal.org";
    const TIMING_OUT_DOMAIN: &str = "time.signal.org";
    const FALLBACK_ONLY_DOMAIN: &str = "fallback.signal.org";

    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);

    struct TestLookup;

    #[async_trait]
    impl DnsLookup for TestLookup {
        async fn dns_lookup(&self, request: DnsLookupRequest) -> super::Result<LookupResult> {
            match request.hostname.as_ref() {
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
        let dns_resolver = DnsResolver::new_custom(vec![(Box::new(TestLookup), ATTEMPT_TIMEOUT)]);

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
        let static_dns_map = StaticDnsMap(HashMap::from([
            (
                FALLBACK_ONLY_DOMAIN,
                LookupResult::new(DnsSource::Test, vec![IPV4], vec![IPV6]),
            ),
            (
                TIMING_OUT_DOMAIN,
                LookupResult::new(DnsSource::Test, vec![IPV4], vec![IPV6]),
            ),
        ]));
        let dns_resolver = DnsResolver::new_custom(vec![
            (Box::new(TestLookup), ATTEMPT_TIMEOUT),
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
    async fn test_dns_loopup_ipv6_disabled() {
        let static_dns_map = StaticDnsMap(HashMap::from([(
            FALLBACK_ONLY_DOMAIN,
            LookupResult::new(DnsSource::Test, vec![IPV4], vec![IPV6]),
        )]));
        let mut dns_resolver = DnsResolver::new_custom(vec![
            (Box::new(TestLookup), ATTEMPT_TIMEOUT),
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
        struct ExpectedIpv6EnabledFlagValue(bool);

        #[async_trait]
        impl DnsLookup for ExpectedIpv6EnabledFlagValue {
            async fn dns_lookup(&self, request: DnsLookupRequest) -> Result<LookupResult> {
                if request.ipv6_enabled == self.0 {
                    Ok(LookupResult::new(DnsSource::Test, vec![IPV4], vec![]))
                } else {
                    Err(Error::LookupFailed)
                }
            }
        }

        let mut dns_resolver = DnsResolver::new_custom(vec![(
            Box::new(ExpectedIpv6EnabledFlagValue(true)),
            ATTEMPT_TIMEOUT,
        )]);
        assert_matches!(dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await, Ok(_));
        dns_resolver.set_ipv6_enabled(false);
        assert_matches!(
            dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await,
            Err(Error::LookupFailed)
        );

        let mut dns_resolver = DnsResolver::new_custom(vec![(
            Box::new(ExpectedIpv6EnabledFlagValue(false)),
            ATTEMPT_TIMEOUT,
        )]);
        assert_matches!(
            dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await,
            Err(Error::LookupFailed)
        );
        dns_resolver.set_ipv6_enabled(false);
        assert_matches!(dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await, Ok(_));
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
            let actual = dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await;
            match expected {
                Some(ip) => assert_eq!(&[ip], actual.unwrap().ipv4.as_slice()),
                None => assert_matches!(actual, Err(Error::LookupFailed)),
            }
        }

        assert_expected_result(
            vec![
                lookup_ok(normal_delay, ip_1),
                lookup_ok(short_delay, ip_2),
                lookup_ok(timing_out, ip_3),
            ],
            Some(ip_1),
        )
        .await;

        assert_expected_result(
            vec![
                lookup_ok(timing_out, ip_1),
                lookup_ok(normal_delay, ip_2),
                lookup_ok(short_delay, ip_3),
            ],
            Some(ip_2),
        )
        .await;

        assert_expected_result(
            vec![
                lookup_ok(timing_out, ip_1),
                lookup_ok(timing_out, ip_2),
                lookup_ok(short_delay, ip_3),
            ],
            Some(ip_3),
        )
        .await;

        assert_expected_result(
            vec![
                lookup_error(short_delay),
                lookup_ok(normal_delay, ip_2),
                lookup_ok(short_delay, ip_3),
            ],
            Some(ip_2),
        )
        .await;

        assert_expected_result(
            vec![
                lookup_error(short_delay),
                lookup_error(normal_delay),
                lookup_ok(short_delay, ip_3),
            ],
            Some(ip_3),
        )
        .await;

        assert_expected_result(
            vec![
                lookup_error(short_delay),
                lookup_error(normal_delay),
                lookup_error(normal_delay),
            ],
            None,
        )
        .await;

        assert_expected_result(
            vec![lookup_error(short_delay), lookup_ok(timing_out, ip_2)],
            None,
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_request_joins_in_flight_request() {
        let response_delay = ATTEMPT_TIMEOUT / 2;
        let resolver =
            TestDnsTransportWithOneResponse::custom_dns_resolver(move |_, q_num, txs| {
                // only works once
                if q_num == 1 {
                    let [tx] = txs;
                    respond_after_timeout(
                        response_delay,
                        tx,
                        ok_query_result_ipv4(Duration::ZERO, &[IPV4]),
                    );
                }
            });

        let dns_resolver = Arc::new(DnsResolver::new_custom(vec![(
            Box::new(resolver),
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
    }

    #[tokio::test(start_paused = true)]
    async fn test_starting_new_lookup_if_previous_done() {
        let response_delay = ATTEMPT_TIMEOUT / 2;
        let ip_1 = ip_addr!(v4, "2.2.2.1");
        let ip_2 = ip_addr!(v4, "2.2.2.2");
        let resolver =
            TestDnsTransportWithOneResponse::custom_dns_resolver(move |_, q_num, txs| {
                let [tx] = txs;
                let ip = if q_num == 1 { ip_1 } else { ip_2 };
                respond_after_timeout(
                    response_delay,
                    tx,
                    ok_query_result_ipv4(Duration::ZERO, &[ip]),
                );
            });

        let dns_resolver = DnsResolver::new_custom(vec![(Box::new(resolver), ATTEMPT_TIMEOUT)]);

        let result = dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await.unwrap();
        assert_eq!(&[ip_1], result.ipv4.as_slice());

        let result = dns_resolver.lookup_ip(IPV4_ONLY_DOMAIN).await.unwrap();
        assert_eq!(&[ip_2], result.ipv4.as_slice());
    }

    fn lookup_ok(delay: Duration, ip: Ipv4Addr) -> Box<impl DnsLookup> {
        Box::new(TestDnsTransportWithOneResponse::custom_dns_resolver(
            move |_, _, txs| {
                let [tx] = txs;
                respond_after_timeout(delay, tx, ok_query_result_ipv4(Duration::ZERO, &[ip]));
            },
        ))
    }

    fn lookup_error(delay: Duration) -> Box<impl DnsLookup> {
        Box::new(TestDnsTransportWithOneResponse::custom_dns_resolver(
            move |_, _, txs| {
                let [tx] = txs;
                respond_after_timeout(delay, tx, Err(Error::LookupFailed));
            },
        ))
    }
}
