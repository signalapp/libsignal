//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use either::Either;
use futures_util::{FutureExt as _, Stream, StreamExt as _};
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::connection_manager::{ConnectionAttemptOutcome, SingleRouteThrottlingConnectionManager};
use crate::dns::dns_errors::Error;
use crate::dns::dns_lookup::DnsLookupRequest;
use crate::dns::dns_types::Expiring;
use crate::dns::dns_utils::log_safe_domain;
use crate::dns::lookup_result::LookupResult;
use crate::timeouts::{DNS_CALL_BACKGROUND_TIMEOUT, DNS_RESOLUTION_DELAY};
use crate::utils::future::results_within_interval;
use crate::utils::{EventSubscription, ObservableEvent};
use crate::{dns, DnsSource};

pub type DnsIpv4Result = Expiring<Vec<Ipv4Addr>>;
pub type DnsIpv6Result = Expiring<Vec<Ipv6Addr>>;
pub type DnsQueryResult = Either<DnsIpv4Result, DnsIpv6Result>;

/// Artificially limit DNS lookup results, so we don't get stuck on stale info with a bad TTL field.
const MAX_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Implementors of this trait encapsulate the logic of sending queries to the DNS server
/// and receiving resposnes.
pub trait DnsTransport: Debug + Sized + Send {
    /// Type of the connection parameters data structure for this DNS transport
    type ConnectionParameters: Clone + Debug + Send + 'static;

    /// Returns the name of the DNS source
    fn dns_source() -> DnsSource;

    /// Establishes a connection to the DNS server over a specific transport.
    ///
    /// Connection will be held open for as long as the returned instance is in use.
    /// Dropping the instance will close the connection and free the resources.
    fn connect(
        connection_params: Self::ConnectionParameters,
        ipv6_enabled: bool,
    ) -> impl Future<Output = dns::Result<Self>> + Send;

    /// Sends DNS queries and returns an async stream of the results
    /// that the caller can handle according to the resolution logic.
    ///
    /// The returned stream of results is not guaranteed to produce exactly two elements.
    /// Depending on the context and restrictions, implementations may choose to return
    /// streams with fewer elements.
    ///
    /// Each result is a list of either IPv4 or IPv6 records
    /// with the order of results not specified.
    fn send_queries(
        self,
        request: DnsLookupRequest,
    ) -> impl Future<
        Output = dns::Result<impl Stream<Item = dns::Result<DnsQueryResult>> + Send + 'static>,
    > + Send;
}

#[derive(Debug)]
struct SharedCacheWithGenerations<K, V> {
    generation: u64,
    map: HashMap<K, V>,
}

impl<K, V> SharedCacheWithGenerations<K, V> {
    fn clear_and_advance(&mut self) {
        self.generation += 1;
        self.map.clear();
    }
}

impl<K, V> Default for SharedCacheWithGenerations<K, V> {
    fn default() -> Self {
        Self {
            generation: Default::default(),
            map: Default::default(),
        }
    }
}

/// A resolver that combines the logic of retrieving results of the DNS queries
/// over a specific transport and caching those results according to the
/// records expiration times.
#[derive(Debug, Clone)]
pub struct CustomDnsResolver<T: DnsTransport> {
    connection_manager: SingleRouteThrottlingConnectionManager<T::ConnectionParameters>,
    cache: Arc<std::sync::Mutex<SharedCacheWithGenerations<String, Expiring<LookupResult>>>>,
    _network_change_subscription: Arc<EventSubscription>,
}

impl<T: DnsTransport + Sync + 'static> CustomDnsResolver<T> {
    pub fn new(
        transport_connection_params: T::ConnectionParameters,
        network_change_event: &ObservableEvent,
    ) -> Self {
        let cache = Arc::new(std::sync::Mutex::new(SharedCacheWithGenerations::default()));
        let cache_for_network_change = Arc::downgrade(&cache);
        let network_change_subscription = network_change_event.subscribe(Box::new(move || {
            // We're clearing the cache on network changes because some networks intercept DNS
            // requests and return IPs that only work within that network.
            let Some(cache) = cache_for_network_change.upgrade() else {
                return;
            };
            cache.lock().expect("not poisoned").clear_and_advance();
        }));
        Self {
            connection_manager: SingleRouteThrottlingConnectionManager::new(
                transport_connection_params,
                DNS_CALL_BACKGROUND_TIMEOUT,
                network_change_event,
            ),
            cache,
            _network_change_subscription: Arc::new(network_change_subscription),
        }
    }

    pub async fn resolve(&self, request: DnsLookupRequest) -> dns::Result<LookupResult> {
        match self.cache_get(&request.hostname) {
            Some(res) => {
                log::info!(
                    "DNS record for {} found in cache",
                    log_safe_domain(&request.hostname)
                );
                Ok(res)
            }
            None => {
                log::info!(
                    "Starting DNS lookup for {}",
                    log_safe_domain(&request.hostname)
                );
                self.lookup(request).await
            }
        }
    }

    fn cache_get(&self, hostname: &str) -> Option<LookupResult> {
        let mut guard = self.cache.lock().expect("not poisoned");
        match guard.map.get(hostname) {
            Some(expiring) if expiring.expiration < Instant::now() => {
                guard.map.remove(hostname);
                None
            }
            Some(expiring) => Some(expiring.data.clone()),
            None => None,
        }
    }

    async fn lookup(&self, request: DnsLookupRequest) -> dns::Result<LookupResult> {
        let transport = match self
            .connection_manager
            .connect_or_wait(|params| T::connect(params.clone(), request.ipv6_enabled))
            .await
        {
            ConnectionAttemptOutcome::Attempted(result) => result,
            ConnectionAttemptOutcome::TimedOut => Err(Error::Timeout),
            ConnectionAttemptOutcome::WaitUntil(_) => Err(Error::Cooldown),
        }?;
        let (ipv4_res_rx, ipv6_res_rx) = self.send_dns_queries(transport, request);
        let (maybe_ipv4, maybe_ipv6) = results_within_interval(
            ipv4_res_rx.map(Result::ok),
            ipv6_res_rx.map(Result::ok),
            DNS_RESOLUTION_DELAY,
        )
        .await;
        let ipv4s = maybe_ipv4.map_or(vec![], |r| r.data);
        let ipv6s = maybe_ipv6.map_or(vec![], |r| r.data);
        match LookupResult::new(T::dns_source(), ipv4s, ipv6s) {
            lookup_result if !lookup_result.is_empty() => Ok(lookup_result),
            _ => Err(Error::LookupFailed),
        }
    }

    /// This method connects to the DNS server using the transport `T`,
    /// sends DNS queries for both IPv4 and IPv6 records, and then processes
    /// the responses. It will also take care of caching the results when they are received.
    ///
    /// The method has its own timeout value to wait for the results to arrive.
    /// It doesn't depend on the caller to drive the returned futures.
    fn send_dns_queries(
        &self,
        transport: T,
        request: DnsLookupRequest,
    ) -> (
        oneshot::Receiver<DnsIpv4Result>,
        oneshot::Receiver<DnsIpv6Result>,
    ) {
        let (ipv4_res_tx, ipv4_res_rx) = oneshot::channel::<DnsIpv4Result>();
        let (ipv6_res_tx, ipv6_res_rx) = oneshot::channel::<DnsIpv6Result>();
        let cache = self.cache.clone();
        let generation_before_lookup = cache.lock().expect("not poisoned").generation;
        let hostname = request.hostname.clone();
        // We're starting this operation on a separate thread because we want to let it run
        // beyond an individual attempt timeout so that even if a result arrived late
        // we could still cache it for the next time.
        //
        // Reference: https://datatracker.ietf.org/doc/html/rfc8305#section-3
        tokio::spawn(do_lookup_task_body(
            transport,
            request,
            (ipv4_res_tx, ipv6_res_tx),
            move |expiring_entry| {
                let mut guard = cache.lock().expect("not poisoned");
                // There are two ways the generation could be out of date:
                // - We started the query, completed the query, and then got a network change.
                // - We started the query, got a network change, and then completed the query on the
                //   new network.
                // In the second case caching the result would still be valid, but trying to
                // distinguish them is tricky. Not caching just means we might do another lookup
                // sooner than necessary.
                if guard.generation == generation_before_lookup {
                    guard.map.insert(hostname.to_string(), expiring_entry);
                }
            },
        ));

        (ipv4_res_rx, ipv6_res_rx)
    }
}

/// Makes the given request and sends the responses to the given receivers.
async fn do_lookup_task_body<T: DnsTransport>(
    transport: T,
    request: DnsLookupRequest,
    (ipv4_res_tx, ipv6_res_tx): (
        oneshot::Sender<DnsIpv4Result>,
        oneshot::Sender<DnsIpv6Result>,
    ),
    try_cache_result: impl FnOnce(Expiring<LookupResult>),
) {
    let started_at = Instant::now();
    let timeout_at = started_at + DNS_CALL_BACKGROUND_TIMEOUT;

    let mut stream = match transport.send_queries(request.clone()).await {
        Ok(stream) => stream,
        Err(err) => {
            log::error!(
                "While resolving [{}] failed to send queries over [{}]: {}",
                log_safe_domain(&request.hostname),
                T::dns_source(),
                err,
            );
            return;
        }
    };
    let mut stream = std::pin::pin!(stream);

    // We're expecting two responses from the DNS server,
    // but they can arrive in any order.
    let mut ipv4_res_tx_opt = Some(ipv4_res_tx);
    let mut ipv6_res_tx_opt = Some(ipv6_res_tx);

    let mut maybe_ipv4_res = None;
    let mut maybe_ipv6_res = None;

    for _ in 0..2 {
        match tokio::select! {
            _ = tokio::time::sleep_until(timeout_at) => None,
            res = stream.next() => res,
        } {
            Some(Ok(DnsQueryResult::Left(res))) => {
                maybe_ipv4_res = Some(res.clone());
                if let Some(p) = ipv4_res_tx_opt.take() {
                    // it is possible that the receiver is dropped,
                    // so we're not treating this as an error
                    let _ = p.send(res);
                }
                log::info!(
                    "Received result of the IPv4 DNS query for [{}] after {:?}",
                    log_safe_domain(&request.hostname),
                    started_at.elapsed()
                );
            }
            Some(Ok(DnsQueryResult::Right(res))) => {
                maybe_ipv6_res = Some(res.clone());
                if let Some(p) = ipv6_res_tx_opt.take() {
                    // it is possible that the receiver is dropped,
                    // so we're not treating this as an error
                    let _ = p.send(res);
                }
                log::info!(
                    "Received result of the IPv6 DNS query for [{}] after {:?}",
                    log_safe_domain(&request.hostname),
                    started_at.elapsed()
                );
            }
            Some(Err(error)) => {
                log::warn!(
                    "One of DNS queries for [{}] failed with an error after {:?}: {}",
                    log_safe_domain(&request.hostname),
                    started_at.elapsed(),
                    error
                );
            }
            None => {
                log::warn!(
                    "Stopped waiting for DNS queries results for [{}] after {:?}",
                    log_safe_domain(&request.hostname),
                    started_at.elapsed()
                );
                break;
            }
        };
    }

    let Some(expiration) = min(
        maybe_ipv4_res.as_ref().map(|e| e.expiration),
        maybe_ipv6_res.as_ref().map(|e| e.expiration),
    ) else {
        // Nothing to cache
        return;
    };

    // update cache
    let v4 = maybe_ipv4_res.map_or(vec![], |e| e.data);
    let v6 = maybe_ipv6_res.map_or(vec![], |e| e.data);
    let expiring_entry = Expiring {
        data: LookupResult::new(DnsSource::Cache, v4, v6),
        // Clamp cached TTLs.
        expiration: min(expiration, started_at + MAX_CACHE_TTL),
    };

    try_cache_result(expiring_entry)
}

#[cfg(test)]
pub(crate) mod test {
    use std::collections::HashSet;
    use std::iter;
    use std::net::IpAddr;
    use std::pin::pin;
    use std::sync::atomic::{AtomicU32, Ordering};

    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use futures_util::stream::FuturesUnordered;

    use super::*;
    use crate::timeouts::CONNECTION_ROUTE_MAX_COOLDOWN;
    use crate::utils::{sleep_and_catch_up, sleep_until_and_catch_up};

    // Remove this when Rust figures out how to make arbitrary Div impls const.
    const fn div_duration(input: Duration, divisor: u32) -> Duration {
        match input.checked_div(divisor) {
            Some(v) => v,
            None => unreachable!(),
        }
    }

    const NORMAL_TTL: Duration = div_duration(MAX_CACHE_TTL, 4);
    const IP_V4_LIST_1: &[Ipv4Addr] = &[ip_addr!(v4, "2.2.2.2"), ip_addr!(v4, "2.2.2.3")];
    const IP_V4_LIST_2: &[Ipv4Addr] = &[ip_addr!(v4, "2.2.2.4"), ip_addr!(v4, "2.2.2.5")];
    const IP_V6_LIST_1: &[Ipv6Addr] = &[ip_addr!(v6, "::1"), ip_addr!(v6, "::2")];
    const IP_V6_LIST_2: &[Ipv6Addr] = &[ip_addr!(v6, "::3"), ip_addr!(v6, "::4")];

    #[derive(Clone, Debug)]
    struct TestDnsTransportFailingToConnect;

    impl DnsTransport for TestDnsTransportFailingToConnect {
        type ConnectionParameters = Error;

        fn dns_source() -> DnsSource {
            DnsSource::Test
        }

        async fn connect(
            connection_params: Self::ConnectionParameters,
            _ipv6_enabled: bool,
        ) -> dns::Result<Self> {
            Err(connection_params)
        }

        fn send_queries(
            self,
            _request: DnsLookupRequest,
        ) -> impl Future<
            Output = dns::Result<impl Stream<Item = dns::Result<DnsQueryResult>> + Send + 'static>,
        > + Send {
            panic!("not implemented");
            #[allow(unreachable_code)] // needed for the compiler to infer the return type
            std::future::ready(Ok(futures_util::stream::empty()))
        }
    }

    pub(crate) type OneshotDnsQueryResultSender = oneshot::Sender<dns::Result<DnsQueryResult>>;
    pub(crate) type SenderHandlerFn<T> =
        Box<dyn Fn(DnsLookupRequest, u32, T) + Send + Sync + 'static>;

    #[derive(Clone)]
    pub(crate) struct TestDnsTransportWithResponses<const RESPONSES: usize> {
        queries_count: Arc<AtomicU32>,
        sender_handler: Arc<SenderHandlerFn<[OneshotDnsQueryResultSender; RESPONSES]>>,
        network_changed_event: Arc<ObservableEvent>,
    }

    impl<const RESPONSES: usize> Debug for TestDnsTransportWithResponses<RESPONSES> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestDnsTransportWithResponses")
                .field("queries_count", &self.queries_count)
                .field("sender_handler", &"_")
                .field("network_changed_event", &"_")
                .finish()
        }
    }

    impl<const RESPONSES: usize> TestDnsTransportWithResponses<RESPONSES> {
        pub(crate) fn custom_dns_resolver<F>(sender_handler: F) -> CustomDnsResolver<Self>
        where
            F: Fn(DnsLookupRequest, u32, [OneshotDnsQueryResultSender; RESPONSES])
                + Send
                + Sync
                + 'static,
        {
            let network_changed_event = Arc::new(ObservableEvent::default());
            CustomDnsResolver::new(
                Self {
                    sender_handler: Arc::new(Box::new(sender_handler)),
                    queries_count: Default::default(),
                    network_changed_event: network_changed_event.clone(),
                },
                &network_changed_event,
            )
        }

        pub(crate) fn transport_and_custom_dns_resolver<F>(
            sender_handler: F,
        ) -> (Self, CustomDnsResolver<Self>)
        where
            F: Fn(DnsLookupRequest, u32, [OneshotDnsQueryResultSender; RESPONSES])
                + Send
                + Sync
                + 'static,
        {
            let transport = Self {
                sender_handler: Arc::new(Box::new(sender_handler)),
                queries_count: Default::default(),
                network_changed_event: Arc::new(ObservableEvent::default()),
            };
            let resolver =
                CustomDnsResolver::new(transport.clone(), &transport.network_changed_event);
            (transport, resolver)
        }

        pub(crate) fn queries_count(&self) -> u32 {
            self.queries_count.load(Ordering::Relaxed)
        }
    }

    impl<const RESPONSES: usize> DnsTransport for TestDnsTransportWithResponses<RESPONSES> {
        type ConnectionParameters = Self;

        fn dns_source() -> DnsSource {
            DnsSource::Test
        }

        async fn connect(
            connection_params: Self::ConnectionParameters,
            _ipv6_enabled: bool,
        ) -> dns::Result<Self> {
            Ok(connection_params)
        }

        fn send_queries(
            self,
            request: DnsLookupRequest,
        ) -> impl Future<
            Output = dns::Result<impl Stream<Item = dns::Result<DnsQueryResult>> + Send + 'static>,
        > + Send {
            let query_num = self.queries_count.fetch_add(1, Ordering::Relaxed) + 1;
            let (txs, rxs): (Vec<_>, Vec<_>) =
                iter::from_fn(|| Some(oneshot::channel::<dns::Result<DnsQueryResult>>()))
                    .take(RESPONSES)
                    .unzip();
            (self.sender_handler)(
                request,
                query_num,
                txs.try_into().expect("correct vec size"),
            );
            std::future::ready(Ok(FuturesUnordered::from_iter(
                rxs.into_iter().map(unwrap_or_lookup_failed),
            )))
        }
    }

    type TestDnsTransportWithOneResponse = TestDnsTransportWithResponses<1>;
    type TestDnsTransportWithTwoResponses = TestDnsTransportWithResponses<2>;
    type TestDnsTransportWithThreeResponses = TestDnsTransportWithResponses<3>;

    async fn unwrap_or_lookup_failed(
        rx: oneshot::Receiver<dns::Result<DnsQueryResult>>,
    ) -> dns::Result<DnsQueryResult> {
        rx.map(|r| r.unwrap_or(Err(Error::LookupFailed))).await
    }

    fn ok_query_result_ipv4(ttl: Duration, data: &[Ipv4Addr]) -> dns::Result<DnsQueryResult> {
        Ok(DnsQueryResult::Left(Expiring {
            data: data.to_vec(),
            expiration: Instant::now() + ttl,
        }))
    }

    fn ok_query_result_ipv6(ttl: Duration, data: &[Ipv6Addr]) -> dns::Result<DnsQueryResult> {
        Ok(DnsQueryResult::Right(Expiring {
            data: data.to_vec(),
            expiration: Instant::now() + ttl,
        }))
    }

    fn respond_after_timeout(
        timeout: Duration,
        tx: OneshotDnsQueryResultSender,
        response: dns::Result<DnsQueryResult>,
    ) {
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let _ = tx.send(response);
        });
    }

    fn assert_lookup_result_content_equal(
        lookup_result: &LookupResult,
        expected_ipv4s: &[Ipv4Addr],
        expected_ipv6s: &[Ipv6Addr],
    ) {
        let mut expected = HashSet::new();
        expected.extend(expected_ipv4s.iter().map(|ip| IpAddr::V4(*ip)));
        expected.extend(expected_ipv6s.iter().map(|ip| IpAddr::V6(*ip)));
        let mut actual = HashSet::new();
        actual.extend(lookup_result.ipv4.iter().map(|ip| IpAddr::V4(*ip)));
        actual.extend(lookup_result.ipv6.iter().map(|ip| IpAddr::V6(*ip)));
        assert_eq!(expected, actual);
    }

    fn test_request() -> DnsLookupRequest {
        DnsLookupRequest {
            hostname: Arc::from("chat.signal.org"),
            ipv6_enabled: true,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn works_correctly_when_both_results_are_within_resolution_delay() {
        let (transport, resolver) =
            TestDnsTransportWithTwoResponses::transport_and_custom_dns_resolver(|_, q_num, txs| {
                let first = DNS_CALL_BACKGROUND_TIMEOUT / 4;
                let second = first + DNS_RESOLUTION_DELAY / 2;
                let (timeout_1, timeout_2) = if q_num == 1 {
                    (first, second)
                } else {
                    (second, first)
                };
                let [tx_1, tx_2] = txs;
                let res_1 = ok_query_result_ipv4(Duration::ZERO, IP_V4_LIST_1);
                let res_2 = ok_query_result_ipv6(Duration::ZERO, IP_V6_LIST_1);
                respond_after_timeout(timeout_1, tx_1, res_1);
                respond_after_timeout(timeout_2, tx_2, res_2);
            });
        let result_1 = resolver.resolve(test_request()).await;
        let result_2 = resolver.resolve(test_request()).await;
        assert_eq!(2, transport.queries_count());
        assert_lookup_result_content_equal(&result_1.unwrap(), IP_V4_LIST_1, IP_V6_LIST_1);
        assert_lookup_result_content_equal(&result_2.unwrap(), IP_V4_LIST_1, IP_V6_LIST_1);
    }

    #[tokio::test(start_paused = true)]
    async fn works_correctly_when_second_response_is_after_resolution_delay() {
        let resolver = TestDnsTransportWithTwoResponses::custom_dns_resolver(|_, q_num, txs| {
            let first = DNS_CALL_BACKGROUND_TIMEOUT / 4;
            let second = first + DNS_RESOLUTION_DELAY * 2;
            let (timeout_1, timeout_2) = if q_num == 1 {
                (first, second)
            } else {
                (second, first)
            };
            let [tx_1, tx_2] = txs;
            let res_1 = ok_query_result_ipv4(Duration::ZERO, IP_V4_LIST_1);
            let res_2 = ok_query_result_ipv6(Duration::ZERO, IP_V6_LIST_1);
            respond_after_timeout(timeout_1, tx_1, res_1);
            respond_after_timeout(timeout_2, tx_2, res_2);
        });
        let result_1 = resolver.resolve(test_request()).await;
        assert_lookup_result_content_equal(&result_1.unwrap(), IP_V4_LIST_1, &[]);
        let result_2 = resolver.resolve(test_request()).await;
        assert_lookup_result_content_equal(&result_2.unwrap(), &[], IP_V6_LIST_1);
    }

    #[tokio::test(start_paused = true)]
    async fn works_correctly_if_transport_only_returns_one_response() {
        let resolver = TestDnsTransportWithOneResponse::custom_dns_resolver(|_, _, txs| {
            let [tx_1] = txs;
            tx_1.send(ok_query_result_ipv4(NORMAL_TTL, IP_V4_LIST_1))
                .unwrap();
        });
        let result = resolver.resolve(test_request()).await;
        assert_lookup_result_content_equal(&result.unwrap(), IP_V4_LIST_1, &[]);
    }

    #[tokio::test(start_paused = true)]
    async fn works_correctly_if_transport_returns_third_response() {
        let resolver = TestDnsTransportWithThreeResponses::custom_dns_resolver(|_, _, txs| {
            let [tx_1, tx_2, tx_3] = txs;
            let res_1 = ok_query_result_ipv4(Duration::ZERO, IP_V4_LIST_1);
            let res_2 = ok_query_result_ipv6(Duration::ZERO, IP_V6_LIST_1);
            let res_3 = Err(Error::NoData);
            let timeout_1 = DNS_CALL_BACKGROUND_TIMEOUT / 4;
            let timeout_2 = timeout_1 + DNS_RESOLUTION_DELAY / 3;
            let timeout_3 = timeout_1 + DNS_RESOLUTION_DELAY / 2;
            respond_after_timeout(timeout_1, tx_1, res_1);
            respond_after_timeout(timeout_2, tx_2, res_2);
            respond_after_timeout(timeout_3, tx_3, res_3);
        });
        let result = resolver.resolve(test_request()).await;
        assert_lookup_result_content_equal(&result.unwrap(), IP_V4_LIST_1, IP_V6_LIST_1);
    }

    #[tokio::test(start_paused = true)]
    async fn returns_second_result_if_first_result_fails() {
        let resolver = TestDnsTransportWithTwoResponses::custom_dns_resolver(|_, _, txs| {
            let timeout_2 = DNS_RESOLUTION_DELAY * 2;
            let [tx_1, tx_2] = txs;
            let res_1 = Err(Error::LookupFailed);
            let res_2 = ok_query_result_ipv6(Duration::ZERO, IP_V6_LIST_1);
            respond_after_timeout(Duration::ZERO, tx_1, res_1);
            respond_after_timeout(timeout_2, tx_2, res_2);
        });
        let result_1 = resolver.resolve(test_request()).await;
        assert_lookup_result_content_equal(&result_1.unwrap(), &[], IP_V6_LIST_1);
    }

    #[tokio::test(start_paused = true)]
    async fn returns_error_if_both_results_fail() {
        let resolver = TestDnsTransportWithTwoResponses::custom_dns_resolver(|_, _, txs| {
            let [tx_1, tx_2] = txs;
            let res_1 = Err(Error::UnexpectedMessageId);
            let res_2 = Err(Error::RequestedIpTypeNotFound);
            respond_after_timeout(Duration::ZERO, tx_1, res_1);
            respond_after_timeout(Duration::ZERO, tx_2, res_2);
        });
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::LookupFailed));
    }

    #[tokio::test(start_paused = true)]
    async fn cache_results_returned_if_not_expired() {
        let (transport, resolver) =
            TestDnsTransportWithTwoResponses::transport_and_custom_dns_resolver(|_, q_num, txs| {
                let [tx_1, tx_2] = txs;
                let (ipv4s, ipv6s) = if q_num == 1 {
                    (IP_V4_LIST_1, IP_V6_LIST_1)
                } else {
                    (IP_V4_LIST_2, IP_V6_LIST_2)
                };
                tx_1.send(ok_query_result_ipv4(NORMAL_TTL, ipv4s)).unwrap();
                tx_2.send(ok_query_result_ipv6(NORMAL_TTL, ipv6s)).unwrap();
            });

        // first request goes to the name server
        let result_1 = resolver.resolve(test_request()).await;
        tokio::time::sleep(NORMAL_TTL / 2).await;
        // second request should be cached as we only waited for half of the ttl
        let result_2 = resolver.resolve(test_request()).await;
        tokio::time::sleep(NORMAL_TTL).await;
        // third request should go to the name server again and have different results
        let result_3 = resolver.resolve(test_request()).await;

        assert_eq!(2, transport.queries_count());
        assert_lookup_result_content_equal(&result_1.unwrap(), IP_V4_LIST_1, IP_V6_LIST_1);
        assert_lookup_result_content_equal(&result_2.unwrap(), IP_V4_LIST_1, IP_V6_LIST_1);
        assert_lookup_result_content_equal(&result_3.unwrap(), IP_V4_LIST_2, IP_V6_LIST_2);
    }

    #[tokio::test(start_paused = true)]
    async fn cache_ttl_limited() {
        const LONG_TTL: Duration = MAX_CACHE_TTL.saturating_mul(10);

        let (transport, resolver) =
            TestDnsTransportWithTwoResponses::transport_and_custom_dns_resolver(|_, q_num, txs| {
                let [tx_1, tx_2] = txs;
                let (ipv4s, ipv6s) = if q_num == 1 {
                    (IP_V4_LIST_1, IP_V6_LIST_1)
                } else {
                    (IP_V4_LIST_2, IP_V6_LIST_2)
                };
                tx_1.send(ok_query_result_ipv4(LONG_TTL, ipv4s)).unwrap();
                tx_2.send(ok_query_result_ipv6(LONG_TTL, ipv6s)).unwrap();
            });

        // first request goes to the name server
        let result_1 = resolver.resolve(test_request()).await;
        tokio::time::sleep(MAX_CACHE_TTL / 2).await;
        // second request should be cached as we only waited for half of the ttl limit
        let result_2 = resolver.resolve(test_request()).await;
        tokio::time::sleep(MAX_CACHE_TTL).await;
        // third request should go to the name server again and have different results,
        // even though we're still within LONG_TTL.
        let result_3 = resolver.resolve(test_request()).await;

        assert_eq!(2, transport.queries_count());
        assert_lookup_result_content_equal(&result_1.unwrap(), IP_V4_LIST_1, IP_V6_LIST_1);
        assert_lookup_result_content_equal(&result_2.unwrap(), IP_V4_LIST_1, IP_V6_LIST_1);
        assert_lookup_result_content_equal(&result_3.unwrap(), IP_V4_LIST_2, IP_V6_LIST_2);
    }

    #[tokio::test(start_paused = true)]
    async fn results_cached_even_if_received_late() {
        // second result is sent within the `LONG_TIMEOUT`, but after the `RESOLUTION_DELAY`
        let timeout_1 = DNS_CALL_BACKGROUND_TIMEOUT / 4;
        let timeout_2 = DNS_CALL_BACKGROUND_TIMEOUT / 2;
        let all_results_received_time = Instant::now() + timeout_2;
        let (transport, resolver) =
            TestDnsTransportWithTwoResponses::transport_and_custom_dns_resolver(
                move |_, q_num, txs| {
                    let [tx_1, tx_2] = txs;
                    // only the first request to the name server succeeds
                    if q_num > 1 {
                        tx_1.send(Err(Error::LookupFailed)).unwrap();
                        tx_2.send(Err(Error::LookupFailed)).unwrap();
                        return;
                    }
                    let res_1 = ok_query_result_ipv4(NORMAL_TTL, IP_V4_LIST_1);
                    let res_2 = ok_query_result_ipv6(NORMAL_TTL, IP_V6_LIST_1);
                    respond_after_timeout(timeout_1, tx_1, res_1);
                    respond_after_timeout(timeout_2, tx_2, res_2);
                },
            );
        let result_1 = resolver.resolve(test_request()).await;
        sleep_until_and_catch_up(all_results_received_time).await;
        let result_2 = resolver.resolve(test_request()).await;
        assert_eq!(1, transport.queries_count());
        assert_lookup_result_content_equal(&result_1.unwrap(), IP_V4_LIST_1, &[]);
        assert_lookup_result_content_equal(&result_2.unwrap(), IP_V4_LIST_1, IP_V6_LIST_1);
    }

    #[tokio::test(start_paused = true)]
    async fn returns_error_if_failed_to_connect_to_transport() {
        let resolver = CustomDnsResolver::<TestDnsTransportFailingToConnect>::new(
            Error::TransportRestricted,
            &ObservableEvent::default(),
        );
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::TransportRestricted));
    }

    #[tokio::test(start_paused = true)]
    async fn early_exits_for_cooldown() {
        let resolver = CustomDnsResolver::<TestDnsTransportFailingToConnect>::new(
            Error::TransportRestricted,
            &ObservableEvent::default(),
        );
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::TransportRestricted));
        // First retry has no cooldown.
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::TransportRestricted));
        // But the second one does have one.
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::Cooldown));

        tokio::time::advance(CONNECTION_ROUTE_MAX_COOLDOWN).await;
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::TransportRestricted));
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::Cooldown));
    }

    #[tokio::test(start_paused = true)]
    async fn returns_error_if_transport_never_sends_results() {
        let resolver = TestDnsTransportWithTwoResponses::custom_dns_resolver(|_, _, _| {
            // transport never responds
        });
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::LookupFailed));
    }

    #[tokio::test]
    async fn cache_cleared_on_network_event() {
        let (transport, resolver) =
            TestDnsTransportWithTwoResponses::transport_and_custom_dns_resolver(|_, _, txs| {
                let [tx_1, tx_2] = txs;
                tx_1.send(ok_query_result_ipv4(NORMAL_TTL, IP_V4_LIST_1))
                    .unwrap();
                tx_2.send(ok_query_result_ipv6(NORMAL_TTL, IP_V6_LIST_1))
                    .unwrap();
            });

        let result_1 = resolver.resolve(test_request()).await.expect("success");
        let cached_result = resolver
            .cache_get(&test_request().hostname)
            .expect("cached");
        assert_eq!(Vec::from_iter(result_1), Vec::from_iter(cached_result));

        transport.network_changed_event.fire();
        assert_matches!(resolver.cache_get(&test_request().hostname), None);
    }

    #[tokio::test(start_paused = true)]
    async fn outstanding_lookups_before_network_event_do_not_end_up_in_cache() {
        let timeout = DNS_CALL_BACKGROUND_TIMEOUT / 4;
        let (resolution_started_tx, mut resolution_started_rx) = oneshot::channel();
        let resolution_started_tx = std::sync::Mutex::new(Some(resolution_started_tx));
        let (transport, resolver) =
            TestDnsTransportWithTwoResponses::transport_and_custom_dns_resolver(
                move |_, _, txs| {
                    if let Some(resolution_started_tx) =
                        resolution_started_tx.lock().expect("not poisoned").take()
                    {
                        _ = resolution_started_tx.send(());
                    }
                    let [tx_1, tx_2] = txs;
                    let res_1 = ok_query_result_ipv4(NORMAL_TTL, IP_V4_LIST_1);
                    let res_2 = ok_query_result_ipv6(NORMAL_TTL, IP_V6_LIST_1);
                    respond_after_timeout(timeout, tx_1, res_1);
                    respond_after_timeout(timeout, tx_2, res_2);
                },
            );

        let mut lookup = pin!(resolver.resolve(test_request()));
        while let Err(oneshot::error::TryRecvError::Empty) = resolution_started_rx.try_recv() {
            let waiting = futures_util::poll!(&mut lookup);
            assert_matches!(
                waiting,
                std::task::Poll::Pending,
                "should pause at respond_after_timeout"
            );
            tokio::task::yield_now().await;
        }

        transport.network_changed_event.fire();
        sleep_and_catch_up(timeout).await;
        lookup.await.expect("success");
        assert_matches!(resolver.cache_get(&test_request().hostname), None);
    }
}
