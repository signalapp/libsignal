//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use either::Either;
use futures_util::{FutureExt as _, Stream, StreamExt as _};
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::dns::dns_errors::Error;
use crate::dns::dns_lookup::DnsLookupRequest;
use crate::dns::dns_types::Expiring;
use crate::dns::dns_utils::log_safe_domain;
use crate::dns::lookup_result::LookupResult;
use crate::route::{
    ConnectionOutcomeParams, ConnectionOutcomes, ConnectorFactory, InterfaceMonitor, ResolvedRoute,
};
use crate::timeouts::{
    DNS_CALL_BACKGROUND_TIMEOUT, NETWORK_INTERFACE_POLL_INTERVAL,
    POST_ROUTE_CHANGE_CONNECTION_TIMEOUT,
};
use crate::utils::NetworkChangeEvent;
use crate::utils::future::results_within_interval;
use crate::{DnsSource, dns};

pub type DnsIpv4Result = Expiring<Vec<Ipv4Addr>>;
pub type DnsIpv6Result = Expiring<Vec<Ipv6Addr>>;
pub type DnsQueryResult = Either<DnsIpv4Result, DnsIpv6Result>;

/// Artificially limit DNS lookup results, so we don't get stuck on stale info with a bad TTL field.
const MAX_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Implementors of this trait encapsulate the logic of sending queries to the DNS server
/// and receiving resposnes.
pub trait DnsTransport: Debug + Sized + Send {
    /// Identifies the DNS source
    const SOURCE: DnsSource;

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

const DNS_CONNECTION_COOLDOWN_CONFIG: ConnectionOutcomeParams = ConnectionOutcomeParams {
    short_term_age_cutoff: Duration::from_secs(5 * 60),
    long_term_age_cutoff: Duration::from_secs(5 * 60),
    cooldown_growth_factor: 10.0,
    max_count: 5,
    max_delay: Duration::from_secs(30),
    count_growth_factor: 10.0,
};

/// A resolver that combines the logic of retrieving results of the DNS queries
/// over a specific transport and caching those results according to the
/// records expiration times.
#[derive(Clone)]
pub struct CustomDnsResolver<R, T> {
    connector_factory: T,
    routes: Vec<R>,
    network_change_event: NetworkChangeEvent,
    attempts_record: Arc<tokio::sync::RwLock<ConnectionOutcomes<R>>>,
    cache: Arc<std::sync::Mutex<SharedCacheWithGenerations<String, Expiring<LookupResult>>>>,
    /// How long to wait for a second response after the first one is received.
    second_response_grace_period: Duration,
}

impl<R, T> CustomDnsResolver<R, T>
where
    T: ConnectorFactory<R, Connector: Sync, Connection: DnsTransport + 'static>,
    R: ResolvedRoute + Clone + Hash + Eq + Send + Sync,
{
    pub fn new(
        routes: Vec<R>,
        connector_factory: T,
        network_change_event: &NetworkChangeEvent,
        second_response_grace_period: Duration,
    ) -> Self {
        let cache = Arc::new(std::sync::Mutex::new(SharedCacheWithGenerations::default()));
        let attempts_record = Arc::new(tokio::sync::RwLock::new(ConnectionOutcomes::new(
            DNS_CONNECTION_COOLDOWN_CONFIG,
        )));

        Self {
            connector_factory,
            routes,
            network_change_event: network_change_event.clone(),
            attempts_record,
            cache,
            second_response_grace_period,
        }
    }

    pub(crate) fn on_network_change(&self, now: Instant) {
        self.cache.lock().expect("not poisoned").clear_and_advance();
        self.attempts_record.blocking_write().reset(now);
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
        let connector = InterfaceMonitor::new(
            self.connector_factory.make(),
            self.network_change_event.clone(),
            NETWORK_INTERFACE_POLL_INTERVAL,
            POST_ROUTE_CHANGE_CONNECTION_TIMEOUT,
        );
        let routes = self
            .routes
            .iter()
            .filter(|route| request.ipv6_enabled || route.immediate_target().is_ipv4())
            .cloned()
            .collect();

        let mut attempts_record_snapshot = self.attempts_record.read().await.clone();
        let (result, updates) = crate::route::connect_resolved(
            routes,
            &mut attempts_record_snapshot,
            connector,
            (),
            "dns",
            |_e| std::ops::ControlFlow::Continue::<std::convert::Infallible>(()),
        )
        .await;
        self.attempts_record.write().await.apply_outcome_updates(
            updates.outcomes,
            updates.finished_at,
            SystemTime::now(),
        );
        let transport = result.map_err(|e| match e {
            crate::route::ConnectError::NoResolvedRoutes => dns::DnsError::TransportRestricted,
            crate::route::ConnectError::AllAttemptsFailed
            | crate::route::ConnectError::FatalConnect(_) => dns::DnsError::TransportFailure,
        })?;

        let (ipv4_res_rx, ipv6_res_rx) = self.send_dns_queries(transport, request);
        let (maybe_ipv4, maybe_ipv6) = results_within_interval(
            ipv4_res_rx.map(Result::ok),
            ipv6_res_rx.map(Result::ok),
            self.second_response_grace_period,
        )
        .await;
        let ipv4s = maybe_ipv4.map_or(vec![], |r| r.data);
        let ipv6s = maybe_ipv6.map_or(vec![], |r| r.data);
        match LookupResult::new(ipv4s, ipv6s) {
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
        transport: T::Connection,
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

impl<R: Debug, T> std::fmt::Debug for CustomDnsResolver<R, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(std::any::type_name::<Self>())
            .field("routes", &self.routes)
            .finish_non_exhaustive()
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

    let stream = match transport.send_queries(request.clone()).await {
        Ok(stream) => stream,
        Err(err) => {
            log::warn!(
                "While resolving [{}] failed to send queries over [{}]: {}",
                log_safe_domain(&request.hostname),
                T::SOURCE,
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
        data: LookupResult::new(v4, v6),
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
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use futures_util::stream::FuturesUnordered;
    use test_case::test_case;

    use super::*;
    use crate::route::Connector;
    use crate::route::testutils::ConnectFn;
    use crate::timeouts::DNS_LATER_RESPONSE_GRACE_PERIOD;
    use crate::utils::{no_network_change_events, sleep_and_catch_up, sleep_until_and_catch_up};

    // Remove this when Rust figures out how to make arbitrary Div impls const.
    const fn div_duration(input: Duration, divisor: u32) -> Duration {
        match input.checked_div(divisor) {
            Some(v) => v,
            None => unreachable!(),
        }
    }

    const NORMAL_TTL: Duration = div_duration(MAX_CACHE_TTL, 4);
    const DNS_SERVER_IP: IpAddr = ip_addr!("192.0.2.1");
    const IP_V4_LIST_1: &[Ipv4Addr] = &[ip_addr!(v4, "192.0.2.22"), ip_addr!(v4, "192.0.2.33")];
    const IP_V4_LIST_2: &[Ipv4Addr] = &[ip_addr!(v4, "192.0.2.44"), ip_addr!(v4, "192.0.2.55")];
    const IP_V6_LIST_1: &[Ipv6Addr] = &[ip_addr!(v6, "3fff::1"), ip_addr!(v6, "3fff::2")];
    const IP_V6_LIST_2: &[Ipv6Addr] = &[ip_addr!(v6, "3fff::3"), ip_addr!(v6, "3fff::4")];

    #[derive(Clone)]
    pub(crate) struct MakeConnectorByCloning<T>(T);

    impl<R, T> ConnectorFactory<R> for MakeConnectorByCloning<T>
    where
        T: Connector<R, ()> + Clone,
    {
        type Connector = T;
        type Connection = T::Connection;

        fn make(&self) -> Self::Connector {
            self.0.clone()
        }
    }

    #[derive(Clone, Debug)]
    struct TestDnsTransportFailingToConnect(Error);

    impl Connector<IpAddr, ()> for TestDnsTransportFailingToConnect {
        type Connection = Self;
        type Error = Error;

        fn connect_over(
            &self,
            _over: (),
            _route: IpAddr,
            _log_tag: &str,
        ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
            std::future::ready(Err(self.0.clone()))
        }
    }

    impl DnsTransport for TestDnsTransportFailingToConnect {
        const SOURCE: DnsSource = DnsSource::Test;

        fn send_queries(
            self,
            _request: DnsLookupRequest,
        ) -> impl Future<
            Output = dns::Result<impl Stream<Item = dns::Result<DnsQueryResult>> + Send + 'static>,
        > + Send {
            panic!("not implemented");
            #[expect(
                unreachable_code,
                reason = "needed for the compiler to infer the return type"
            )]
            std::future::ready(Ok(futures_util::stream::empty()))
        }
    }

    pub(crate) type OneshotDnsQueryResultSender = oneshot::Sender<dns::Result<DnsQueryResult>>;
    pub(crate) type SenderHandlerFn<T> = dyn Fn(DnsLookupRequest, u32, T) + Send + Sync + 'static;

    #[derive(Clone)]
    pub(crate) struct TestDnsTransportWithResponses<const RESPONSES: usize> {
        queries_count: Arc<AtomicU32>,
        sender_handler: Arc<SenderHandlerFn<[OneshotDnsQueryResultSender; RESPONSES]>>,
    }

    impl<const RESPONSES: usize> Debug for TestDnsTransportWithResponses<RESPONSES> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestDnsTransportWithResponses")
                .field("queries_count", &self.queries_count)
                .field("sender_handler", &"_")
                .finish()
        }
    }

    impl<const RESPONSES: usize> Connector<IpAddr, ()> for TestDnsTransportWithResponses<RESPONSES> {
        type Connection = Self;
        type Error = std::convert::Infallible;

        fn connect_over(
            &self,
            _over: (),
            _route: IpAddr,
            _log_tag: &str,
        ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
            std::future::ready(Ok(self.clone()))
        }
    }

    impl<const RESPONSES: usize> TestDnsTransportWithResponses<RESPONSES> {
        pub(crate) fn custom_dns_resolver<F>(
            sender_handler: F,
        ) -> CustomDnsResolver<IpAddr, MakeConnectorByCloning<Self>>
        where
            F: Fn(DnsLookupRequest, u32, [OneshotDnsQueryResultSender; RESPONSES])
                + Send
                + Sync
                + 'static,
        {
            CustomDnsResolver::new(
                vec![DNS_SERVER_IP],
                MakeConnectorByCloning(Self {
                    sender_handler: Arc::new(Box::new(sender_handler)),
                    queries_count: Default::default(),
                }),
                &no_network_change_events(),
                DNS_LATER_RESPONSE_GRACE_PERIOD,
            )
        }

        pub(crate) fn transport_and_custom_dns_resolver<F>(
            sender_handler: F,
        ) -> (
            Self,
            CustomDnsResolver<IpAddr, MakeConnectorByCloning<Self>>,
        )
        where
            F: Fn(DnsLookupRequest, u32, [OneshotDnsQueryResultSender; RESPONSES])
                + Send
                + Sync
                + 'static,
        {
            let transport = Self {
                sender_handler: Arc::new(Box::new(sender_handler)),
                queries_count: Default::default(),
            };
            let resolver = CustomDnsResolver::new(
                vec![DNS_SERVER_IP],
                MakeConnectorByCloning(transport.clone()),
                &no_network_change_events(),
                DNS_LATER_RESPONSE_GRACE_PERIOD,
            );
            (transport, resolver)
        }

        pub(crate) fn queries_count(&self) -> u32 {
            self.queries_count.load(Ordering::Relaxed)
        }
    }

    impl<const RESPONSES: usize> DnsTransport for TestDnsTransportWithResponses<RESPONSES> {
        const SOURCE: DnsSource = DnsSource::Test;

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
                let second = first + DNS_LATER_RESPONSE_GRACE_PERIOD / 2;
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
            let second = first + DNS_LATER_RESPONSE_GRACE_PERIOD * 2;
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
            let timeout_2 = timeout_1 + DNS_LATER_RESPONSE_GRACE_PERIOD / 3;
            let timeout_3 = timeout_1 + DNS_LATER_RESPONSE_GRACE_PERIOD / 2;
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
            let timeout_2 = DNS_LATER_RESPONSE_GRACE_PERIOD * 2;
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
        let resolver = CustomDnsResolver::new(
            vec![DNS_SERVER_IP],
            MakeConnectorByCloning(TestDnsTransportFailingToConnect(Error::Io(
                std::io::ErrorKind::BrokenPipe,
            ))),
            &no_network_change_events(),
            DNS_LATER_RESPONSE_GRACE_PERIOD,
        );
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::TransportFailure));
    }

    #[tokio::test(start_paused = true)]
    async fn returns_error_if_transport_never_sends_results() {
        let resolver = TestDnsTransportWithTwoResponses::custom_dns_resolver(|_, _, _| {
            // transport never responds
        });
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::LookupFailed));
    }

    #[test_case(false)]
    #[test_case(true)]
    #[tokio::test(start_paused = true)]
    async fn respects_ipv6_filter_for_dns_server_itself(ipv6_enabled: bool) {
        let ips = [ip_addr!("3fff::100"), DNS_SERVER_IP];
        let routes_tried = Arc::new(Mutex::new(HashSet::new()));
        let resolver = CustomDnsResolver::new(
            ips.to_vec(),
            ConnectFn(|_over, route: IpAddr| {
                routes_tried.lock().expect("not poisoned").insert(route);
                std::future::ready(Err::<TestDnsTransportFailingToConnect, _>(Error::Io(
                    std::io::ErrorKind::BrokenPipe,
                )))
            }),
            &no_network_change_events(),
            DNS_LATER_RESPONSE_GRACE_PERIOD,
        );
        let result = resolver
            .resolve(DnsLookupRequest {
                ipv6_enabled,
                ..test_request()
            })
            .await;
        assert_matches!(result, Err(Error::TransportFailure));
        assert_eq!(
            *routes_tried.lock().expect("not poisoned"),
            HashSet::from_iter(if ipv6_enabled {
                ips.iter().copied()
            } else {
                [DNS_SERVER_IP].iter().copied()
            })
        );
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn outcomes_recorded() {
        let attempts_by_ip = Arc::new(Mutex::new(HashMap::<IpAddr, u32>::new()));
        let ips = [ip_addr!("3fff::100"), DNS_SERVER_IP];
        let resolver = CustomDnsResolver::new(
            ips.to_vec(),
            ConnectFn(|_over, route: IpAddr| {
                *attempts_by_ip
                    .lock()
                    .expect("no panic")
                    .entry(route)
                    .or_default() += 1;
                let result = if route.is_ipv4() {
                    Ok(TestDnsTransportWithTwoResponses {
                        queries_count: Default::default(),
                        sender_handler: Arc::new(|_, _, txs| {
                            let [tx_1, tx_2] = txs;
                            tx_1.send(ok_query_result_ipv4(NORMAL_TTL, IP_V4_LIST_1))
                                .unwrap();
                            tx_2.send(ok_query_result_ipv6(NORMAL_TTL, IP_V6_LIST_1))
                                .unwrap();
                        }),
                    })
                } else {
                    Err(Error::Io(std::io::ErrorKind::BrokenPipe))
                };
                std::future::ready(result)
            }),
            &no_network_change_events(),
            DNS_LATER_RESPONSE_GRACE_PERIOD,
        );
        let result = resolver.resolve(test_request()).await;
        assert_lookup_result_content_equal(&result.unwrap(), IP_V4_LIST_1, IP_V6_LIST_1);
        // We should have tried both routes, with the good one being second.
        assert_eq!(
            *attempts_by_ip.lock().expect("not poisoned"),
            HashMap::from_iter([(ips[0], 1), (ips[1], 1)])
        );

        // Try a second time (with a different hostname, so we don't hit the cache!)
        let result = resolver
            .resolve(DnsLookupRequest {
                hostname: "chat.staging.signal.org".into(),
                ..test_request()
            })
            .await;
        assert_lookup_result_content_equal(&result.unwrap(), IP_V4_LIST_1, IP_V6_LIST_1);
        // Even though the bad transport route was listed first, we should have tried the good
        // transport route first on our second attempt.
        assert_eq!(
            *attempts_by_ip.lock().expect("not poisoned"),
            HashMap::from_iter([(ips[0], 1), (ips[1], 2)])
        );
    }

    #[tokio::test]
    async fn cache_cleared_on_network_event() {
        let resolver = TestDnsTransportWithTwoResponses::custom_dns_resolver(|_, _, txs| {
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

        tokio::task::spawn_blocking({
            let resolver = resolver.clone();
            move || resolver.on_network_change(Instant::now())
        })
        .await
        .expect("no panics");
        assert_matches!(resolver.cache_get(&test_request().hostname), None);
    }

    #[tokio::test(start_paused = true)]
    async fn outstanding_lookups_before_network_event_do_not_end_up_in_cache() {
        let timeout = DNS_CALL_BACKGROUND_TIMEOUT / 4;
        let (resolution_started_tx, mut resolution_started_rx) = oneshot::channel();
        let resolution_started_tx = std::sync::Mutex::new(Some(resolution_started_tx));
        let resolver = TestDnsTransportWithTwoResponses::custom_dns_resolver(move |_, _, txs| {
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
        });

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

        tokio::task::spawn_blocking({
            let resolver = resolver.clone();
            move || resolver.on_network_change(Instant::now())
        })
        .await
        .expect("no panics");

        sleep_and_catch_up(timeout).await;
        lookup.await.expect("success");
        assert_matches!(resolver.cache_get(&test_request().hostname), None);
    }
}
