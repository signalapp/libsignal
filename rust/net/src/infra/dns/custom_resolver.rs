//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::min;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use either::Either;
use futures_util::stream::BoxStream;
use futures_util::StreamExt;
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::infra::dns::dns_errors::Error;
use crate::infra::dns::dns_lookup::DnsLookupRequest;
use crate::infra::dns::dns_types::Expiring;
use crate::infra::dns::dns_utils::{log_safe_domain, results_within_interval};
use crate::infra::dns::lookup_result::LookupResult;
use crate::infra::{dns, DnsSource};

pub type DnsIpv4Result = Expiring<Vec<Ipv4Addr>>;
pub type DnsIpv6Result = Expiring<Vec<Ipv6Addr>>;
pub type DnsQueryResult = Either<DnsIpv4Result, DnsIpv6Result>;

const RESOLUTION_DELAY: Duration = Duration::from_millis(50);
const LONG_TIMEOUT: Duration = Duration::from_secs(30);

/// Implementors of this trait encapsulate the logic of sending queries to the DNS server
/// and receiving resposnes.
#[async_trait]
pub trait DnsTransport: Sized + Send {
    /// Type of the connection parameters data structure for this DNS transport
    type ConnectionParameters: Clone + Send + 'static;

    /// Returns the name of the DNS source
    fn dns_source() -> DnsSource;

    /// Establishes a connection to the DNS server over a specific transport.
    ///
    /// Connection will be held open for as long as the returned instance is in use.
    /// Dropping the instance will close the connection and free the resources.
    async fn connect(
        connection_params: Self::ConnectionParameters,
        ipv6_enabled: bool,
    ) -> dns::Result<Self>;

    /// Sends DNS queries and returns an async stream of the results
    /// that the caller can handle according to the resolution logic.
    ///
    /// The returned stream of results is not guaranteed to produce exactly two elements.
    /// Depending on the context and restrictions, implementations may choose to return
    /// streams with fewer elements.
    ///
    /// Each result is a list of either IPv4 or IPv6 records
    /// with the order of results not specified.
    async fn send_queries(
        self,
        request: DnsLookupRequest,
    ) -> dns::Result<BoxStream<'static, dns::Result<DnsQueryResult>>>;
}

/// A resolver that combines the logic of retrieving results of the DNS queries
/// over a specific transport and caching those results according to the
/// records expiration times.
#[derive(Clone)]
pub struct CustomDnsResolver<T: DnsTransport> {
    transport_connection_params: T::ConnectionParameters,
    cache: Arc<std::sync::Mutex<HashMap<String, Expiring<LookupResult>>>>,
}

impl<T: DnsTransport + Sync + 'static> CustomDnsResolver<T> {
    pub fn new(transport_connection_params: T::ConnectionParameters) -> Self {
        Self {
            transport_connection_params,
            cache: Default::default(),
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
        match guard.get(hostname) {
            Some(expiring) if expiring.expiration < Instant::now() => {
                guard.remove(hostname);
                None
            }
            Some(expiring) => Some(expiring.data.clone()),
            None => None,
        }
    }

    async fn lookup(&self, request: DnsLookupRequest) -> dns::Result<LookupResult> {
        let transport = T::connect(
            self.transport_connection_params.clone(),
            request.ipv6_enabled,
        )
        .await?;
        let (ipv4_res_rx, ipv6_res_rx) = self.send_dns_queries(transport, request);
        let (maybe_ipv4, maybe_ipv6) =
            results_within_interval(ipv4_res_rx, ipv6_res_rx, RESOLUTION_DELAY).await;
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
        // We're starting this operation on a separate thread because we want to let it run
        // beyond an individual attempt timeout so that even if a result arrived late
        // we could still cache it for the next time.
        //
        // Reference: https://datatracker.ietf.org/doc/html/rfc8305#section-3
        tokio::spawn(async move {
            let started_at = Instant::now();
            let timeout_at = started_at + LONG_TIMEOUT;

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

            // update cache
            if let Some(expiring_entry) = match (maybe_ipv4_res, maybe_ipv6_res) {
                (Some(ipv4_res), Some(ipv6_res)) => Some(Expiring {
                    data: LookupResult::new(DnsSource::Cache, ipv4_res.data, ipv6_res.data),
                    expiration: min(ipv4_res.expiration, ipv6_res.expiration),
                }),
                (Some(ipv4_res), None) => Some(Expiring {
                    data: LookupResult::new(DnsSource::Cache, ipv4_res.data, vec![]),
                    expiration: ipv4_res.expiration,
                }),
                (None, Some(ipv6_res)) => Some(Expiring {
                    data: LookupResult::new(DnsSource::Cache, vec![], ipv6_res.data),
                    expiration: ipv6_res.expiration,
                }),
                (None, None) => None,
            } {
                let mut guard = cache.lock().expect("not poisoned");
                guard.insert(request.hostname.to_string(), expiring_entry);
            };
        });

        (ipv4_res_rx, ipv6_res_rx)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::infra::dns::custom_resolver::{
        CustomDnsResolver, DnsQueryResult, DnsTransport, LONG_TIMEOUT, RESOLUTION_DELAY,
    };
    use crate::infra::dns::dns_errors::Error;
    use crate::infra::dns::dns_lookup::DnsLookupRequest;
    use crate::infra::dns::dns_types::Expiring;
    use crate::infra::dns::lookup_result::LookupResult;
    use crate::infra::{dns, DnsSource};
    use crate::utils::sleep_until_and_catch_up;
    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use const_str::ip_addr;
    use futures_util::stream::{BoxStream, FuturesUnordered};
    use futures_util::FutureExt;
    use std::collections::HashSet;
    use std::iter;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::time::Instant;

    const NORMAL_TTL: Duration = Duration::from_secs(300);
    const IP_V4_LIST_1: &[Ipv4Addr] = &[ip_addr!(v4, "2.2.2.2"), ip_addr!(v4, "2.2.2.3")];
    const IP_V4_LIST_2: &[Ipv4Addr] = &[ip_addr!(v4, "2.2.2.4"), ip_addr!(v4, "2.2.2.5")];
    const IP_V6_LIST_1: &[Ipv6Addr] = &[ip_addr!(v6, "::1"), ip_addr!(v6, "::2")];
    const IP_V6_LIST_2: &[Ipv6Addr] = &[ip_addr!(v6, "::3"), ip_addr!(v6, "::4")];

    #[derive(Clone)]
    struct TestDnsTransportFailingToConnect;

    #[async_trait]
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

        async fn send_queries(
            self,
            _request: DnsLookupRequest,
        ) -> dns::Result<BoxStream<'static, dns::Result<DnsQueryResult>>> {
            panic!("not implemented")
        }
    }

    pub(crate) type OneshotDnsQueryResultSender = oneshot::Sender<dns::Result<DnsQueryResult>>;
    pub(crate) type SenderHandlerFn<T> =
        Box<dyn Fn(DnsLookupRequest, u32, T) + Send + Sync + 'static>;

    #[derive(Clone)]
    pub(crate) struct TestDnsTransportWithResponses<const RESPONSES: usize> {
        queries_count: Arc<AtomicU32>,
        sender_handler: Arc<SenderHandlerFn<[OneshotDnsQueryResultSender; RESPONSES]>>,
    }

    impl<const RESPONSES: usize> TestDnsTransportWithResponses<RESPONSES> {
        pub(crate) fn custom_dns_resolver<F>(sender_handler: F) -> CustomDnsResolver<Self>
        where
            F: Fn(DnsLookupRequest, u32, [OneshotDnsQueryResultSender; RESPONSES])
                + Send
                + Sync
                + 'static,
        {
            CustomDnsResolver::new(Self {
                sender_handler: Arc::new(Box::new(sender_handler)),
                queries_count: Default::default(),
            })
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
            };
            (transport.clone(), CustomDnsResolver::new(transport))
        }

        pub(crate) fn queries_count(&self) -> u32 {
            self.queries_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
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

        async fn send_queries(
            self,
            request: DnsLookupRequest,
        ) -> dns::Result<BoxStream<'static, dns::Result<DnsQueryResult>>> {
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
            Ok(Box::pin(FuturesUnordered::from_iter(
                rxs.into_iter().map(unwrap_or_lookup_failed),
            )))
        }
    }

    pub(crate) type TestDnsTransportWithOneResponse = TestDnsTransportWithResponses<1>;
    type TestDnsTransportWithTwoResponses = TestDnsTransportWithResponses<2>;
    type TestDnsTransportWithThreeResponses = TestDnsTransportWithResponses<3>;

    async fn unwrap_or_lookup_failed(
        rx: oneshot::Receiver<dns::Result<DnsQueryResult>>,
    ) -> dns::Result<DnsQueryResult> {
        rx.map(|r| r.unwrap_or(Err(Error::LookupFailed))).await
    }

    pub(crate) fn ok_query_result_ipv4(
        ttl: Duration,
        data: &[Ipv4Addr],
    ) -> dns::Result<DnsQueryResult> {
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

    pub(crate) fn respond_after_timeout(
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
                let first = LONG_TIMEOUT / 4;
                let second = first + RESOLUTION_DELAY / 2;
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
            let first = LONG_TIMEOUT / 4;
            let second = first + RESOLUTION_DELAY * 2;
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
            let timeout_1 = LONG_TIMEOUT / 4;
            let timeout_2 = timeout_1 + RESOLUTION_DELAY / 3;
            let timeout_3 = timeout_1 + RESOLUTION_DELAY / 2;
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
            let timeout_2 = RESOLUTION_DELAY * 2;
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
    async fn results_cached_even_if_received_late() {
        // second result is sent within the `LONG_TIMEOUT`, but after the `RESOLUTION_DELAY`
        let timeout_1 = LONG_TIMEOUT / 4;
        let timeout_2 = LONG_TIMEOUT / 2;
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
        let resolver =
            CustomDnsResolver::<TestDnsTransportFailingToConnect>::new(Error::TransportRestricted);
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::TransportRestricted));
    }

    #[tokio::test(start_paused = true)]
    async fn returns_error_if_transport_never_sends_results() {
        let resolver = TestDnsTransportWithTwoResponses::custom_dns_resolver(|_, _, _| {
            // transport never responds
        });
        let result = resolver.resolve(test_request()).await;
        assert_matches!(result, Err(Error::LookupFailed));
    }
}
