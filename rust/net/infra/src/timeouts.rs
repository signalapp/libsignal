use std::time::Duration;

/// Timeout for a system DNS lookup
pub const DNS_SYSTEM_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// A list of timeouts per each fallback DNS lookup attempt
pub const DNS_FALLBACK_LOOKUP_TIMEOUTS: &[Duration] = &[
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(15),
];
/// If during a DNS resolution we've sent multiple queries (one per IP type)
/// and one of them produced a result, we'll wait this time interval
/// to let the other query complete before proceeding
pub const DNS_RESOLUTION_DELAY: Duration = Duration::from_millis(50);
/// How long before the DNS resolver should give up on a query entirely.
///
/// When making a DNS query, a caller is given a result future that it may or may not
/// await on until the result is ready (callers will likely await with a timeout).
/// Regardless of the caller's behavior, DNS resolver will wait this time interval
/// for results to arrive to cache them for the future lookups.
pub const DNS_CALL_BACKGROUND_TIMEOUT: Duration = Duration::from_secs(30);

/// Frequency of the WebSocket `PING` requests
pub const WS_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// Maximum time of incoming packets inactivity allowed on a WebSocket connection
pub const WS_MAX_IDLE_INTERVAL: Duration = Duration::from_secs(45);

/// Timeout for a connect operation that attempts one route
/// (this includes DNS resolution, TCP connection, and SSL handshake)
pub const ONE_ROUTE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for a connect operation that attempts multiple routes
pub const MULTI_ROUTE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(180);

/// When establishing a TCP connection, connections to different IP addresses are
/// raced between each other with each new attempt being given an additional delay
/// before it starts.
pub const TCP_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(200);

/// A sequence of timeout values to be used as cooldown intervals between attempts
/// when a connection to a given route is consecutively failing to establish
pub const CONNECTION_ROUTE_COOLDOWN_INTERVALS: [Duration; 8] = [
    Duration::from_secs(0),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(32),
    CONNECTION_ROUTE_MAX_COOLDOWN,
];

/// Maximum value of a coolduwn interval between connection attempts
pub const CONNECTION_ROUTE_MAX_COOLDOWN: Duration = Duration::from_secs(64);

/// The result of an operation that can time out or produce a value.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, derive_more::From)]
pub enum TimeoutOr<E> {
    #[from(skip)]
    Timeout {
        /// How long the operation was allowed to run for before timing out.
        attempt_duration: Duration,
    },
    Other(E),
}
