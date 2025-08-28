use std::time::Duration;

/// Timeout for a system DNS lookup.
///
/// The current DNS strategy is system lookup -> DOH fallback -> static fallback.
/// Each lookup starts after the previous one has timed out.
///
/// This timeout is set low because system DNS is often cached, and when not cached,
/// it will generally be fetched from a nearby recursive resolver in 1 RTT.
///
/// iOS and Android give us a maximum of thirty seconds to fetch notifications in the background,
/// so [`DNS_SYSTEM_LOOKUP_TIMEOUT`] + [`DOH_FALLBACK_LOOKUP_TIMEOUT`] must be much less than
/// thirty seconds to leave time for the static fallback in the worst case.
pub const DNS_SYSTEM_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for a remote DNS-over-HTTPS lookup.
///
/// This timeout needs to be longer than system DNS because it will take at least 3 RTTs
/// to the nearest Cloudflare point-of-presence.
pub const DOH_FALLBACK_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
/// If during a DNS resolution we've sent multiple queries (one per IP type)
/// and one of them produced a result, we'll wait this time interval
/// to let the other query complete before proceeding
pub const DNS_LATER_RESPONSE_GRACE_PERIOD: Duration = Duration::from_millis(100);
/// How long before the DNS resolver should give up on a query entirely.
///
/// When making a DNS query, a caller is given a result future that it may or may not
/// await on until the result is ready (callers will likely await with a timeout).
/// Regardless of the caller's behavior, DNS resolver will wait this time interval
/// for results to arrive to cache them for the future lookups.
pub const DNS_CALL_BACKGROUND_TIMEOUT: Duration = Duration::from_secs(30);

/// Frequency of the WebSocket `PING` requests
/// Set to be slightly longer than the client keep-alive interval to minimize duplicate
///   network usage.
/// See: Signal-Android's KEEPALIVE_FREQUENCY_SECONDS OkHttpWebSocketConnection.java:58, and
///      Signal-Desktop's KEEPALIVE_INTERVAL_MS at WebSocketResources.ts:1085,
///    which are both thirty seconds.
pub const WS_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(31);
/// Maximum time of incoming packets inactivity allowed on a WebSocket connection
pub const WS_MAX_IDLE_INTERVAL: Duration = Duration::from_secs(45);

/// Timeout for a connect operation that attempts one route
/// (this includes DNS resolution, TCP connection, and SSL handshake)
pub const ONE_ROUTE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// How often to check if the network interface has changed (without an OS-provided network change
/// event).
pub const NETWORK_INTERFACE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Duration to wait after a network change event that has resulted in a different preferred network
/// interface.
pub const POST_ROUTE_CHANGE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);

/// Timeout for a connect operation that attempts multiple routes
pub const MULTI_ROUTE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(180);

/// When establishing a TCP connection, connections to different IP addresses are
/// raced between each other with each new attempt being given an additional delay
/// before it starts.
pub const TCP_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(200);

/// Timeout for a TCP connection attempt to a single IP address.
pub const TCP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

/// Minimum timeout duration for TLS handshake. May be greater depending on length of
/// the TCP handshake.
pub const MIN_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

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
