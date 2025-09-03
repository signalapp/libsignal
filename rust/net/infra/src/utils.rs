//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::sync::LazyLock;
use std::time::Duration;

use base64::prelude::{BASE64_STANDARD, Engine as _};
use http::HeaderValue;
use tokio::time::Instant;

pub(crate) mod binary_heap;
pub mod future;
pub mod oneshot_broadcast;

/// Constructs the value of the `Authorization` header for the `Basic` auth scheme.
pub fn basic_authorization(username: &str, password: &str) -> HeaderValue {
    let auth = BASE64_STANDARD.encode(format!("{username}:{password}").as_bytes());
    let auth = format!("Basic {auth}");
    HeaderValue::try_from(auth).expect("valid header value")
}

/// Requires a `Future` to complete before the specified duration has elapsed.
///
/// Takes in a future whose return type is `Result<T, E>`, a `duration` timeout,
/// and a `timeout_error` of type `E`. Internally, a [tokio::time::timeout] is called,
/// but the return type of this method is the same as the return type of the given `future`,
/// i.e. `Result<T, E>`, which in the case of timing out will be `Err(timeout_error)`.
pub async fn timeout<T, E, F>(duration: Duration, timeout_error: E, future: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(duration, future).await {
        Ok(r) => r,
        Err(_) => Err(timeout_error),
    }
}

/// In the tokio time paused test mode, if some logic is supposed to wake up at specific time
/// and a test wants to make sure it observes the result of that logic without moving
/// the time past that point, it's not enough to call `sleep()` or `advance()` alone.
/// The combination of sleeping and advancing by 0 makes sure that all events
/// (in all tokio threads) scheduled to run at (or before) that specific time are processed.
///
/// `sleep_and_catch_up_showcase()` test demonstrates this behavior.
#[cfg(test)]
pub(crate) async fn sleep_and_catch_up(duration: Duration) {
    tokio::time::sleep(duration).await;
    tokio::time::advance(Duration::ZERO).await
}

/// See [`sleep_and_catch_up`]
#[cfg(test)]
pub(crate) async fn sleep_until_and_catch_up(time: tokio::time::Instant) {
    tokio::time::sleep_until(time).await;
    tokio::time::advance(Duration::ZERO).await
}

// We allow dead code here just to make sure this method does not bit rot. It is
// compiled as part of the unit tests, but is only called manually by developers.
#[cfg(feature = "dev-util")]
#[allow(dead_code)]
pub(crate) fn development_only_enable_nss_standard_debug_interop(
    ssl: &mut boring_signal::ssl::SslConnectorBuilder,
) -> Result<(), crate::errors::TransportConnectError> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::sync::Mutex;

    use once_cell::sync::OnceCell;

    use crate::errors::TransportConnectError;

    log::warn!(
        "NSS TLS debugging enabled! If you don't expect this, report to security@signal.org"
    );
    if let Ok(keylog_path) = std::env::var("SSLKEYLOGFILE") {
        // This copies the behavior from BoringSSL where the connection will fail if
        //  SSLKEYLOGFILE is set but the file cannot be created. See:
        //  https://boringssl.googlesource.com/boringssl/+/refs/heads/master/tool/client.cc#400
        static FILE_OPEN_MUTEX: OnceCell<Mutex<std::fs::File>> = OnceCell::new();

        let file_mutex = FILE_OPEN_MUTEX
            .get_or_try_init(|| {
                OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(keylog_path)
                    .map(Mutex::new)
            })
            .map_err(|_| TransportConnectError::ClientAbort)?;

        ssl.set_keylog_callback(move |_ssl_ref, keylogfile_formatted_line| {
            let mut file = file_mutex
                .lock()
                .expect("no earlier panic while lock was held");
            let _ = writeln!(file, "{keylogfile_formatted_line}");
            let _ = file.flush();
        });
    }
    Ok(())
}

/// Utility function to track how long a future takes to execute.
pub async fn timed<T>(f: impl Future<Output = T>) -> (Duration, T) {
    let time_at_first_poll = Instant::now();
    let t = f.await;
    let finished_at = Instant::now();
    (finished_at - time_at_first_poll, t)
}

/// The type used by ongoing operations to track network change events.
pub type NetworkChangeEvent = tokio::sync::watch::Receiver<()>;

pub fn no_network_change_events() -> NetworkChangeEvent {
    static SENDER_THAT_NEVER_SENDS: LazyLock<tokio::sync::watch::Sender<()>> =
        LazyLock::new(Default::default);
    SENDER_THAT_NEVER_SENDS.subscribe()
}

#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    /// Usable as a [Waker](std::task::Waker) for async polling.
    #[derive(Debug, Default)]
    pub struct TestWaker {
        wake_count: AtomicUsize,
    }

    impl TestWaker {
        pub fn was_woken(&self) -> bool {
            self.wake_count() != 0
        }
        pub fn wake_count(&self) -> usize {
            self.wake_count.load(std::sync::atomic::Ordering::SeqCst)
        }
        pub fn as_waker(self: &Arc<Self>) -> std::task::Waker {
            std::task::Waker::from(Arc::clone(self))
        }
    }

    impl std::task::Wake for TestWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref()
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.wake_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod test {
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tokio::time;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn sleep_and_catch_up_showcase() {
        const DURATION: Duration = Duration::from_millis(100);

        async fn test<F: Future<Output = ()>>(sleep_variant: F) -> bool {
            let flag = Arc::new(AtomicBool::new(false));
            let flag_clone = flag.clone();
            tokio::spawn(async move {
                time::sleep(DURATION).await;
                flag_clone.store(true, Ordering::Relaxed);
            });
            sleep_variant.await;
            flag.load(Ordering::Relaxed)
        }

        assert!(!test(time::sleep(DURATION)).await);
        assert!(!test(time::advance(DURATION)).await);
        assert!(test(sleep_and_catch_up(DURATION)).await);
    }
}
