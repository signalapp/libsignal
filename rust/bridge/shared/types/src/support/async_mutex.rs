//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// Like [`tokio::sync::Mutex`], but with a minimal implementation of poison-on-panic like
/// [`std::sync::Mutex`] to provide [`std::panic::UnwindSafe`].
///
/// Ensures that caught panics don't allow protected resources to blithely continue on. If you don't
/// need [`tokio::sync::Mutex`]'s behavior of holding the lock over an `await` point, however,
/// prefer [`std::sync::Mutex`] (as suggested by the tokio docs).
///
/// Like both [`tokio::sync::Mutex`] and [`std::sync::Mutex`], the protected resource isn't dropped
/// until the `AsyncMutex` is, even if there's been a panic.
#[derive(Default)]
pub struct AsyncMutex<T> {
    inner: tokio::sync::Mutex<(T, bool)>,
}

/// The guard for a held [`AsyncMutex`].
pub struct AsyncMutexGuard<'a, T> {
    inner: tokio::sync::MutexGuard<'a, (T, bool)>,
}

impl<T> AsyncMutex<T> {
    pub async fn lock(&self) -> AsyncMutexGuard<'_, T> {
        // If the implementation of `lock()` itself panics, we will not be able to record a poison,
        // so this AssertUnwindSafe isn't *quite* safe. However, that's very unlikely! If `lock()`
        // panics, we probably have bigger problems.
        let guard = std::panic::AssertUnwindSafe(self.inner.lock()).await;
        if guard.1 {
            panic!("mutex is poisoned from prior panic");
        }

        AsyncMutexGuard { inner: guard }
    }

    pub fn blocking_lock(&self) -> AsyncMutexGuard<'_, T> {
        let guard = self.inner.blocking_lock();
        if guard.1 {
            panic!("mutex is poisoned from prior panic");
        }

        AsyncMutexGuard { inner: guard }
    }

    pub fn get_mut(&mut self) -> &mut T {
        let (contents, panicked) = self.inner.get_mut();
        if *panicked {
            panic!("mutex is poisoned from prior panic");
        }
        contents
    }

    pub fn into_inner(self) -> T {
        let (contents, panicked) = self.inner.into_inner();
        if panicked {
            panic!("mutex is poisoned from prior panic");
        }
        contents
    }
}

impl<T> From<T> for AsyncMutex<T> {
    fn from(value: T) -> Self {
        Self {
            inner: (value, false).into(),
        }
    }
}

// AsyncMutex should implement Send and Sync whenever the data is Send, just like
// tokio::sync::Mutex.
static_assertions::assert_impl_all!(AsyncMutex<std::cell::Cell<()>>: Send, Sync);

// AsyncMutex provides unwind safety even though tokio::sync::Mutex does not - that's its raison
// d'être.
impl<T> std::panic::UnwindSafe for AsyncMutex<T> {}
impl<T> std::panic::RefUnwindSafe for AsyncMutex<T> {}
impl<T> std::panic::UnwindSafe for AsyncMutexGuard<'_, T> {}
impl<T> std::panic::RefUnwindSafe for AsyncMutexGuard<'_, T> {}

impl<T> std::ops::Deref for AsyncMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner.0
    }
}

impl<T> std::ops::DerefMut for AsyncMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.0
    }
}

impl<T> Drop for AsyncMutexGuard<'_, T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.inner.1 = true;
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use assert_matches::assert_matches;
    use futures_util::FutureExt as _;

    use super::*;

    fn panic_while_holding_mutex(mutex: &AsyncMutex<i32>) {
        _ = std::panic::catch_unwind(|| {
            let _guard = mutex.blocking_lock();
            panic!("while holding mutex");
        })
        .expect_err("should have panicked");
    }

    #[test]
    fn caught_panic_does_not_cause_further_panics_if_unused() {
        let mutex = AsyncMutex::default();
        panic_while_holding_mutex(&mutex);
    }

    #[test]
    #[should_panic(expected = "poisoned from prior panic")]
    fn caught_panic_poisons_blocking_lock() {
        let mutex = AsyncMutex::default();
        assert_eq!(*mutex.blocking_lock(), 0);
        panic_while_holding_mutex(&mutex);
        _ = mutex.blocking_lock();
    }

    #[test]
    #[should_panic(expected = "poisoned from prior panic")]
    fn caught_panic_poisons_async_lock() {
        let mutex = AsyncMutex::default();
        assert_eq!(
            async { *mutex.lock().await }.now_or_never().expect("ready"),
            0
        );
        panic_while_holding_mutex(&mutex);
        _ = async { *mutex.lock().await }.now_or_never().expect("ready");
    }

    #[test]
    #[should_panic(expected = "poisoned from prior panic")]
    fn caught_panic_poisons_get_mut() {
        let mut mutex = AsyncMutex::default();
        assert_eq!(*mutex.get_mut(), 0);
        panic_while_holding_mutex(&mutex);
        _ = mutex.get_mut();
    }

    #[test]
    fn test_into_inner_separate_from_panic() {
        let mutex: AsyncMutex<i32> = AsyncMutex::default();
        assert_eq!(mutex.into_inner(), 0);
    }

    #[test]
    #[should_panic(expected = "poisoned from prior panic")]
    fn caught_panic_poisons_into_inner() {
        let mutex = AsyncMutex::default();
        panic_while_holding_mutex(&mutex);
        _ = mutex.into_inner();
    }

    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "poisoned from prior panic")]
    async fn panic_during_async() {
        let mutex: AsyncMutex<i32> = AsyncMutex::default();

        // Spawn this separately because JoinHandle is UnwindSafe even though the sleep future
        // itself isn't.
        let other_task = tokio::spawn(tokio::time::sleep(Duration::from_secs(1)));

        let mut task = Box::pin(
            async {
                let guard = mutex.lock().await;
                // Check that the guard can be held across an await point.
                _ = other_task.await;
                panic!("while holding mutex: {}", *guard);
            }
            .catch_unwind(),
        );

        // Invoke with as_mut() so that the Future isn't immediately destroyed.
        // This ensures that the mutex guard is Dropped at the point of unwinding instead of waiting
        // for its containing Future to be dropped.
        task.as_mut().await.expect_err("task should have panicked");

        _ = mutex.lock().await;
    }

    #[test]
    fn panic_does_not_immediately_drop() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let mutex = AsyncMutex::from(tx);
        assert_matches!(
            rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );

        _ = std::panic::catch_unwind(|| {
            let _guard = mutex.blocking_lock();
            panic!("while holding mutex");
        })
        .expect_err("should have panicked");
        assert_matches!(
            rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );

        drop(mutex);
        assert_matches!(
            rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        );
    }
}
