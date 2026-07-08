//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::ControlFlow;
use std::pin::Pin;
use std::time::Duration;

use futures_util::FutureExt as _;
use pin_project::pin_project;

/// A wrapper around a [`TryStream`](futures_util::TryStream) that handles fetching several entries
/// at once.
///
/// See [`Self::next_chunk`] for details.
#[derive(Debug)]
#[pin_project]
pub struct BulkPolledStream<T: futures_util::TryStream> {
    #[pin]
    state: BulkPolledStreamState<T>,
    pending: Vec<T::Ok>,
    max_chunk_size: usize,
    debounce_time: Duration,
}

#[derive(Debug)]
#[pin_project(project = BulkPolledStreamStateProj)]
enum BulkPolledStreamState<T> {
    Active(#[pin] T),
    Terminated,
}

/// Reasons why a [`TryStream`](futures_util::TryStream) will no longer be polled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BulkPolledStreamTerminationReason<E> {
    Finished,
    Error(E),
}

impl<E> BulkPolledStreamTerminationReason<E> {
    pub fn into_option(self) -> Option<E> {
        match self {
            BulkPolledStreamTerminationReason::Finished => None,
            BulkPolledStreamTerminationReason::Error(e) => Some(e),
        }
    }
}

/// The result from [`BulkPolledStream::next_chunk`] and [`BulkPolledStream::next_chunk_unpin`].
#[derive(Debug)]
pub struct BulkPolledStreamChunk<T, E> {
    pub chunk: Vec<T>,
    pub termination: Option<BulkPolledStreamTerminationReason<E>>,
}

impl<T: futures_util::TryStream> BulkPolledStream<T> {
    pub fn new(stream: T, max_chunk_size: usize, debounce_time: Duration) -> Self {
        // We don't reserve capacity on the chunk because we don't preserve capacity anyway.
        assert!(
            max_chunk_size > 0,
            "cannot bulk-poll with zero-sized chunks"
        );
        Self {
            state: BulkPolledStreamState::Active(stream),
            pending: vec![],
            max_chunk_size,
            // Limit to 1 hour max so that we don't have to deal with overflow edge cases around
            // Duration::MAX.
            debounce_time: debounce_time.clamp(Duration::ZERO, Duration::from_secs(60 * 60)),
        }
    }

    /// A convenience wrapper around [`Self::next_chunk`] for when `T` doesn't require pinning (or
    /// is already pinned).
    pub fn next_chunk_unpin(
        &mut self,
    ) -> impl Future<Output = BulkPolledStreamChunk<T::Ok, T::Error>>
    where
        Self: Unpin,
    {
        Pin::new(self).next_chunk()
    }

    fn terminate_with_reason(
        self: Pin<&mut Self>,
        reason: BulkPolledStreamTerminationReason<T::Error>,
    ) -> BulkPolledStreamChunk<T::Ok, T::Error> {
        let mut self_ = self.project();
        self_.state.set(BulkPolledStreamState::Terminated);
        debug_assert!(self_.pending.len() < *self_.max_chunk_size);
        BulkPolledStreamChunk {
            chunk: std::mem::take(self_.pending),
            termination: Some(reason),
        }
    }

    /// Awaits the next chunk of items from the stream.
    ///
    /// Waits an unlimited amount of time to fetch one item from the stream, or receive confirmation
    /// that the stream has ended. Then, collects subsequent items during the next debounce
    /// interval. Returns what's been collected when
    ///
    /// - `max_chunk_size` has been reached (as set at construction time)
    /// - `debounce_time` has been used up (as set at construction time)
    /// - the end of the stream has been reached
    /// - the stream produces an error (remember it's a [`TryStream`](futures_util::TryStream))
    ///
    /// The result will always have a non-empty `Vec` of items *or* a termination reason, and may
    /// have both.
    ///
    /// `BulkPolledStream` has "fused"-like behavior: after returning a chunk with a termination
    /// reason, future calls to `next_chunk` will always produce an empty chunk with the reason
    /// [`BulkPolledStreamTerminationReason::Finished`] (even if the stream was terminated because
    /// of an error).
    ///
    /// This operation is "cancel-safe": if cancelled before a result is produced, all elements of
    /// the underlying stream will show up in future calls.
    pub async fn next_chunk(mut self: Pin<&mut Self>) -> BulkPolledStreamChunk<T::Ok, T::Error> {
        let self_ = self.as_mut().project();

        debug_assert!(
            self_.pending.len() < *self_.max_chunk_size,
            "if we had a full chunk, we would have returned it last time"
        );

        let mut stream = match self_.state.project() {
            BulkPolledStreamStateProj::Active(stream) => stream,
            BulkPolledStreamStateProj::Terminated => {
                return BulkPolledStreamChunk {
                    chunk: std::mem::take(self_.pending),
                    termination: Some(BulkPolledStreamTerminationReason::Finished),
                };
            }
        };

        // "pull", not "poll": this returns a Future that *does* wait for the next element, whereas
        // "poll" would immediately return "pending" if there isn't one.
        //
        // This function is cancel-safe (as in, it will not drop any stream elements). Any
        // non-pending result from the underlying stream will be immediately reported.
        fn pull_next<T: futures_util::TryStream>(
            mut stream: Pin<&mut T>,
        ) -> impl Future<Output = ControlFlow<BulkPolledStreamTerminationReason<T::Error>, T::Ok>>
        {
            std::future::poll_fn(move |cx| stream.as_mut().try_poll_next(cx)).map(move |next| {
                match next {
                    Some(Ok(item)) => ControlFlow::Continue(item),
                    None => ControlFlow::Break(BulkPolledStreamTerminationReason::Finished),
                    Some(Err(status)) => {
                        ControlFlow::Break(BulkPolledStreamTerminationReason::Error(status))
                    }
                }
            })
        }

        // Always wait for at least one item.
        if self_.pending.is_empty() {
            match pull_next(stream.as_mut()).await {
                ControlFlow::Continue(item) => {
                    self_.pending.push(item);
                }
                ControlFlow::Break(termination) => {
                    return self.terminate_with_reason(termination);
                }
            }
        }

        // Keep polling until we either hit the max chunk size or the debounce timeout.
        let now = tokio::time::Instant::now();
        let deadline = now + *self_.debounce_time;
        while self_.pending.len() < *self_.max_chunk_size {
            // We rely on the pull_next helper being cancel-safe here.
            match tokio::time::timeout_at(deadline, pull_next(stream.as_mut())).await {
                Ok(ControlFlow::Continue(item)) => {
                    self_.pending.push(item);
                }
                Ok(ControlFlow::Break(termination)) => {
                    return self.terminate_with_reason(termination);
                }
                Err(tokio::time::error::Elapsed { .. }) => {
                    break;
                }
            }
        }

        // Explicitly check that the stream is still borrowed at this point, meaning we're still in
        // the Active state.
        _ = stream.as_mut();
        BulkPolledStreamChunk {
            chunk: std::mem::take(self_.pending),
            termination: None,
        }
    }
}

#[cfg(test)]
mod test {
    use std::pin::pin;

    use assert_matches::assert_matches;
    use futures_util::StreamExt as _;
    use itertools::Itertools;
    use proptest::proptest;
    use test_case::test_matrix;
    use tokio::time::Instant;

    use super::*;

    #[allow(clippy::zero_prefixed_literal)] // something inside test_matrix is causing this
    #[test_matrix(0..10)]
    #[tokio::test(start_paused = true)]
    async fn finite_streams_finish_immediately(stream_length: usize) {
        let max_chunk = 5;

        let mut stream = BulkPolledStream::new(
            futures_util::stream::iter(0..stream_length).map(Ok::<_, ()>),
            max_chunk,
            Duration::from_secs(1),
        );
        let result = stream
            .next_chunk_unpin()
            .now_or_never()
            .expect("should have finished");
        assert_eq!(
            result.chunk,
            (0..stream_length)
                .take(stream_length)
                .take(max_chunk)
                .collect_vec()
        );

        if stream_length < max_chunk {
            assert_matches!(
                result.termination,
                Some(BulkPolledStreamTerminationReason::Finished)
            );
            let second_result = &stream
                .next_chunk_unpin()
                .now_or_never()
                .expect("should have finished");
            assert_matches!(second_result.chunk[..], []);
            assert_matches!(
                second_result.termination,
                Some(BulkPolledStreamTerminationReason::Finished)
            );
        } else {
            assert_matches!(result.termination, None)
        }
    }

    #[allow(clippy::zero_prefixed_literal)] // something inside test_matrix is causing this
    #[test_matrix(1..=10)]
    #[tokio::test(start_paused = true)]
    async fn reading_in_chunks_eventually_gets_everything(max_chunk: usize) {
        let mut stream = BulkPolledStream::new(
            futures_util::stream::iter(0..10).map(Ok::<_, ()>),
            max_chunk,
            Duration::from_secs(1),
        );

        let mut collected = vec![];
        loop {
            let BulkPolledStreamChunk { chunk, termination } = stream
                .next_chunk_unpin()
                .now_or_never()
                .expect("should have finished");
            assert!(!chunk.is_empty() || termination.is_some());
            collected.extend(chunk);
            if let Some(termination) = termination {
                assert_matches!(termination, BulkPolledStreamTerminationReason::Finished);
                break;
            }
            assert!(collected.len() <= 10, "should have finished by now");
        }
        assert_eq!(collected, Vec::from_iter(0..10));

        let second_result = &stream
            .next_chunk_unpin()
            .now_or_never()
            .expect("should have finished");
        assert_matches!(second_result.chunk[..], []);
        assert_matches!(
            second_result.termination,
            Some(BulkPolledStreamTerminationReason::Finished)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn poll_pending_does_not_finish_early() {
        let mut stream = BulkPolledStream::new(
            futures_util::stream::pending::<Result<u32, ()>>(),
            5,
            Duration::from_secs(1),
        );
        tokio::time::timeout(Duration::from_secs(10), stream.next_chunk_unpin())
            .await
            .expect_err("should not have finished");
    }

    #[test_matrix(1..10)]
    #[tokio::test(start_paused = true)]
    async fn partially_pending_streams_wait_for_debounce(stream_length: usize) {
        let start = Instant::now();
        let debounce_time = Duration::from_secs(1);
        let max_chunk = 5;

        let mut stream = BulkPolledStream::new(
            futures_util::stream::iter(0..stream_length)
                .map(Ok::<_, ()>)
                .chain(futures_util::stream::pending()),
            max_chunk,
            debounce_time,
        );
        let BulkPolledStreamChunk { chunk, termination } =
            tokio::time::timeout(Duration::from_secs(10), stream.next_chunk_unpin())
                .await
                .expect("should have finished");
        assert_eq!(
            chunk,
            (0..stream_length)
                .take(stream_length)
                .take(max_chunk)
                .collect_vec()
        );
        assert_matches!(termination, None);

        if stream_length >= max_chunk {
            assert_eq!(Instant::now(), start);
        } else {
            assert_eq!(Instant::now(), start + debounce_time);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn slow_streams_wait_for_debounce() {
        let start = Instant::now();
        let sleep_time = Duration::from_millis(300);
        let debounce_time = Duration::from_secs(1); // not a multiple of sleep_time!

        let stream = pin!(BulkPolledStream::new(
            futures_util::stream::unfold(0, |i| async move {
                tokio::time::sleep(sleep_time).await;
                Some((Ok::<_, ()>(i), i + 1))
            }),
            5,
            debounce_time
        ));
        let BulkPolledStreamChunk { chunk, termination } =
            tokio::time::timeout(Duration::from_secs(10), stream.next_chunk())
                .await
                .expect("should have finished");
        assert_eq!(chunk, vec![0, 1, 2, 3]); // wait for 0, then start the timer for 1,2,3
        assert_matches!(termination, None);
        assert_eq!(Instant::now(), start + sleep_time + debounce_time);
    }

    #[tokio::test(start_paused = true)]
    async fn debounce_timer_starts_immediately_if_there_are_pending_elements() {
        let start = Instant::now();
        let sleep_time = Duration::from_millis(300);
        let debounce_time = Duration::from_secs(1); // not a multiple of sleep_time!

        let mut stream = pin!(BulkPolledStream::new(
            futures_util::stream::unfold(0, |i| async move {
                tokio::time::sleep(sleep_time).await;
                Some((Ok::<_, ()>(i), i + 1))
            }),
            10,
            debounce_time
        ));

        let a_bit_more_than_twice_sleep_time = Duration::from_millis(650);
        _ = tokio::time::timeout(
            a_bit_more_than_twice_sleep_time,
            stream.as_mut().next_chunk(),
        )
        .await
        .expect_err("should have been cancelled by tokio::time::timeout");
        assert_eq!(Instant::now(), start + a_bit_more_than_twice_sleep_time);

        let BulkPolledStreamChunk { chunk, termination } =
            tokio::time::timeout(Duration::from_secs(10), stream.next_chunk())
                .await
                .expect("should have finished");
        // We immediately get 0 and 1, then start the timer for 2 (already partway through sleeping), 3, and 4.
        assert_eq!(chunk, vec![0, 1, 2, 3, 4]);
        assert_matches!(termination, None);
        assert_eq!(
            Instant::now(),
            start + a_bit_more_than_twice_sleep_time + debounce_time
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fast_streams_stop_at_chunk_size() {
        let start = Instant::now();
        let sleep_time = Duration::from_millis(100);
        let debounce_time = Duration::from_secs(1); // not a multiple of sleep_time!

        let stream = pin!(BulkPolledStream::new(
            futures_util::stream::unfold(0, |i| async move {
                tokio::time::sleep(sleep_time).await;
                Some((Ok::<_, ()>(i), i + 1))
            }),
            5,
            debounce_time
        ));
        let BulkPolledStreamChunk { chunk, termination } =
            tokio::time::timeout(Duration::from_secs(10), stream.next_chunk())
                .await
                .expect("should have finished");
        assert_eq!(chunk, vec![0, 1, 2, 3, 4]);
        assert_matches!(termination, None);
        assert_eq!(Instant::now(), start + 5 * sleep_time);
    }

    #[test]
    fn stream_starting_with_error_returns_error() {
        let mut stream = BulkPolledStream::new(
            futures_util::stream::iter([Err::<i32, _>("oh no")])
                .chain(futures_util::stream::poll_fn(|_| unreachable!())),
            5,
            Duration::from_secs(1),
        );
        let result = stream
            .next_chunk_unpin()
            .now_or_never()
            .expect("should have finished");
        assert_matches!(result.chunk[..], []);
        assert_matches!(
            result.termination,
            Some(BulkPolledStreamTerminationReason::Error("oh no"))
        );

        // A repeated poll should have sensible behavior.
        let second_result = stream
            .next_chunk_unpin()
            .now_or_never()
            .expect("should have finished");
        assert_matches!(second_result.chunk[..], []);
        assert_matches!(
            second_result.termination,
            Some(BulkPolledStreamTerminationReason::Finished)
        );
    }

    #[test_matrix(1..=3)]
    #[tokio::test(start_paused = true)]
    async fn stream_with_error_after_elements(num_elements: usize) {
        let mut stream = BulkPolledStream::new(
            futures_util::stream::iter(0..num_elements)
                .map(Ok)
                .chain(futures_util::stream::iter([Err("oh no")]))
                .chain(futures_util::stream::poll_fn(|_| unreachable!())),
            5,
            Duration::from_secs(1),
        );
        let result = stream
            .next_chunk_unpin()
            .now_or_never()
            .expect("should have finished");
        assert_eq!(result.chunk, Vec::from_iter(0..num_elements));
        assert_matches!(
            result.termination,
            Some(BulkPolledStreamTerminationReason::Error("oh no"))
        );

        // A repeated poll should have sensible behavior.
        let second_result = stream
            .next_chunk_unpin()
            .now_or_never()
            .expect("should have finished");
        assert_matches!(second_result.chunk[..], []);
        assert_matches!(
            second_result.termination,
            Some(BulkPolledStreamTerminationReason::Finished)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn absurdly_large_limits() {
        let mut stream = BulkPolledStream::new(
            futures_util::stream::iter(0..10).map(Ok::<_, ()>),
            usize::MAX,
            Duration::MAX,
        );
        let BulkPolledStreamChunk { chunk, termination } =
            stream.next_chunk_unpin().now_or_never().expect("ready");
        assert_eq!(chunk, Vec::from_iter(0..10));
        assert_matches!(
            termination,
            Some(BulkPolledStreamTerminationReason::Finished)
        );
    }

    // Note the lack of start_paused here; if it's paused, the debounce timer *hasn't* expired on
    // first poll. But even with that we still read all the ready items anyway.
    #[tokio::test]
    async fn duration_of_zero() {
        let mut stream = BulkPolledStream::new(
            futures_util::stream::iter(0..10).map(Ok::<_, ()>),
            20,
            Duration::ZERO,
        );
        let BulkPolledStreamChunk { chunk, termination } =
            stream.next_chunk_unpin().now_or_never().expect("ready");
        assert_eq!(chunk, Vec::from_iter(0..10));
        assert_matches!(
            termination,
            Some(BulkPolledStreamTerminationReason::Finished)
        );
    }

    #[allow(clippy::zero_prefixed_literal)] // something inside test_matrix is causing this
    #[test_matrix(1..=10)]
    #[tokio::test(start_paused = true)]
    async fn reading_in_chunks_eventually_gets_everything_even_with_cancellation(max_chunk: usize) {
        proptest!(|(poll_counts in proptest::collection::vec(..10usize, 1..20))| {
            proptest::prop_assume!(poll_counts.iter().any(|count| *count != 0));

            let mut stream = pin!(BulkPolledStream::new(
                futures_util::stream::unfold(0, |i| async move {
                    tokio::task::yield_now().await;
                    Some((Ok::<_, ()>(i), i + 1))
                })
                .take(10),
                max_chunk,
                Duration::MAX,
            ));

            let mut collected = vec![];
            'outer: for num_polls in poll_counts.into_iter().cycle() {
                let mut fut = pin!(stream.as_mut().next_chunk());
                // The general strategy: poll the future N times (chosen by proptest), then give up
                // if it's not ready yet. As long as N isn't *always* 0, this should eventually succeed.
                for _ in 0..num_polls {
                    match fut.as_mut().now_or_never() {
                        None => {}
                        Some(BulkPolledStreamChunk { chunk, termination }) => {
                            assert!(!chunk.is_empty() || termination.is_some());
                            collected.extend(chunk);
                            eprintln!("received {}", collected.len());
                            if let Some(termination) = termination {
                                assert_matches!(
                                    termination,
                                    BulkPolledStreamTerminationReason::Finished
                                );
                                break 'outer;
                            }
                            assert!(collected.len() <= 10, "should have finished by now");
                            continue 'outer;
                        }
                    }
                }
            }
            assert_eq!(collected, Vec::from_iter(0..10));

            let second_result = &stream
                .next_chunk()
                .now_or_never()
                .expect("should have finished");
            assert_matches!(second_result.chunk[..], []);
            assert_matches!(
                second_result.termination,
                Some(BulkPolledStreamTerminationReason::Finished)
            );
        });
    }
}
