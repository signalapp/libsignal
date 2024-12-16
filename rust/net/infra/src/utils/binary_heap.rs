//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::Reverse;

use derive_where::derive_where;

/// Push, pop, and peek implementations.
pub trait Queue: Default {
    type Item;
    type PeekItem<'a>
    where
        Self: 'a;

    fn new() -> Self {
        Self::default()
    }

    /// Put another keyed element into the queue.
    fn push(&mut self, item: Self::Item);

    /// Take the next keyed element out of the queue.
    ///
    /// Returns `None` if the queue is empty.
    fn pop(&mut self) -> Option<Self::Item>;

    /// Returns a reference to the next item that would be returned by a call to
    /// [`Self::pop`].
    fn peek(&self) -> Option<Self::PeekItem<'_>>;

    /// Returns `true` if there are no more elements in the queue.
    fn is_empty(&self) -> bool {
        self.peek().is_none()
    }
}

/// A min-heap.
///
/// Implements [`Queue`]. When calling [`Queue::pop`], the next value out will
/// be the minimum one still in the queue.
///
/// For a max-heap, use [`std::collections::BinaryHeap`].
#[derive(Clone, Debug)]
#[derive_where(Default; T: Ord)]
pub struct MinHeap<T>(std::collections::BinaryHeap<Reverse<T>>);

/// A keyed priority queue with items of type `V` keyed by `K`.
///
/// Implements [`Queue`]. When calling [`Queue::pop`], the next value out will
/// be the one with the minimal `K`.
#[derive(Clone, Debug)]
#[derive_where(Default; K: Ord)]
pub struct MinKeyValueQueue<K, V>(MinHeap<KeyValue<K, V>>);

impl<T: Ord + Eq> Queue for MinHeap<T> {
    type Item = T;
    type PeekItem<'a>
        = &'a T
    where
        Self: 'a;

    fn push(&mut self, item: Self::Item) {
        self.0.push(Reverse(item));
    }

    fn pop(&mut self) -> Option<Self::Item> {
        self.0.pop().map(|Reverse(t)| t)
    }

    fn peek(&self) -> Option<Self::PeekItem<'_>> {
        self.0.peek().map(|Reverse(t)| t)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T: Ord + Eq> Extend<T> for MinHeap<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter.into_iter().map(Reverse))
    }
}

impl<K: Ord + Eq, V> Queue for MinKeyValueQueue<K, V> {
    type Item = (K, V);
    type PeekItem<'a>
        = (&'a K, &'a V)
    where
        Self: 'a;

    fn push(&mut self, (key, value): Self::Item) {
        self.0.push(KeyValue { key, value });
    }

    fn pop(&mut self) -> Option<Self::Item> {
        self.0.pop().map(|KeyValue { key, value }| (key, value))
    }

    fn peek(&self) -> Option<Self::PeekItem<'_>> {
        self.0.peek().map(|KeyValue { key, value }| (key, value))
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<K: Ord + Eq, V> Extend<(K, V)> for MinKeyValueQueue<K, V> {
    fn extend<T: IntoIterator<Item = (K, V)>>(&mut self, iter: T) {
        self.0
            .extend(iter.into_iter().map(|(key, value)| KeyValue { key, value }));
    }
}

/// Key-value pair that implements [`Ord`] and [`Eq`] by comparing only keys.
#[derive(Copy, Clone, Debug)]
struct KeyValue<K, V> {
    key: K,
    value: V,
}

impl<K: Eq, V> PartialEq for KeyValue<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<K: Eq, V> Eq for KeyValue<K, V> {}

impl<K: Ord + Eq, V> PartialOrd for KeyValue<K, V> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: Ord + Eq, V> Ord for KeyValue<K, V> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.cmp(&other.key)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn min_heap_ordering() {
        let mut min_heap = MinHeap::new();

        min_heap.push(10);
        min_heap.push(20);
        min_heap.push(1);
        min_heap.push(2);

        assert_eq!(min_heap.pop(), Some(1));
        assert_eq!(min_heap.pop(), Some(2));
        assert_eq!(min_heap.pop(), Some(10));
        assert_eq!(min_heap.pop(), Some(20));
        assert_eq!(min_heap.pop(), None);
    }

    #[test]
    fn min_heap_extend_peek_empty() {
        let mut min_heap = MinHeap::new();

        assert!(min_heap.is_empty());
        min_heap.extend([5, 4, 3, 2, 2]);

        assert_eq!(min_heap.peek(), Some(&2));
        let _ = min_heap.pop();
        assert_eq!(min_heap.peek(), Some(&2));
        let _ = min_heap.pop();
        assert_eq!(min_heap.peek(), Some(&3));
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    struct Unordered<T>(T);

    #[test]
    fn min_kv_queue_ordering() {
        let mut min_queue = MinKeyValueQueue::new();

        min_queue.push((10, Unordered('a')));
        min_queue.push((20, Unordered('b')));
        min_queue.push((1, Unordered('c')));
        min_queue.push((2, Unordered('d')));

        assert_eq!(min_queue.pop(), Some((1, Unordered('c'))));
        assert_eq!(min_queue.pop(), Some((2, Unordered('d'))));
        assert_eq!(min_queue.pop(), Some((10, Unordered('a'))));
        assert_eq!(min_queue.pop(), Some((20, Unordered('b'))));
        assert_eq!(min_queue.pop(), None);
    }

    #[test]
    fn min_kv_queue_extend_peek_empty() {
        let mut min_queue = MinKeyValueQueue::new();

        assert!(min_queue.is_empty());
        min_queue.extend([(5, 'a'), (5, 'b'), (4, 'c'), (3, 'd'), (2, 'e')]);

        assert_eq!(min_queue.peek(), Some((&2, &'e')));
        let _ = min_queue.pop();
        assert_eq!(min_queue.peek(), Some((&3, &'d')));
        let _ = min_queue.pop();
        assert_eq!(min_queue.peek(), Some((&4, &'c')));
    }
}
