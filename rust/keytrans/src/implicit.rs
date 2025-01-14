//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! Implements the Implicit Binary Search Tree.

use std::collections::HashSet;

pub use crate::left_balanced::is_leaf;
use crate::left_balanced::{left_step, log2, parent_step, right_step};

fn move_within(mut x: u64, start: u64, n: u64) -> u64 {
    while !(start..n).contains(&x) {
        if x < start {
            x = right_step(x)
        } else {
            x = left_step(x)
        }
    }
    x
}

/// Returns the position of the root node of a search.
pub fn root(start: u64, n: u64) -> u64 {
    move_within((1 << log2(n)) - 1, start, n)
}

/// Returns the left child of an intermediate node.
pub fn left(x: u64, start: u64, n: u64) -> u64 {
    move_within(left_step(x), start, n)
}

/// Returns the right child of an intermediate node.
pub fn right(x: u64, start: u64, n: u64) -> u64 {
    move_within(right_step(x), start, n)
}

fn parent(x: u64, n: u64) -> u64 {
    let mut p = parent_step(x);
    while p >= n {
        p = parent_step(p);
    }
    p
}

fn direct_path(mut x: u64, start: u64, n: u64) -> impl Iterator<Item = u64> {
    let r = root(start, n);
    std::iter::from_fn(move || {
        if x == r {
            None
        } else {
            x = parent(x, n);
            Some(x)
        }
    })
}

/// Returns the sequence of parent nodes to be checked as part of monitoring a
/// single version of a key.
pub fn monitoring_path(x: u64, start: u64, n: u64) -> impl Iterator<Item = u64> {
    direct_path(x, start, n).filter(move |parent| *parent > x)
}

/// Returns the frontier of the log.
pub fn frontier(start: u64, n: u64) -> Vec<u64> {
    let mut last = root(start, n);
    let mut frontier = vec![last];
    while last != n - 1 {
        last = right(last, start, n);
        frontier.push(last);
    }
    frontier
}

fn monitoring_frontier(frontier: &[u64], entries: HashSet<u64>) -> Vec<u64> {
    let (index, _value) = frontier
        .iter()
        .enumerate()
        .rev()
        .find(|(_index, value)| entries.contains(value))
        .expect("monitoring paths must always terminate at some frontier node");
    frontier[index + 1..].to_vec()
}

/// Returns the full set of entries that should be checked as part of monitoring
/// a particular version of a key.
pub fn full_monitoring_path(entry: u64, start: u64, n: u64) -> Vec<u64> {
    let mut path = vec![];
    let mut dedup = HashSet::new();
    for x in monitoring_path(entry, start, n) {
        if dedup.insert(x) {
            path.push(x);
        }
    }
    dedup.insert(entry);
    path.extend(monitoring_frontier(&frontier(start, n), dedup));
    path
}

/// Find the first parent node which is to the right of the entry.
fn first_parent_to_the_right(entry: &u64) -> u64 {
    let mut out = *entry;
    while out <= *entry {
        out = parent_step(out);
    }
    out + 1
}

pub fn next_monitor(entries: &[u64]) -> u64 {
    entries
        .iter()
        .map(first_parent_to_the_right)
        .min()
        .expect("entries array should not be empty")
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    #[derive(Clone, Debug)]
    struct StartAndN {
        start: u64,
        n: u64,
    }

    prop_compose! {
        fn start_and_n()(n in 0..=u64::MAX)(start in 0..n, n in Just(n)) -> StartAndN {
            StartAndN { start, n }
        }
    }

    fn direct_path_eager(mut x: u64, start: u64, n: u64) -> Vec<u64> {
        let r = root(start, n);
        if x == r {
            return vec![];
        }

        let mut d = vec![];
        while x != r {
            x = parent(x, n);
            d.push(x);
        }
        d
    }

    #[test]
    fn direct_path_model() {
        proptest!(|(config in start_and_n())| {
            let StartAndN { start, n } = config;
            let eager = direct_path_eager(start, start, n);
            let lazy: Vec<_> = direct_path(start, start, n).collect();
            assert_eq!(eager, lazy);
        });
    }

    #[test]
    fn root_prop() {
        proptest!(|(config in start_and_n())|{
            let StartAndN { start, n } = config;
            let _ = root(start, n);
        });
    }
}
