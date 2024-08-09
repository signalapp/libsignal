//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Contains functions that are shared between the two left-balanced search tree
//! implementations (the Log Tree and the Implicit Binary Search Tree).
//!
//! This module works on a flat array representation, where the nodes of the
//! tree are numbered from left to right. Leaf nodes are stored in even-numbered
//! indices, while intermediate nodes are stored in odd-numbered indices:
//!
//! ```text
//!                              X
//!                              |
//!                    .---------+---------.
//!                   /                     \
//!                  X                       X
//!                  |                       |
//!              .---+---.               .---+---.
//!             /         \             /         \
//!            X           X           X           X
//!           / \         / \         / \         /
//!          /   \       /   \       /   \       /
//!         X     X     X     X     X     X     X
//!
//! Index:  0  1  2  3  4  5  6  7  8  9 10 11 12 13
//! ```
//!
//! The bit twiddling functions in this file are all taken from RFC 9420,
//! although you will not find more insight on how/why they work there.

pub fn log2(n: u64) -> u32 {
    n.checked_ilog2().unwrap_or(0)
}

/// Returns true if x is the position of a leaf node.
pub fn is_leaf(x: u64) -> bool {
    (x & 1) == 0
}

/// Returns the level of a node in the tree. Leaves are level 0, their parents
/// are level 1, and so on.
pub fn level(x: u64) -> usize {
    x.trailing_ones() as usize
}

pub fn left_step(x: u64) -> u64 {
    match level(x) {
        0 => panic!("leaf node has no children"),
        k => x ^ (1 << (k - 1)),
    }
}

pub fn right_step(x: u64) -> u64 {
    match level(x) {
        0 => panic!("leaf node has no children"),
        k => x ^ (3 << (k - 1)),
    }
}

pub fn parent_step(x: u64) -> u64 {
    let k = level(x);
    let b = (x >> (k + 1)) & 1;
    (x | (1 << k)) ^ (b << (k + 1))
}
