//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! Implements the Log Tree.
use std::num::NonZero;

use sha2::{Digest, Sha256};

type Hash = [u8; 32];

mod math {
    // This module implements functions for navigating a Log Tree. Note that the
    // Log Tree structure is different from the Implicit Binary Search Tree's
    // structure, in that intermediate nodes always have two children.

    pub use crate::left_balanced::level;
    use crate::left_balanced::{left_step, log2, parent_step, right_step};

    // Returns the number of nodes needed to store a tree with n leaves.
    fn node_width(n: u64) -> u64 {
        match n {
            0 => 0,
            n => 2 * (n - 1) + 1,
        }
    }

    // Returns the id of the root node of a tree with n leaves.
    pub fn root(n: u64) -> u64 {
        (1 << log2(node_width(n))) - 1
    }

    // Returns the left child of an intermediate node.
    fn left(x: u64) -> u64 {
        left_step(x)
    }

    // Returns the right child of an intermediate node.
    fn right(x: u64, n: u64) -> u64 {
        let mut r = right_step(x);
        let w = node_width(n);
        while r >= w {
            r = left(r)
        }
        r
    }

    // Returns the id of the parent node of x in a tree with n leaves.
    fn parent(x: u64, n: u64) -> u64 {
        if x == root(n) {
            panic!("root node has no parent");
        }

        let width = node_width(n);
        let mut p = parent_step(x);
        while p >= width {
            p = parent_step(p);
        }
        p
    }

    // Returns the other child of the node's parent.
    fn sibling(x: u64, n: u64) -> u64 {
        let p = parent(x, n);
        if x < p { right(p, n) } else { left(p) }
    }

    // Returns true if node x represents a full subtree.
    fn is_full_subtree(x: u64, n: u64) -> bool {
        let rightmost = 2 * (n - 1);
        let expected = x + (1 << level(x)) - 1;

        expected <= rightmost
    }

    // Returns an iterator over the list of full subtrees that x consists of.
    pub fn full_subtrees(x: u64, n: u64) -> impl Iterator<Item = u64> {
        let mut next_x = Some(x);
        std::iter::from_fn(move || {
            let x = next_x?;

            if !is_full_subtree(x, n) {
                next_x = Some(right(x, n));
                return Some(left(x));
            }

            next_x = None;
            Some(x)
        })
    }

    // Returns the list of node ids to return for a consistency proof between m
    // and n, based on the algorithm from RFC 6962.
    pub fn consistency_proof(m: u64, n: u64) -> Vec<u64> {
        sub_proof(m, n)
    }

    fn sub_proof(m: u64, n: u64) -> Vec<u64> {
        let estimated_output_count = usize::try_from(log2(n)).unwrap_or_default() + 1;
        let mut output = Vec::with_capacity(estimated_output_count);
        sub_proof_impl(m, n, true, &mut output);
        return output;

        #[track_caller]
        fn sub_proof_impl(m: u64, n: u64, b: bool, output: &mut Vec<u64>) {
            if m == n {
                if !b {
                    output.push(root(m));
                }
                return;
            }
            let mut k = 1u64 << log2(n);
            if k == n {
                k /= 2;
            }
            if m <= k {
                sub_proof_impl(m, k, b, output);
                output.push(right(root(n), n));
            } else {
                output.push(left(root(n)));
                let subproof_start = output.len();

                sub_proof_impl(m - k, n - k, false, output);

                // Fix up the just-inserted sub-proof values.
                for x in &mut output[subproof_start..] {
                    *x += 2 * k;
                }
            }
        }
    }

    // Returns the copath nodes of a batch of leaves.
    pub fn batch_copath(leaves: &[u64], n: u64) -> Vec<u64> {
        // Convert the leaf indices to node indices.
        let mut current_level: Vec<u64> = leaves.iter().map(|x| 2 * x).collect();
        current_level.sort();

        // Iteratively combine nodes until there's only one entry in the list
        // (being the root), keeping track of the extra nodes we needed to get
        // there.
        let mut out = vec![];
        let root = root(n);

        // Use a slice over the elements to make dropping elements from the front
        // O(1). When we're ready to move on to the next level we'll replace
        // current_level and regenerate our view into it.
        let mut nodes = current_level.as_slice();

        while !(nodes.len() == 1 && nodes[0] == root) {
            let mut next_level = vec![];

            while nodes.len() > 1 {
                let p = parent(nodes[0], n);
                if right(p, n) == nodes[1] {
                    // Sibling is already here.
                    nodes = &nodes[2..];
                } else {
                    // Need to fetch sibling.
                    out.push(sibling(nodes[0], n));
                    nodes = &nodes[1..];
                }
                next_level.push(p);
            }
            if nodes.len() == 1 {
                if !next_level.is_empty() && level(parent(nodes[0], n)) > level(next_level[0]) {
                    next_level.push(nodes[0]);
                } else {
                    out.push(sibling(nodes[0], n));
                    next_level.push(parent(nodes[0], n));
                }
            }

            current_level = next_level;
            nodes = current_level.as_slice();
        }
        out.sort();

        out
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_math() {
            assert_eq!(log2(0), 0);
            assert_eq!(log2(8), 3);
            assert_eq!(log2(10000), 13);

            assert_eq!(level(1), 1);
            assert_eq!(level(2), 0);
            assert_eq!(level(3), 2);

            assert_eq!(root(5), 7);
            assert_eq!(left(7), 3);
            assert_eq!(right(7, 8), 11);
            assert_eq!(parent(1, 4), 3);
            assert_eq!(parent(5, 4), 3);
            assert_eq!(sibling(13, 8), 9);
            assert_eq!(sibling(9, 8), 13);

            assert_eq!(full_subtrees(7, 6).collect::<Vec<_>>(), vec![3, 9]);

            assert_eq!(batch_copath(&[0, 2, 3, 4], 8), vec![2, 10, 13]);
            assert_eq!(batch_copath(&[0, 2, 3], 8), vec![2, 11]);
        }
    }
}

#[derive(Debug, displaydoc::Display)]
pub enum Error {
    /// Empty chain
    EmptyChain,
    /// Malformed chain
    MalformedChain,
    /// Invalid input: {0}
    InvalidInput(&'static str),
    /// Malformed proof
    MalformedProof,
    /// Proof mismatch: {0}
    ProofMismatch(&'static str),
    /// Unexpected error: {0}
    Unexpected(&'static str),
}

type Result<T> = std::result::Result<T, Error>;

// The primary wrapper struct for representing a single node in the tree.
#[repr(C)]
#[derive(Clone, zerocopy::IntoBytes, zerocopy::Immutable)]
struct NodeData {
    /// `false` for leaf nodes, otherwise `true`
    interior: bool,
    value: Hash,
}

impl NodeData {
    fn marshal(&self) -> &[u8; 33] {
        let Self { interior, value } = self;
        #[allow(
            dropping_copy_types,
            reason = "explicit usages of implicitly-read fields"
        )]
        drop((interior, value));
        zerocopy::transmute_ref!(self)
    }
}

// Returns the intermediate hash of left and right.
fn tree_hash(left: &NodeData, right: &NodeData) -> NodeData {
    let mut hasher = Sha256::new();
    hasher.update(left.marshal());
    hasher.update(right.marshal());

    NodeData {
        interior: true,
        value: hasher.finalize().into(),
    }
}

struct SimpleRootCalculator {
    chain: Vec<Option<NodeData>>,
}

impl SimpleRootCalculator {
    fn new() -> Self {
        Self { chain: vec![] }
    }

    fn insert(&mut self, level: usize, value: Hash) {
        if let Some(needed) = (level + 1)
            .checked_sub(self.chain.len())
            .and_then(NonZero::new)
        {
            self.chain.extend(std::iter::repeat_n(None, needed.get()))
        }

        let mut acc = NodeData {
            interior: level != 0,
            value,
        };
        let mut i = level;

        while let Some(nd) = self.chain.get(i).and_then(Option::as_ref) {
            acc = tree_hash(nd, &acc);
            self.chain[i] = None;
            i += 1;
        }
        if i == self.chain.len() {
            self.chain.push(Some(acc));
        } else {
            self.chain[i] = Some(acc);
        }
    }

    fn root(&self) -> Result<Hash> {
        if self.chain.is_empty() {
            return Err(Error::EmptyChain);
        }

        // Find first non-null element of chain.
        let (root_pos, root) = self
            .chain
            .iter()
            .enumerate()
            .find_map(|(i, nd)| Some(i).zip(nd.as_ref()))
            .ok_or(Error::MalformedChain)?;

        // Fold the hashes above what we just found into one.
        Ok(self.chain[root_pos + 1..]
            .iter()
            .fold(root.clone(), |acc, nd| match nd {
                Some(nd) => tree_hash(nd, &acc),
                None => acc,
            })
            .value)
    }
}

// Returns the root that would result in the given proof being valid for the
// given values.
pub fn evaluate_batch_proof(x: &[u64], n: u64, values: &[Hash], proof: &[Hash]) -> Result<Hash> {
    if x.len() != values.len() {
        return Err(Error::InvalidInput(
            "expected same number of indices and values",
        ));
    }
    let sorted = x.windows(2).all(|w| w[0] < w[1]);
    if !sorted {
        return Err(Error::InvalidInput("input entries must be in sorted order"));
    }
    let last = x.last().ok_or(Error::InvalidInput(
        "can not evaluate empty batch inclusion proof",
    ))?;
    if *last >= n {
        return Err(Error::InvalidInput(
            "leaf ids can not be larger than tree size",
        ));
    }

    let copath = math::batch_copath(x, n);
    if proof.len() != copath.len() {
        return Err(Error::MalformedProof);
    }

    let mut calc = SimpleRootCalculator::new();
    let (mut i, mut j) = (0, 0);
    while i < x.len() && j < copath.len() {
        if 2 * x[i] < copath[j] {
            calc.insert(0, values[i]);
            i += 1;
        } else {
            calc.insert(math::level(copath[j]), proof[j]);
            j += 1;
        }
    }
    while i < x.len() {
        calc.insert(0, values[i]);
        i += 1;
    }
    while j < copath.len() {
        calc.insert(math::level(copath[j]), proof[j]);
        j += 1;
    }

    calc.root()
}

// Checks that `proof` is a valid consistency proof between `m_root` and
// `n_root` where `m` < `n`.
pub fn verify_consistency_proof(
    m: u64,
    n: u64,
    proof: &[Hash],
    m_root: &Hash,
    n_root: &Hash,
) -> Result<()> {
    if m == 0 || m >= n {
        return Err(Error::InvalidInput("m must be within [0, n)"));
    }
    let ids = math::consistency_proof(m, n);
    if proof.len() != ids.len() {
        return Err(Error::MalformedProof);
    }

    // Step 1: Verify that the consistency proof aligns with m_root.
    let mut calc = SimpleRootCalculator::new();

    let mut path = math::full_subtrees(math::root(m), m);

    let path_is_single_element;
    let path = {
        let first = path.next();
        let second = first.is_some().then(|| path.next()).flatten();
        path_is_single_element = first.is_some() && second.is_none();
        [first, second].into_iter().flatten().chain(path)
    };

    let i;
    if path_is_single_element {
        // m is a power of two so we don't need to verify anything.
        calc.insert(math::level(math::root(m)), *m_root);
        i = 0;
    } else {
        let mut path_len = 0;
        for (i, elem) in path.enumerate() {
            if ids[i] != elem {
                // TODO: PathMismatch maybe?
                return Err(Error::Unexpected("id does not match path"));
            }
            calc.insert(math::level(elem), proof[i]);
            path_len = i + 1;
        }

        if m_root != &calc.root()? {
            return Err(Error::ProofMismatch("first root does not match proof"));
        }
        i = path_len;
    }

    // Step 2: Verify that the consistency proof aligns with n_root.
    for j in i..ids.len() {
        calc.insert(math::level(ids[j]), proof[j]);
    }
    match calc.root() {
        Ok(root) if n_root == &root => Ok(()),
        Ok(_root) => Err(Error::ProofMismatch("second root does not match proof")),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod test {
    use const_str::hex;

    use super::*;

    #[test]
    fn test_evaluate_batch_proof() {
        let mut values = [[0u8; 32]; 6];
        let mut proof = [[0u8; 32]; 7];
        for (i, value) in values.iter_mut().enumerate() {
            #[expect(clippy::cast_possible_truncation)]
            {
                value[0] = i as u8;
            }
        }
        for (i, elem) in proof.iter_mut().enumerate() {
            #[expect(clippy::cast_possible_truncation)]
            {
                elem[0] = (6 + i) as u8;
            }
        }

        let got = evaluate_batch_proof(&[0, 1, 2, 4, 8, 16], 18, &values, &proof).unwrap();
        let want = hex!("435b929d1b8da2cb7f35119903c1f72d3f048e30b0dd0081a97b41f8da37f58f");
        assert_eq!(got, want);
    }

    #[test]
    fn test_verify_consistency_proof() {
        let m_root = hex!("47cffc2f3d88213d58d25ec12a2284cc94dd7736a5a2f99b5e49543f6d324409");
        let n_root = hex!("7b830576af52cb15e47f51bf0859c7918858881a2ae1945889e15e89f0b6b654");

        let proof = &[
            hex!("817b7723f0c429cc053f1690cdd9ef6357cf544c90b2b898f2b17647379a55f0"),
            hex!("a3d4fac233766d3f546ce7d21683bcfd442db3da1fd8f672b04223cd7e26e1d4"),
            hex!("02632c875f214195b9c116a13a105b7a5a891d3bf19d77e1c807380d918623d5"),
            hex!("cb0c07deb12feceeca301453fdc65fb15a1bada91dc69f5b045a3fb647a216ba"),
            hex!("f23e0ed32b4481c6619e6175105f6a555f55a7b6d98d4f297f4a292bfeedebb1"),
            hex!("7343774893f3b7b4dac9d1a5cb4e88d5c57b71dba95aa377f88da043af030df2"),
            hex!("bc593d72ffdfda9b8cbbc758e10a8bd07e8aed332f8c9168cbf834e8d1d80012"),
            hex!("32ef158c2def8c641f5c5392b6d248508b7d0fc1ea5ccda1deaf866d38e93ca4"),
            hex!("74e16d5b930d68f3228396f35717df5a2f6b58382c8d82a14d1c1f5190900f14"),
            hex!("db84e6de2d857cf6753b7321f5c3e6c7e66aaf8ec2c7b94b7959c462a4fc8162"),
            hex!("6263b4af228c862edcc8b63ca33d4e67d1d278000e1f7c3eb8cd56039b9613b3"),
        ];

        assert!(verify_consistency_proof(1078, 2000, proof, &m_root, &n_root).is_ok());
        assert!(verify_consistency_proof(1078, 2000, proof, &m_root, &m_root).is_err());
        assert!(verify_consistency_proof(1078, 2000, proof, &n_root, &n_root).is_err());
    }
}
