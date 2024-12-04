//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! Implements the Log Tree.
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
        if x < p {
            right(p, n)
        } else {
            left(p)
        }
    }

    // Returns true if node x represents a full subtree.
    fn is_full_subtree(x: u64, n: u64) -> bool {
        let rightmost = 2 * (n - 1);
        let expected = x + (1 << level(x)) - 1;

        expected <= rightmost
    }

    // Returns the list of full subtrees that x consists of.
    pub fn full_subtrees(mut x: u64, n: u64) -> Vec<u64> {
        let mut out = vec![];

        while !is_full_subtree(x, n) {
            out.push(left(x));
            x = right(x, n);
        }
        out.push(x);

        out
    }

    // Returns the list of node ids to return for a consistency proof between m
    // and n, based on the algorithm from RFC 6962.
    pub fn consistency_proof(m: u64, n: u64) -> Vec<u64> {
        sub_proof(m, n, true)
    }

    fn sub_proof(m: u64, n: u64, b: bool) -> Vec<u64> {
        if m == n {
            return match b {
                true => vec![],
                false => vec![root(m)],
            };
        }
        let mut k = 1u64 << log2(n);
        if k == n {
            k /= 2;
        }
        if m <= k {
            let mut proof = sub_proof(m, k, b);
            proof.push(right(root(n), n));
            proof
        } else {
            let mut proof: Vec<u64> = sub_proof(m - k, n - k, false)
                .iter()
                .map(|x| x + 2 * k)
                .collect();
            proof.insert(0, left(root(n)));
            proof
        }
    }

    // Returns the copath nodes of a batch of leaves.
    pub fn batch_copath(leaves: &[u64], n: u64) -> Vec<u64> {
        // Convert the leaf indices to node indices.
        let mut nodes: Vec<u64> = leaves.iter().map(|x| 2 * x).collect();
        nodes.sort();

        // Iteratively combine nodes until there's only one entry in the list
        // (being the root), keeping track of the extra nodes we needed to get
        // there.
        let mut out = vec![];
        let root = root(n);
        while !(nodes.len() == 1 && nodes[0] == root) {
            let mut next_level = vec![];

            while nodes.len() > 1 {
                let p = parent(nodes[0], n);
                if right(p, n) == nodes[1] {
                    // Sibling is already here.
                    nodes.drain(..2);
                } else {
                    // Need to fetch sibling.
                    out.push(sibling(nodes[0], n));
                    nodes.drain(..1);
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

            nodes = next_level;
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

            assert_eq!(full_subtrees(7, 6), vec![3, 9]);

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
#[derive(Clone)]
struct NodeData {
    leaf: bool,
    value: Hash,
}

impl NodeData {
    fn marshal(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        if !self.leaf {
            out[0] = 1;
        }
        out[1..33].copy_from_slice(&self.value);

        out
    }
}

// Returns the intermediate hash of left and right.
fn tree_hash(left: &NodeData, right: &NodeData) -> NodeData {
    let mut hasher = Sha256::new();
    hasher.update(left.marshal());
    hasher.update(right.marshal());

    NodeData {
        leaf: false,
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
        while self.chain.len() < level + 1 {
            self.chain.push(None);
        }

        let mut acc = NodeData {
            leaf: level == 0,
            value,
        };
        let mut i = level;
        while i < self.chain.len() {
            match self.chain[i].as_ref() {
                Some(nd) => {
                    acc = tree_hash(nd, &acc);
                    self.chain[i] = None;
                    i += 1;
                }
                None => break,
            }
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
        let res = self.chain.iter().enumerate().find(|(_, nd)| nd.is_some());
        let (root_pos, root) = match res {
            Some((i, Some(nd))) => (i, (*nd).clone()),
            _ => return Err(Error::MalformedChain),
        };

        // Fold the hashes above what we just found into one.
        Ok(self.chain[root_pos + 1..]
            .iter()
            .fold(root, |acc, nd| match nd {
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
    if x.is_empty() {
        return Err(Error::InvalidInput(
            "can not evaluate empty batch inclusion proof",
        ));
    }
    if x[x.len() - 1] >= n {
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

// Returns the root of the tree immediately after the leaf `x[early_stop]` has
// been sequenced.
pub fn truncate_batch_proof(
    early_stop: usize,
    x: &[u64],
    values: &[Hash],
    proof: &[Hash],
) -> Result<Hash> {
    if early_stop >= x.len() {
        return Err(Error::InvalidInput("early_stop is out of bounds"));
    }
    let x = &x[..early_stop + 1];
    let stop_id = x[early_stop];
    let copath = math::batch_copath(x, stop_id + 1);

    evaluate_batch_proof(
        x,
        stop_id + 1,
        &values[..early_stop + 1],
        &proof[..copath.len()],
    )
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
    let path = math::full_subtrees(math::root(m), m);
    if path.len() == 1 {
        // m is a power of two so we don't need to verify anything.
        calc.insert(math::level(math::root(m)), *m_root);
    } else {
        for (i, &elem) in path.iter().enumerate() {
            if ids[i] != elem {
                // TODO: PathMismatch maybe?
                return Err(Error::Unexpected("id does not match path"));
            }
            calc.insert(math::level(elem), proof[i]);
        }
        match calc.root() {
            Ok(root) => {
                if m_root != &root {
                    return Err(Error::ProofMismatch("first root does not match proof"));
                }
            }
            Err(err) => return Err(err),
        }
    }

    // Step 2: Verify that the consistency proof aligns with n_root.
    let i = match path.len() {
        1 => 0,
        i => i,
    };
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
    use hex_literal::hex;

    use super::*;

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_evaluate_batch_proof() {
        let mut values = [[0u8; 32]; 6];
        let mut proof = [[0u8; 32]; 7];
        for (i, value) in values.iter_mut().enumerate() {
            value[0] = i as u8;
        }
        for (i, elem) in proof.iter_mut().enumerate() {
            elem[0] = (6 + i) as u8;
        }

        let got = evaluate_batch_proof(&[0, 1, 2, 4, 8, 16], 18, &values, &proof).unwrap();
        let want = hex!("435b929d1b8da2cb7f35119903c1f72d3f048e30b0dd0081a97b41f8da37f58f");
        assert!(got == want);
    }

    #[test]
    fn test_truncate_batch_proof() {
        let values = &[
            hex!("92c3f73e218d073192c84247c56c12cadd8adc70624c5e879ef213afee0a927a"),
            hex!("42b59b311613ff156ce56686f690ea17794bbe155947e1893263957639e776b7"),
            hex!("c9fdbec01c9fe76f9b97c7afcc9b93829cb62b4f0fd5018c687ff6e537198d31"),
        ];
        let proof = &[
            hex!("a0b219fe94b49121df5b8210ff4f14b5bbddaf49f689be971cbcfe82d47cc590"),
            hex!("5bebed9662a891f5ad369fad2a58efdedc37eef70a1979244cb3b3dd2c13782e"),
            hex!("f8d36bfd0ce37743de10910a32f1eaa1cf3d7b037342b9834b4c9e847b416618"),
            hex!("190fefcbd2f2617305b74097c449d131fe8c0b62365a1de6d0708ddb6bbf0f7d"),
            hex!("b941e7a040c42477e2f547003760821428195876b9185a95f70484868e92b900"),
            hex!("ecf8b73011345554f10c6aea96ea07c685ae2fb37e337075c30a74949ee28e14"),
            hex!("d306f87c5a08d671d1d27a0050aeb50c34bbd09bee1e04e8843143205de96bb1"),
            hex!("88d133186fc10d8bf2d11aef0fad6a984c348af392729218916e91366749c1ff"),
        ];

        let got = truncate_batch_proof(1, &[5, 10, 15], values, proof).unwrap();
        let want = hex!("1eb26fa1fac53af285479ba4536ef762648fb4c740429f2810065130b92fb00f");
        assert!(got == want);
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
