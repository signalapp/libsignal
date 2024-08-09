//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::result::Result;

use crate::implicit;

/// Set of counters is not monotonic
#[derive(Debug, displaydoc::Display)]
pub struct InvalidState;

pub struct VersionedId {
    id: u64,
    version: u32,
}

impl VersionedId {
    pub fn new(id: u64, version: u32) -> Self {
        Self { id, version }
    }
}

/// ProofGuide is used for determining which nodes should be accessed when
/// conducting searches in the Implicit Binary Search Tree.
pub struct ProofGuide {
    /// Position of the key's first occurrence in the log.
    pos: u64,
    /// Number of leaf entries in the log.
    n: u64,
    /// The version of the key being searched for.
    version: u32,
    /// List of ids to fetch as part of search.
    ids: Vec<u64>,
    /// List of ids that were fetched, and the counter found.
    sorted: Vec<VersionedId>,
    // Whether `ids` represent the frontier.
    is_frontier: bool,
}

impl ProofGuide {
    pub fn new(version: Option<u32>, pos: u64, n: u64) -> Self {
        match version {
            None => Self::for_most_recent(pos, n),
            Some(version) => Self::for_version(version, pos, n),
        }
    }

    fn for_version(version: u32, pos: u64, n: u64) -> Self {
        Self {
            pos,
            n,
            version,
            ids: vec![implicit::root(pos, n)],
            sorted: vec![],

            is_frontier: false,
        }
    }

    fn for_most_recent(pos: u64, n: u64) -> Self {
        Self {
            pos,
            n,
            version: 0,
            ids: implicit::frontier(pos, n),
            sorted: vec![],

            is_frontier: true,
        }
    }

    /// Returns true if the search proof is finished.
    fn poll(&mut self) -> Result<bool, InvalidState> {
        if self.ids.len() > self.sorted.len() {
            return Ok(false);
        }
        self.sorted.sort_by_key(|versioned_id| versioned_id.id);

        // Check that the list of counters is monotonic.
        let sorted = self.sorted.windows(2).all(|w| w[0].version <= w[1].version);
        if !sorted {
            return Err(InvalidState);
        }

        // Determine the "last" id looked up. Generally this is actually just
        // the last id that was looked up, but if we just fetched the frontier
        // then we start searching at the first element of the frontier with the
        // greatest version.
        let last = if self.is_frontier {
            self.version = self.sorted[self.sorted.len() - 1].version;
            self.is_frontier = false;

            self.sorted
                .iter()
                .find(|versioned_id| versioned_id.version == self.version)
                .expect("last element of array must match, if no earlier one does")
                .id
        } else {
            self.ids[self.ids.len() - 1]
        };
        if implicit::is_leaf(last) {
            return Ok(true);
        }

        // Find the counter associated with the last id looked up.
        let ctr = self
            .sorted
            .iter()
            .find(|versioned_id| versioned_id.id == last)
            .expect("last id looked up must have corresponding entry in sorted")
            .version;

        // Find the next id to lookup by moving left or right depending on ctr.
        let next_id = if ctr < self.version {
            if last == self.n - 1 {
                return Ok(true);
            }
            implicit::right(last, self.pos, self.n)
        } else {
            if last == self.pos {
                return Ok(true);
            }
            implicit::left(last, self.pos, self.n)
        };
        self.ids.push(next_id);
        Ok(false)
    }

    /// Returns the next id to fetch from the database.
    fn next_id(&self) -> u64 {
        self.ids[self.sorted.len()]
    }

    /// Adds an id-counter pair to the guide.
    pub fn insert(&mut self, id: u64, ctr: u32) {
        self.sorted.push(VersionedId::new(id, ctr));
    }

    // Returns the index that represents the final search result.
    fn result(self) -> Option<(usize, u64)> {
        // Must only be called after poll returned true.
        assert!(!self.is_frontier, "result() called unexpectedly");

        let VersionedId {
            id: smallest_id,
            version: _,
        } = self
            .sorted
            .iter()
            // Just using find (== version) would iterate over all the items (> version) unnecessarily
            .find(|versioned_id| versioned_id.version >= self.version)
            .filter(|versioned_id| versioned_id.version == self.version)
            .or(None)?;

        // Return the index of the search that contains the result we want.
        self.ids
            .into_iter()
            .enumerate()
            .find(|(_, id)| id == smallest_id)
    }

    /// Iterates over the ProofGuide by continuously calling `poll` until it returns true.
    /// Invokes `step` on each iteration passing it the mutable reference to the guide
    /// as well as the current id for this step.
    pub fn consume<StepF, E>(mut self, mut step: StepF) -> Result<Option<(usize, u64)>, E>
    where
        StepF: FnMut(&mut Self, u64) -> Result<(), E>,
        E: From<InvalidState>,
    {
        loop {
            if self.poll()? {
                return Ok(self.result());
            }
            let next_id = self.next_id();
            step(&mut self, next_id)?;
        }
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;

    fn execute_guide(
        guide: ProofGuide,
        start: u64,
        end: u64,
        target: u64,
    ) -> (Option<(usize, u64)>, Vec<u64>) {
        let mut ids = vec![];

        let result = guide.consume(|guide, id| {
            assert!(
                (start..end).contains(&id),
                "Requested id is outside the expected range [start, end)"
            );

            ids.push(id);
            if id < target {
                guide.insert(id, 0);
            } else {
                guide.insert(id, 1);
            }
            Ok::<(), InvalidState>(())
        });

        (result.unwrap(), ids)
    }

    #[test_case(0, 100; "version 0")]
    #[test_case(1, 399; "version 1")]
    fn test_version_proof_guide(version: u32, expected_id: u64) {
        let guide = ProofGuide::for_version(version, 100, 700);
        let (result, ids) = execute_guide(guide, 100, 700, 399);
        let (result_i, result_id) = result.unwrap();
        assert_eq!(ids[result_i], expected_id);
        assert_eq!(result_id, expected_id);
    }

    #[test_case(700, 701, 100; "target 701")]
    #[test_case(700, 399, 399; "target 399")]
    #[test_case(700, 699, 699; "target 699")]
    #[test_case(701, 700, 700; "target 700")]
    fn test_most_recent_proof_guide(end: u64, target: u64, expected_id: u64) {
        let guide = ProofGuide::for_most_recent(100, end);
        let (result, ids) = execute_guide(guide, 100, end, target);
        let (result_i, result_id) = result.unwrap();
        assert_eq!(ids[result_i], expected_id);
        assert_eq!(result_id, expected_id);
    }
}
