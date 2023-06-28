//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use generic_array::{ArrayLength, GenericArray};
use hmac::crypto_mac::{MacError, Output};
use hmac::Mac;
use sha2::digest::FixedOutput;
use typenum::Unsigned;

#[derive(Clone)]
pub struct Incremental<M: Mac> {
    mac: M,
    chunk_size: usize,
    unused_length: usize,
}

#[derive(Clone)]
pub struct Validating<M: Mac> {
    incremental: Incremental<M>,
    // Expected MACs in reversed order, to efficiently pop them from off the end
    expected: Vec<Output<M>>,
}

const MINIMUM_INCREMENTAL_CHUNK_SIZE: usize = 8 * 1024;
const MAXIMUM_INCREMENTAL_DIGEST_BYTES: usize = 1024;

#[allow(clippy::manual_clamp)]
pub fn calculate_chunk_size<D>(data_size: usize) -> usize
where
    D: FixedOutput,
    D::OutputSize: ArrayLength<u8>,
{
    if data_size == 0 {
        return MINIMUM_INCREMENTAL_CHUNK_SIZE;
    }
    let max_chunks = MAXIMUM_INCREMENTAL_DIGEST_BYTES / D::OutputSize::USIZE;
    let chunk_size = (data_size + max_chunks - 1) / max_chunks;
    std::cmp::min(
        data_size,
        std::cmp::max(chunk_size, MINIMUM_INCREMENTAL_CHUNK_SIZE),
    )
}

impl<M: Mac> Incremental<M> {
    pub fn new(mac: M, chunk_size: usize) -> Self {
        assert!(chunk_size > 0, "chunk size must be positive");
        Self {
            mac,
            chunk_size,
            unused_length: chunk_size,
        }
    }

    pub fn validating<A, I>(self, macs: I) -> Validating<M>
    where
        A: AsRef<[u8]>,
        I: IntoIterator<Item = A>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
    {
        let expected = macs
            .into_iter()
            .map(|mac| {
                let arr = GenericArray::<u8, M::OutputSize>::from_slice(mac.as_ref()).to_owned();
                Output::<M>::new(arr)
            })
            .rev()
            .collect();
        Validating {
            incremental: self,
            expected,
        }
    }

    pub fn update<'a>(&'a mut self, bytes: &'a [u8]) -> impl Iterator<Item = Output<M>> + 'a {
        let split_point = std::cmp::min(bytes.len(), self.unused_length);
        let (to_write, overflow) = bytes.split_at(split_point);

        std::iter::once(to_write)
            .chain(overflow.chunks(self.chunk_size))
            .flat_map(move |chunk| self.update_chunk(chunk))
    }

    pub fn finalize(self) -> Output<M> {
        self.mac.finalize()
    }

    fn update_chunk(&mut self, bytes: &[u8]) -> Option<Output<M>> {
        assert!(bytes.len() <= self.unused_length);
        self.mac.update(bytes);
        self.unused_length -= bytes.len();
        if self.unused_length == 0 {
            self.unused_length = self.chunk_size;
            let mac = self.mac.clone();
            Some(mac.finalize())
        } else {
            None
        }
    }
}

impl<M: Mac> Validating<M> {
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), MacError> {
        let mut result = Ok(());
        let macs = self.incremental.update(bytes);

        // for mac in self.incremental.update(bytes) {
        for mac in macs {
            match self.expected.last() {
                Some(expected) if expected == &mac => {
                    self.expected.pop();
                }
                _ => {
                    result = Err(MacError);
                }
            }
        }
        result
    }

    pub fn finalize(self) -> Result<(), MacError> {
        let mac = self.incremental.finalize();
        match &self.expected[..] {
            [expected] if expected == &mac => Ok(()),
            _ => Err(MacError),
        }
    }
}

#[cfg(test)]
mod test {
    use hmac::{Hmac, NewMac};
    use proptest::prelude::*;
    use rand::distributions::Uniform;
    use rand::prelude::{Rng, ThreadRng};
    use sha2::Sha256;

    use crate::crypto::hmac_sha256;

    use super::*;

    const TEST_HMAC_KEY_HEX: &str =
        "a83481457efecc69ad1342e21d9c0297f71debbf5c9304b4c1b2e433c1a78f98";

    const TEST_CHUNK_SIZE: usize = 32;

    fn new_incremental(key: &[u8], chunk_size: usize) -> Incremental<Hmac<Sha256>> {
        let hmac = Hmac::<Sha256>::new_from_slice(key)
            .expect("Should be able to create a new HMAC instance");
        Incremental::new(hmac, chunk_size)
    }

    fn test_key() -> Vec<u8> {
        hex::decode(TEST_HMAC_KEY_HEX).expect("Should be able to decode the key from a hex string")
    }

    #[test]
    fn simple_test() {
        let key = test_key();
        let input = "this is a simple test input string which is longer than the chunk";

        let bytes = input.as_bytes();
        let expected = hmac_sha256(&key, bytes);
        let mut incremental = new_incremental(&key, TEST_CHUNK_SIZE);
        let _ = incremental.update(bytes).collect::<Vec<_>>();
        let digest = incremental.finalize();
        let actual: [u8; 32] = digest.into_bytes().into();
        assert_eq!(actual, expected);
    }

    #[test]
    fn final_result_should_be_equal_to_non_incremental_hmac() {
        let key = test_key();
        proptest!(|(input in ".{0,100}")| {
            let bytes = input.as_bytes();
            let expected = hmac_sha256(&key, bytes);
            let mut incremental = new_incremental(&key, TEST_CHUNK_SIZE);
            let _ = incremental.update(bytes).collect::<Vec<_>>();
            let actual: [u8; 32] = incremental.finalize().into_bytes().into();
            assert_eq!(actual, expected);
        });
    }

    #[test]
    fn incremental_macs_are_valid() {
        let key = test_key();

        proptest!(|(input in ".{50,100}")| {
            let bytes = input.as_bytes();
            let mut incremental = new_incremental(&key, TEST_CHUNK_SIZE);

            // Manually breaking the input in buffer-sized chunks and calculating the HMACs on the
            // ever-increasing input prefix.
            let expected: Vec<_> = bytes
                .chunks(incremental.chunk_size)
                .scan(Vec::new(), |acc, chunk| {
                    acc.extend(chunk.iter());
                    Some(hmac_sha256(&key, acc).to_vec())
                })
                .collect();

            let mut actual: Vec<Vec<u8>> = bytes
                .random_chunks(incremental.chunk_size)
                .flat_map(|chunk| incremental.update(chunk).collect::<Vec<_>>())
                .map(|out| out.into_bytes().into())
                .map(|bs: [u8; 32]| bs.to_vec())
                .collect();
            // If the input is not an exact multiple of the chunk_size, there are some leftovers in
            // the incremental that need to be accounted for.
            if bytes.len() % incremental.chunk_size != 0 {
                let last_hmac: [u8; 32] = incremental.finalize().into_bytes().into();
                actual.push(last_hmac.to_vec());
            }
            assert_eq!(actual, expected);
        });
    }

    #[test]
    fn validating_simple_test() {
        let key = test_key();
        let input = "this is a simple test input string";

        let bytes = input.as_bytes();
        let mut incremental = new_incremental(&key, TEST_CHUNK_SIZE);
        let mut expected_macs: Vec<_> = incremental.update(bytes).collect();
        expected_macs.push(incremental.finalize());

        let expected_bytes: Vec<[u8; 32]> = expected_macs
            .into_iter()
            .map(|mac| mac.into_bytes().into())
            .collect();

        {
            let mut validating =
                new_incremental(&key, TEST_CHUNK_SIZE).validating(expected_bytes.clone());
            validating
                .update(bytes)
                .expect("update: validation should succeed");
            validating
                .finalize()
                .expect("finalize: validation should succeed");
        }

        {
            let mut failing_first_update = expected_bytes.clone();
            failing_first_update
                .first_mut()
                .expect("there must be at least one mac")[0] ^= 0xff;
            let mut validating =
                new_incremental(&key, TEST_CHUNK_SIZE).validating(failing_first_update);
            validating.update(bytes).expect_err("MacError");
        }

        {
            let mut failing_finalize = expected_bytes.clone();
            failing_finalize
                .last_mut()
                .expect("there must be at least one mac")[0] ^= 0xff;
            let mut validating =
                new_incremental(&key, TEST_CHUNK_SIZE).validating(failing_finalize);
            validating.update(bytes).expect("update should succeed");
            validating.finalize().expect_err("MacError");
        }

        {
            let missing_last_mac = &expected_bytes[0..expected_bytes.len() - 1];
            let mut validating =
                new_incremental(&key, TEST_CHUNK_SIZE).validating(missing_last_mac);
            validating.update(bytes).expect("update should succeed");
            validating.finalize().expect_err("MacError");
        }

        {
            let missing_first_mac: Vec<_> = expected_bytes.clone().into_iter().skip(1).collect();
            let mut validating =
                new_incremental(&key, TEST_CHUNK_SIZE).validating(missing_first_mac);
            validating.update(bytes).expect_err("MacError");
        }
        // To make clippy happy and allow extending the test in the future
        std::hint::black_box(expected_bytes);
    }

    #[test]
    fn produce_and_validate() {
        let key = test_key();

        proptest!(|(input in ".{0,100}")| {
            let bytes = input.as_bytes();
            let mut incremental = new_incremental(&key, TEST_CHUNK_SIZE);
            let input_chunks = bytes.random_chunks(incremental.chunk_size*2);

            let mut produced: Vec<[u8; 32]> = input_chunks.clone()
                .flat_map(|chunk| incremental.update(chunk).collect::<Vec<_>>())
                .map(|out| out.into_bytes().into())
                .collect();
            produced.push(incremental.finalize().into_bytes().into());

            let mut validating = new_incremental(&key, TEST_CHUNK_SIZE).validating(produced);
            for chunk in input_chunks.clone() {
                validating.update(chunk).expect("update: validation should succeed");
            }
            validating.finalize().expect("finalize: validation should succeed");
        });
    }

    #[test]
    fn chunk_sizes() {
        for (data_size, expected) in [
            (1024, 1024),
            (10 * 1024, MINIMUM_INCREMENTAL_CHUNK_SIZE),
            (100 * 1024, MINIMUM_INCREMENTAL_CHUNK_SIZE),
            (1024 * 1024, 65_536),
            (10 * 1024 * 1024, 10 * 65_536),
            (100 * 1024 * 1024, 100 * 65_536),
        ] {
            let actual = calculate_chunk_size::<sha2::Sha512>(data_size);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn total_digest_size_is_never_too_big() {
        proptest!(|(data_size in 256_usize..1_000_000_000)| {
            let chunk_size = calculate_chunk_size::<Sha256>(data_size);
            let num_increments = std::cmp::max(1, (data_size + chunk_size - 1) / chunk_size);
            let total_digest_size = num_increments * <Sha256 as FixedOutput>::OutputSize::USIZE;
            assert!(total_digest_size <= MAXIMUM_INCREMENTAL_DIGEST_BYTES)
        })
    }

    #[test]
    fn chunk_size_is_never_larger_than_data_size() {
        proptest!(|(data_size in 256_usize..1_000_000_000)| {
            let chunk_size = calculate_chunk_size::<Sha256>(data_size);
            assert!(chunk_size <= data_size)
        })
    }

    #[test]
    fn chunk_size_for_empty_input() {
        assert_eq!(
            MINIMUM_INCREMENTAL_CHUNK_SIZE,
            calculate_chunk_size::<Sha256>(0)
        );
    }

    #[derive(Clone)]
    struct RandomChunks<'a, T, R: Rng> {
        base: &'a [T],
        distribution: Uniform<usize>,
        rng: R,
    }

    impl<'a, T, R: Rng> Iterator for RandomChunks<'a, T, R> {
        type Item = &'a [T];

        fn next(&mut self) -> Option<Self::Item> {
            if self.base.is_empty() {
                None
            } else {
                let candidate = self.rng.sample(self.distribution);
                let chunk_size = std::cmp::min(candidate, self.base.len());
                let (before, after) = self.base.split_at(chunk_size);
                self.base = after;
                Some(before)
            }
        }
    }

    trait RandomChunksIterator<T> {
        fn random_chunks(&self, max_size: usize) -> RandomChunks<T, ThreadRng>;
    }

    impl<T> RandomChunksIterator<T> for [T] {
        fn random_chunks(&self, max_size: usize) -> RandomChunks<T, ThreadRng> {
            assert!(max_size > 0, "Maximal chunk size should be positive");
            RandomChunks {
                base: self,
                distribution: Uniform::new(0, max_size + 1),
                rng: Default::default(),
            }
        }
    }
}
