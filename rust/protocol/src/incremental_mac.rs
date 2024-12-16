//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use aes::cipher::Unsigned;
use hmac::digest::generic_array::{ArrayLength, GenericArray};
use hmac::Mac;
use sha2::digest::{FixedOutput, MacError, Output};

#[derive(Clone)]
pub struct Incremental<M: Mac + Clone> {
    mac: M,
    chunk_size: usize,
    unused_length: usize,
}

#[derive(Clone)]
pub struct Validating<M: Mac + Clone> {
    incremental: Incremental<M>,
    // Expected MACs in reversed order, to efficiently pop them from off the end
    expected: Vec<Output<M>>,
}

const MINIMUM_CHUNK_SIZE: usize = 64 * 1024;
const MAXIMUM_CHUNK_SIZE: usize = 2 * 1024 * 1024;
const TARGET_TOTAL_DIGEST_SIZE: usize = 8 * 1024;

pub const fn calculate_chunk_size<D>(data_size: usize) -> usize
where
    D: FixedOutput,
    D::OutputSize: ArrayLength<u8>,
{
    assert!(
        0 == TARGET_TOTAL_DIGEST_SIZE % D::OutputSize::USIZE,
        "Target digest size should be a multiple of digest size"
    );
    let target_chunk_count = TARGET_TOTAL_DIGEST_SIZE / D::OutputSize::USIZE;
    if data_size < target_chunk_count * MINIMUM_CHUNK_SIZE {
        return MINIMUM_CHUNK_SIZE;
    }
    if data_size < target_chunk_count * MAXIMUM_CHUNK_SIZE {
        return data_size.div_ceil(target_chunk_count);
    }
    MAXIMUM_CHUNK_SIZE
}

impl<M: Mac + Clone> Incremental<M> {
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
            .map(|mac| GenericArray::<u8, M::OutputSize>::from_slice(mac.as_ref()).to_owned())
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
        self.mac.finalize().into_bytes()
    }

    fn update_chunk(&mut self, bytes: &[u8]) -> Option<Output<M>> {
        assert!(bytes.len() <= self.unused_length);
        self.mac.update(bytes);
        self.unused_length -= bytes.len();
        if self.unused_length == 0 {
            self.unused_length = self.chunk_size;
            let mac = self.mac.clone();
            Some(mac.finalize().into_bytes())
        } else {
            None
        }
    }

    fn pending_bytes_size(&self) -> usize {
        self.chunk_size - self.unused_length
    }
}

impl<M: Mac + Clone> Validating<M> {
    pub fn update(&mut self, bytes: &[u8]) -> Result<usize, MacError> {
        let mut result = Ok(0);
        let macs = self.incremental.update(bytes);

        let mut whole_chunks = 0;
        for mac in macs {
            match self.expected.last() {
                Some(expected) if expected == &mac => {
                    whole_chunks += 1;
                    self.expected.pop();
                }
                _ => {
                    result = Err(MacError);
                }
            }
        }
        let validated_bytes = whole_chunks * self.incremental.chunk_size;
        result.map(|_| validated_bytes)
    }

    pub fn finalize(self) -> Result<usize, MacError> {
        let pending_bytes_size = self.incremental.pending_bytes_size();
        let mac = self.incremental.finalize();
        match &self.expected[..] {
            [expected] if expected == &mac => Ok(pending_bytes_size),
            _ => Err(MacError),
        }
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use hmac::Hmac;
    use proptest::prelude::*;
    use rand::distributions::Uniform;
    use rand::prelude::{Rng, ThreadRng};
    use sha2::digest::OutputSizeUser;
    use sha2::Sha256;

    use super::*;
    use crate::crypto::hmac_sha256;

    const TEST_HMAC_KEY: &[u8] =
        &hex!("a83481457efecc69ad1342e21d9c0297f71debbf5c9304b4c1b2e433c1a78f98");

    const TEST_CHUNK_SIZE: usize = 32;

    fn new_incremental(key: &[u8], chunk_size: usize) -> Incremental<Hmac<Sha256>> {
        let hmac = Hmac::<Sha256>::new_from_slice(key)
            .expect("Should be able to create a new HMAC instance");
        Incremental::new(hmac, chunk_size)
    }

    #[test]
    #[should_panic]
    fn chunk_size_zero() {
        new_incremental(&[], 0);
    }

    #[test]
    fn simple_test() {
        let key = TEST_HMAC_KEY;
        let input = "this is a simple test input string which is longer than the chunk";

        let bytes = input.as_bytes();
        let expected = hmac_sha256(key, bytes);
        let mut incremental = new_incremental(key, TEST_CHUNK_SIZE);
        let _ = incremental.update(bytes).collect::<Vec<_>>();
        let digest = incremental.finalize();
        let actual: [u8; 32] = digest.into();
        assert_eq!(actual, expected);
    }

    #[test]
    fn final_result_should_be_equal_to_non_incremental_hmac() {
        let key = TEST_HMAC_KEY;
        proptest!(|(input in ".{0,100}")| {
            let bytes = input.as_bytes();
            let expected = hmac_sha256(key, bytes);
            let mut incremental = new_incremental(key, TEST_CHUNK_SIZE);
            let _ = incremental.update(bytes).collect::<Vec<_>>();
            let actual: [u8; 32] = incremental.finalize().into();
            assert_eq!(actual, expected);
        });
    }

    #[test]
    fn incremental_macs_are_valid() {
        let key = TEST_HMAC_KEY;

        proptest!(|(input in ".{50,100}")| {
            let bytes = input.as_bytes();
            let mut incremental = new_incremental(key, TEST_CHUNK_SIZE);

            // Manually breaking the input in buffer-sized chunks and calculating the HMACs on the
            // ever-increasing input prefix.
            let expected: Vec<_> = bytes
                .chunks(incremental.chunk_size)
                .scan(Vec::new(), |acc, chunk| {
                    acc.extend(chunk.iter());
                    Some(hmac_sha256(key, acc).to_vec())
                })
                .collect();

            let mut actual: Vec<Vec<u8>> = bytes
                .random_chunks(incremental.chunk_size)
                .flat_map(|chunk| incremental.update(chunk).collect::<Vec<_>>())
                .map(|out| out.into())
                .map(|bs: [u8; 32]| bs.to_vec())
                .collect();
            // If the input is not an exact multiple of the chunk_size, there are some leftovers in
            // the incremental that need to be accounted for.
            if bytes.len() % incremental.chunk_size != 0 {
                let last_hmac: [u8; 32] = incremental.finalize().into();
                actual.push(last_hmac.to_vec());
            }
            assert_eq!(actual, expected);
        });
    }

    #[test]
    fn validating_simple_test() {
        let key = TEST_HMAC_KEY;
        let input = "this is a simple test input string";

        let bytes = input.as_bytes();
        let mut incremental = new_incremental(key, TEST_CHUNK_SIZE);
        let mut expected_macs: Vec<_> = incremental.update(bytes).collect();
        expected_macs.push(incremental.finalize());

        let expected_bytes: Vec<[u8; 32]> =
            expected_macs.into_iter().map(|mac| mac.into()).collect();

        {
            let mut validating =
                new_incremental(key, TEST_CHUNK_SIZE).validating(expected_bytes.clone());
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
                new_incremental(key, TEST_CHUNK_SIZE).validating(failing_first_update);
            validating.update(bytes).expect_err("MacError");
        }

        {
            let mut failing_finalize = expected_bytes.clone();
            failing_finalize
                .last_mut()
                .expect("there must be at least one mac")[0] ^= 0xff;
            let mut validating = new_incremental(key, TEST_CHUNK_SIZE).validating(failing_finalize);
            validating.update(bytes).expect("update should succeed");
            validating.finalize().expect_err("MacError");
        }

        {
            let missing_last_mac = &expected_bytes[0..expected_bytes.len() - 1];
            let mut validating = new_incremental(key, TEST_CHUNK_SIZE).validating(missing_last_mac);
            validating.update(bytes).expect("update should succeed");
            validating.finalize().expect_err("MacError");
        }

        {
            let missing_first_mac: Vec<_> = expected_bytes.clone().into_iter().skip(1).collect();
            let mut validating =
                new_incremental(key, TEST_CHUNK_SIZE).validating(missing_first_mac);
            validating.update(bytes).expect_err("MacError");
        }
        // To make clippy happy and allow extending the test in the future
        std::hint::black_box(expected_bytes);
    }

    #[test]
    fn validating_returns_right_size() {
        let key = TEST_HMAC_KEY;
        let input = "this is a simple test input string";

        let bytes = input.as_bytes();
        let mut incremental = new_incremental(key, TEST_CHUNK_SIZE);
        let mut expected_macs: Vec<_> = incremental.update(bytes).collect();
        expected_macs.push(incremental.finalize());

        let expected_bytes: Vec<[u8; 32]> =
            expected_macs.into_iter().map(|mac| mac.into()).collect();

        let mut validating = new_incremental(key, TEST_CHUNK_SIZE).validating(expected_bytes);

        // Splitting input into chunks of 16 will give us one full incremental chunk + 3 bytes
        // authenticated by call to finalize.
        let input_chunks = bytes.chunks(16).collect::<Vec<_>>();
        assert_eq!(3, input_chunks.len());
        let expected_remainder = bytes.len() - TEST_CHUNK_SIZE;

        for (expected_size, input) in std::iter::zip([0, TEST_CHUNK_SIZE, 0], input_chunks) {
            assert_eq!(
                expected_size,
                validating
                    .update(input)
                    .expect("update: validation should succeed")
            );
        }
        assert_eq!(
            expected_remainder,
            validating
                .finalize()
                .expect("finalize: validation should succeed")
        );
    }

    #[test]
    fn produce_and_validate() {
        let key = TEST_HMAC_KEY;

        proptest!(|(input in ".{0,100}")| {
            let bytes = input.as_bytes();
            let mut incremental = new_incremental(key, TEST_CHUNK_SIZE);
            let input_chunks = bytes.random_chunks(incremental.chunk_size*2);

            let mut produced: Vec<[u8; 32]> = input_chunks.clone()
                .flat_map(|chunk| incremental.update(chunk).collect::<Vec<_>>())
                .map(|out| out.into())
                .collect();
            produced.push(incremental.finalize().into());

            let mut validating = new_incremental(key, TEST_CHUNK_SIZE).validating(produced);
            for chunk in input_chunks.clone() {
                validating.update(chunk).expect("update: validation should succeed");
            }
            validating.finalize().expect("finalize: validation should succeed");
        });
    }

    const KIBIBYTES: usize = 1024;
    const MEBIBYTES: usize = 1024 * KIBIBYTES;
    const GIBIBYTES: usize = 1024 * MEBIBYTES;

    #[test]
    fn chunk_sizes_sha256() {
        for (data_size, expected) in [
            (0, MINIMUM_CHUNK_SIZE),
            (KIBIBYTES, MINIMUM_CHUNK_SIZE),
            (10 * KIBIBYTES, MINIMUM_CHUNK_SIZE),
            (100 * KIBIBYTES, MINIMUM_CHUNK_SIZE),
            (MEBIBYTES, MINIMUM_CHUNK_SIZE),
            (10 * MEBIBYTES, MINIMUM_CHUNK_SIZE),
            (20 * MEBIBYTES, 80 * KIBIBYTES),
            (100 * MEBIBYTES, 400 * KIBIBYTES),
            (200 * MEBIBYTES, 800 * KIBIBYTES),
            (256 * MEBIBYTES, MEBIBYTES),
            (512 * MEBIBYTES, 2 * MEBIBYTES),
            (GIBIBYTES, 2 * MEBIBYTES),
            (2 * GIBIBYTES, 2 * MEBIBYTES),
        ] {
            let actual = calculate_chunk_size::<Sha256>(data_size);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn chunk_sizes_sha512() {
        for (data_size, expected) in [
            (0, MINIMUM_CHUNK_SIZE),
            (KIBIBYTES, MINIMUM_CHUNK_SIZE),
            (10 * KIBIBYTES, MINIMUM_CHUNK_SIZE),
            (100 * KIBIBYTES, MINIMUM_CHUNK_SIZE),
            (MEBIBYTES, MINIMUM_CHUNK_SIZE),
            (10 * MEBIBYTES, 80 * KIBIBYTES),
            (20 * MEBIBYTES, 160 * KIBIBYTES),
            (100 * MEBIBYTES, 800 * KIBIBYTES),
            (200 * MEBIBYTES, 1600 * KIBIBYTES),
            (256 * MEBIBYTES, 2 * MEBIBYTES),
            (512 * MEBIBYTES, 2 * MEBIBYTES),
            (GIBIBYTES, 2 * MEBIBYTES),
        ] {
            let actual = calculate_chunk_size::<sha2::Sha512>(data_size);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn total_digest_size_is_never_too_big() {
        fn total_digest_size(data_size: usize) -> usize {
            let chunk_size = calculate_chunk_size::<Sha256>(data_size);
            let num_chunks = std::cmp::max(1, data_size.div_ceil(chunk_size));
            num_chunks * <Sha256 as OutputSizeUser>::OutputSize::USIZE
        }
        let config = ProptestConfig::with_cases(10_000);
        proptest!(config, |(data_size in 256..256*MEBIBYTES)| {
            assert!(total_digest_size(data_size) <= 8*KIBIBYTES)
        });
        proptest!(|(data_size_mib in 256_usize..2048)| {
            assert!(total_digest_size(data_size_mib*MEBIBYTES) <= 32*KIBIBYTES)
        });
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
