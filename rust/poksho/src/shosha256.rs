//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// implements the "innerpad" SHO/SHA256 proposal

use sha2::{Digest, Sha256};
use std::cmp;

use crate::shoapi::ShoApi;

pub const BLOCK_LEN: usize = 64;
pub const HASH_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
enum Mode {
    ABSORBING,
    RATCHETED,
}

#[derive(Clone)]
pub struct ShoSha256 {
    hasher: Sha256,
    cv: [u8; HASH_LEN],
    mode: Mode,
}

impl ShoApi for ShoSha256 {
    fn new(label: &[u8]) -> ShoSha256 {
        let mut sho = ShoSha256 {
            hasher: Sha256::new(),
            cv: [0; HASH_LEN],
            mode: Mode::RATCHETED,
        };
        sho.absorb_and_ratchet(label);
        sho
    }

    fn absorb(&mut self, input: &[u8]) {
        if let Mode::RATCHETED = self.mode {
            // Explicitly pass a slice to avoid generating multiple versions of update().
            self.hasher.update(&[0u8; BLOCK_LEN][..]);
            self.hasher.update(&self.cv[..]);
            self.mode = Mode::ABSORBING;
        }
        self.hasher.update(input);
    }

    // called after absorb() only; streaming squeeze not yet supported
    fn ratchet(&mut self) {
        if let Mode::RATCHETED = self.mode {
            return;
        }

        // Double hash
        self.cv
            .copy_from_slice(&Sha256::digest(&self.hasher.finalize_reset()[..])[..]);
        self.mode = Mode::RATCHETED;
    }

    fn squeeze_and_ratchet(&mut self, outlen: usize) -> Vec<u8> {
        assert!(self.mode == Mode::RATCHETED);
        let mut output = Vec::<u8>::new();
        let mut output_hasher_prefix = Sha256::new();
        // Explicitly pass a slice to avoid generating multiple versions of update().
        output_hasher_prefix.update(&[0u8; BLOCK_LEN - 1][..]);
        output_hasher_prefix.update(&[1u8][..]); // domain separator byte
        output_hasher_prefix.update(self.cv);
        let mut i = 0;
        while i * HASH_LEN < outlen {
            let mut output_hasher = output_hasher_prefix.clone();
            output_hasher.update((i as u64).to_be_bytes());
            let digest = output_hasher.finalize();
            let num_bytes = cmp::min(HASH_LEN, outlen - i * HASH_LEN);
            output.extend_from_slice(&digest[0..num_bytes]);
            i += 1
        }

        let mut next_hasher = Sha256::new();
        next_hasher.update(&[0u8; BLOCK_LEN - 1][..]);
        next_hasher.update(&[2u8][..]); // domain separator byte
        next_hasher.update(self.cv);
        next_hasher.update((outlen as u64).to_be_bytes());
        self.cv.copy_from_slice(&next_hasher.finalize()[..]);
        self.mode = Mode::RATCHETED;
        output
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_vectors() {
        let mut sho = ShoSha256::new(b"asd");
        sho.absorb_and_ratchet(b"asdasd");
        let out = sho.squeeze_and_ratchet(64);

        println!("{}", hex::encode(&out));

        assert!(
            out == vec![
                0xeb, 0xe4, 0xef, 0x29, 0xe1, 0x8a, 0xa5, 0x41, 0x37, 0xed, 0xd8, 0x9c, 0x23, 0xf8,
                0xbf, 0xea, 0xc2, 0x73, 0x1c, 0x9f, 0x67, 0x5d, 0xa2, 0x0e, 0x7c, 0x67, 0xd5, 0xad,
                0x68, 0xd7, 0xee, 0x2d, 0x40, 0xa4, 0x52, 0x32, 0xb5, 0x99, 0x55, 0x2d, 0x46, 0xb5,
                0x20, 0x08, 0x2f, 0xb2, 0x70, 0x59, 0x71, 0xf0, 0x7b, 0x31, 0x58, 0xb0, 0x72, 0xb6,
                0x3a, 0xb0, 0x93, 0x4a, 0x05, 0xe6, 0xaf, 0x64,
            ]
        );

        let mut sho = ShoSha256::new(b"asd");
        sho.absorb_and_ratchet(b"asdasd");
        let out = sho.squeeze_and_ratchet(65);
        /*
        println!("{}", hex::encode(&out));
        */
        assert!(
            out == vec![
                0xeb, 0xe4, 0xef, 0x29, 0xe1, 0x8a, 0xa5, 0x41, 0x37, 0xed, 0xd8, 0x9c, 0x23, 0xf8,
                0xbf, 0xea, 0xc2, 0x73, 0x1c, 0x9f, 0x67, 0x5d, 0xa2, 0x0e, 0x7c, 0x67, 0xd5, 0xad,
                0x68, 0xd7, 0xee, 0x2d, 0x40, 0xa4, 0x52, 0x32, 0xb5, 0x99, 0x55, 0x2d, 0x46, 0xb5,
                0x20, 0x08, 0x2f, 0xb2, 0x70, 0x59, 0x71, 0xf0, 0x7b, 0x31, 0x58, 0xb0, 0x72, 0xb6,
                0x3a, 0xb0, 0x93, 0x4a, 0x05, 0xe6, 0xaf, 0x64, 0x48,
            ]
        );

        let mut sho = ShoSha256::new(b"");
        sho.absorb_and_ratchet(b"abc");
        sho.absorb_and_ratchet(&[0u8; 63]);
        sho.absorb_and_ratchet(&[0u8; 64]);
        sho.absorb_and_ratchet(&[0u8; 65]);
        sho.absorb_and_ratchet(&[0u8; 127]);
        sho.absorb_and_ratchet(&[0u8; 128]);
        sho.absorb_and_ratchet(&[0u8; 129]);
        sho.squeeze_and_ratchet(63);
        sho.squeeze_and_ratchet(64);
        sho.squeeze_and_ratchet(65);
        sho.squeeze_and_ratchet(127);
        sho.squeeze_and_ratchet(128);
        sho.squeeze_and_ratchet(129);
        sho.absorb_and_ratchet(b"def");
        let out = sho.squeeze_and_ratchet(63);
        /*
        println!("{}", hex::encode(&out));
        */
        assert!(
            out == vec![
                0x0d, 0xde, 0xea, 0x97, 0x3f, 0x32, 0x10, 0xf7, 0x72, 0x5a, 0x3c, 0xdb, 0x24, 0x73,
                0xf8, 0x73, 0xae, 0xab, 0x8f, 0xeb, 0x32, 0xb8, 0x0d, 0xee, 0x67, 0xf0, 0xcd, 0xe7,
                0x95, 0x4e, 0x92, 0x9a, 0x4e, 0x78, 0x7a, 0xef, 0xee, 0x6d, 0xbe, 0x91, 0xd3, 0xff,
                0xf1, 0x62, 0x1a, 0xab, 0x8d, 0x0d, 0x29, 0x19, 0x4f, 0x8a, 0xf9, 0x86, 0xd6, 0xf3,
                0x57, 0xad, 0xd0, 0x15, 0x0d, 0xf7, 0xd9,
            ]
        );
    }
}
