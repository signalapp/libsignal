//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
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
pub struct ShoHmacSha256 {
    hasher: Hmac<Sha256>,
    cv: [u8; HASH_LEN],
    mode: Mode,
}

impl ShoApi for ShoHmacSha256 {
    fn new(label: &[u8]) -> ShoHmacSha256 {
        let mut sho = ShoHmacSha256 {
            hasher: Hmac::<Sha256>::new_from_slice(&[0; HASH_LEN])
                .expect("HMAC accepts 256-bit keys"),
            cv: [0; HASH_LEN],
            mode: Mode::RATCHETED,
        };
        sho.absorb_and_ratchet(label);
        sho
    }

    fn absorb(&mut self, input: &[u8]) {
        if let Mode::RATCHETED = self.mode {
            self.hasher =
                Hmac::<Sha256>::new_from_slice(&self.cv).expect("HMAC accepts 256-bit keys");
            self.mode = Mode::ABSORBING;
        }
        self.hasher.update(input);
    }

    // called after absorb() only; streaming squeeze not yet supported
    fn ratchet(&mut self) {
        if let Mode::RATCHETED = self.mode {
            return;
        }
        self.hasher.update(&[0x00]);
        self.cv
            .copy_from_slice(&self.hasher.clone().finalize().into_bytes());
        self.hasher.reset();
        self.mode = Mode::RATCHETED;
    }

    fn squeeze_and_ratchet(&mut self, outlen: usize) -> Vec<u8> {
        assert!(self.mode == Mode::RATCHETED);
        let mut output = Vec::<u8>::new();
        let output_hasher_prefix =
            Hmac::<Sha256>::new_from_slice(&self.cv).expect("HMAC accepts 256-bit keys");
        let mut i = 0;
        while i * HASH_LEN < outlen {
            let mut output_hasher = output_hasher_prefix.clone();
            output_hasher.update(&(i as u64).to_be_bytes());
            output_hasher.update(&[0x01]);
            let digest = output_hasher.finalize().into_bytes();
            let num_bytes = cmp::min(HASH_LEN, outlen - i * HASH_LEN);
            output.extend_from_slice(&digest[0..num_bytes]);
            i += 1
        }

        let mut next_hasher = output_hasher_prefix;
        next_hasher.update(&(outlen as u64).to_be_bytes());
        next_hasher.update(&[0x02]);
        self.cv
            .copy_from_slice(&next_hasher.finalize().into_bytes()[..]);
        self.mode = Mode::RATCHETED;
        output
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_vectors() {
        let mut sho = ShoHmacSha256::new(b"asd");
        sho.absorb_and_ratchet(b"asdasd");
        let out = sho.squeeze_and_ratchet(64);
        /*
        println!("{}", hex::encode(&out));
        */
        assert!(
            out == vec![
                0x39, 0x2c, 0xb9, 0x44, 0x93, 0x73, 0x03, 0x7f, 0xa0, 0xc1, 0x1a, 0xeb, 0xed, 0x69,
                0xcc, 0xa3, 0xb7, 0xd3, 0xbc, 0x97, 0x90, 0x87, 0x8f, 0x34, 0x17, 0x29, 0xc6, 0x5d,
                0x55, 0x06, 0x44, 0x2f, 0x04, 0x98, 0x6c, 0xb5, 0xc9, 0x09, 0x8f, 0x27, 0x7c, 0x3e,
                0xa6, 0x40, 0xa4, 0xdc, 0x6e, 0x90, 0x37, 0x2b, 0x43, 0x3a, 0x90, 0xaf, 0x9a, 0xea,
                0x70, 0x72, 0xea, 0xba, 0x33, 0x98, 0xc4, 0xfe,
            ]
        );

        let mut sho = ShoHmacSha256::new(b"asd");
        sho.absorb_and_ratchet(b"asdasd");
        let out = sho.squeeze_and_ratchet(65);
        /*
        println!("{}", hex::encode(&out));
        */
        assert!(
            out == vec![
                0x39, 0x2c, 0xb9, 0x44, 0x93, 0x73, 0x03, 0x7f, 0xa0, 0xc1, 0x1a, 0xeb, 0xed, 0x69,
                0xcc, 0xa3, 0xb7, 0xd3, 0xbc, 0x97, 0x90, 0x87, 0x8f, 0x34, 0x17, 0x29, 0xc6, 0x5d,
                0x55, 0x06, 0x44, 0x2f, 0x04, 0x98, 0x6c, 0xb5, 0xc9, 0x09, 0x8f, 0x27, 0x7c, 0x3e,
                0xa6, 0x40, 0xa4, 0xdc, 0x6e, 0x90, 0x37, 0x2b, 0x43, 0x3a, 0x90, 0xaf, 0x9a, 0xea,
                0x70, 0x72, 0xea, 0xba, 0x33, 0x98, 0xc4, 0xfe, 0x7a,
            ]
        );

        let mut sho = ShoHmacSha256::new(b"");
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
        println!("{}", hex::encode(&out));
        assert!(
            out == vec![
                0xc5, 0xc1, 0x3b, 0xcc, 0x65, 0x96, 0xc2, 0x5f, 0xc4, 0x51, 0x4e, 0xac, 0x92, 0x69,
                0xdd, 0x6e, 0x3e, 0x57, 0xef, 0x70, 0xf4, 0xbf, 0xb8, 0xd6, 0x7f, 0xd3, 0x08, 0x2e,
                0xd9, 0x73, 0x2d, 0x77, 0x90, 0xd8, 0xd2, 0x68, 0x6f, 0x19, 0xeb, 0x25, 0x33, 0xa6,
                0x5c, 0x94, 0xbb, 0x8c, 0xed, 0xa0, 0xa0, 0x68, 0xe1, 0xb6, 0x15, 0xc8, 0x1b, 0xb2,
                0x6e, 0x41, 0x18, 0x89, 0xda, 0x9f, 0xb7,
            ]
        );
    }
}
