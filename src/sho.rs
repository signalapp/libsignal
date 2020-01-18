//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

use sha2::{Digest, Sha256};
use std::cmp;

#[derive(Clone)]
pub struct ShoSha256 {
    inner_hasher: Sha256,
    absorbed_len: u64,
}

pub const BLOCK_LEN: u64 = 64;
pub const HASH_LEN: u64 = 32;
pub const ZEROS: [u8; 64] = [0u8; 64];

impl ShoSha256 {
    pub fn shohash(label: &[u8], input: &[u8], outlen: u64) -> Vec<u8> {
        let mut sho = ShoSha256::new(label);
        sho.absorb(input);
        sho.squeeze(outlen)
    }

    pub fn new(label: &[u8]) -> ShoSha256 {
        let mut sho = ShoSha256 {
            inner_hasher: Sha256::new(),
            absorbed_len: 0,
        };
        sho.inner_hasher.input(&[0u8; BLOCK_LEN as usize][..]);
        sho.absorb(&((label.len() as u16).to_be_bytes()));
        sho.absorb(label);
        sho.pad_block();
        sho
    }

    pub fn absorb(&mut self, input: &[u8]) {
        self.inner_hasher.input(input);
        self.absorbed_len += input.len() as u64;
    }

    pub fn squeeze(&mut self, outlen: u64) -> Vec<u8> {
        let inner_digest = self.inner_hasher.result_reset();;
        let mut output = Vec::<u8>::new();
        let mut outer_hasher = Sha256::new();
        let mut i: u64 = 0;
        while i * HASH_LEN < outlen {
            outer_hasher.input(inner_digest);
            outer_hasher.input((i + 1).to_be_bytes());
            outer_hasher.input(0u64.to_be_bytes());
            let outer_digest = outer_hasher.result_reset();
            let num_bytes = cmp::min(HASH_LEN, outlen - i * HASH_LEN) as usize;
            output.extend_from_slice(&outer_digest[0..num_bytes]);
            i += 1
        }
        outer_hasher.input(inner_digest);
        outer_hasher.input(0u64.to_be_bytes());
        outer_hasher.input(outlen.to_be_bytes());
        let chain_key = outer_hasher.result_reset();
        self.inner_hasher.input(&[0u8; HASH_LEN as usize][..]);
        self.inner_hasher.input(chain_key);
        self.absorbed_len = 0;
        output
    }

    pub fn pad_block(&mut self) {
        let pad_len = (BLOCK_LEN - (self.absorbed_len % BLOCK_LEN)) % BLOCK_LEN;
        self.absorb(&ZEROS[0..pad_len as usize]);
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_vectors() {
        let mut block31 = [0u8; 31];
        let mut block32 = [0u8; 32];
        let mut block33 = [0u8; 33];
        let mut block63 = [0u8; 63];
        let mut block64 = [0u8; 64];
        let mut block65 = [0u8; 65];
        for i in 0..31 {
            block31[i] = i as u8;
        }
        for i in 0..32 {
            block32[i] = i as u8;
        }
        for i in 0..33 {
            block33[i] = i as u8;
        }
        for i in 0..63 {
            block63[i] = i as u8;
        }
        for i in 0..64 {
            block64[i] = i as u8;
        }
        for i in 0..65 {
            block65[i] = i as u8;
        }

        // empty label with different input lengths
        let mut sho = ShoSha256::new(b"");
        let out = sho.squeeze(16);
        assert!(
            out == [
                0x5d, 0xd7, 0x7, 0x8, 0x6e, 0xed, 0x5b, 0xf, 0xf6, 0xaa, 0xb1, 0x5f, 0x5f, 0x6e,
                0x27, 0x85
            ]
        );

        let mut sho = ShoSha256::new(b"");
        sho.absorb(&block31);
        let out = sho.squeeze(32);
        assert!(
            out == [
                0xf3, 0x9a, 0x4e, 0x15, 0x19, 0x35, 0xbf, 0x73, 0x70, 0xfc, 0x35, 0xd3, 0xa2, 0xcc,
                0x97, 0xa5, 0x11, 0x49, 0x5e, 0x65, 0x0, 0xdf, 0x70, 0x65, 0x1b, 0xf3, 0xc9, 0x6a,
                0x2e, 0xaf, 0xb, 0x3
            ]
        );

        let mut sho = ShoSha256::new(b"");
        sho.absorb(&block32);
        let out = sho.squeeze(48);
        assert!(
            out == vec![
                0x10, 0x70, 0xe2, 0x32, 0x1b, 0xbf, 0x56, 0xff, 0x5b, 0xef, 0xd2, 0xcb, 0x3, 0xd2,
                0xd1, 0x5a, 0xd2, 0xff, 0x7, 0x11, 0xe3, 0x5d, 0xa0, 0x48, 0xd0, 0x14, 0x7f, 0x37,
                0xb7, 0xa1, 0x0, 0xe8, 0x4a, 0x8c, 0xe7, 0xe1, 0x49, 0xf4, 0x9b, 0xdf, 0xbf, 0x71,
                0xa8, 0xe6, 0xed, 0x49, 0xf6, 0xbe
            ]
        );

        let mut sho = ShoSha256::new(b"");
        sho.absorb(&block33);
        let out = sho.squeeze(64);
        assert!(
            out == vec![
                0xa, 0xbd, 0x51, 0x9b, 0x17, 0x86, 0xf5, 0xa9, 0x4e, 0xc0, 0xc1, 0x97, 0x7b, 0xd,
                0x34, 0xeb, 0xc7, 0xa4, 0x59, 0x1f, 0xf0, 0x40, 0x99, 0x89, 0xa4, 0xeb, 0xb2, 0xb7,
                0xe2, 0x89, 0xf6, 0x9d, 0xc, 0x9a, 0x4d, 0xe6, 0x96, 0x15, 0x44, 0x55, 0x63, 0x49,
                0x3e, 0xb8, 0xfc, 0x6b, 0x5a, 0x44, 0x6b, 0x74, 0x9f, 0x46, 0xce, 0x5, 0xed, 0x8e,
                0x5f, 0xb, 0xb9, 0x88, 0x6, 0x74, 0x22, 0x52
            ]
        );

        //longer labels with a different input lengths
        let mut sho = ShoSha256::new(b"label");
        let out = sho.squeeze(16);
        assert!(
            out == vec![
                0xf7, 0xbc, 0xb8, 0xc0, 0xe0, 0xc, 0xa0, 0xb4, 0x65, 0xeb, 0xaf, 0x70, 0xeb, 0x4e,
                0x98, 0x95
            ]
        );

        let mut sho = ShoSha256::new(&block31);
        sho.absorb(&block63);
        let out = sho.squeeze(33);
        assert!(
            out == vec![
                0xde, 0xba, 0x7d, 0x15, 0x5a, 0x6a, 0x72, 0x1f, 0xf0, 0x4a, 0x8, 0x9a, 0x75, 0x2c,
                0x74, 0x79, 0x55, 0xe7, 0x9c, 0x48, 0xc1, 0x37, 0xa9, 0x6d, 0x4d, 0xa, 0x62, 0x2c,
                0x8, 0x57, 0x19, 0x7b, 0x2b
            ]
        );

        let mut sho = ShoSha256::new(&block32);
        sho.absorb(&block64);
        let out = sho.squeeze(47);
        assert!(
            out == vec![
                0x31, 0x70, 0x44, 0x3b, 0x33, 0xfe, 0xae, 0xc3, 0xeb, 0xda, 0x58, 0xd4, 0xa0, 0x8c,
                0xf8, 0x91, 0xee, 0x6c, 0x56, 0xf9, 0x13, 0xbe, 0xe1, 0x7b, 0xd1, 0x9e, 0xbc, 0xb0,
                0x78, 0xa3, 0xf5, 0x33, 0x29, 0xf3, 0xb6, 0x32, 0xdf, 0x40, 0x53, 0x95, 0x5, 0x32,
                0xe5, 0xeb, 0x5a, 0x66, 0xd3
            ]
        );

        let mut sho = ShoSha256::new(&block33);
        sho.absorb(&block65);
        let out = sho.squeeze(80);
        assert!(
            out == vec![
                0x96, 0xe5, 0xf6, 0x1f, 0x94, 0x30, 0x1c, 0x34, 0x1, 0xfd, 0xe6, 0xdc, 0x26, 0x4b,
                0x58, 0x59, 0x7f, 0x17, 0xdb, 0xe7, 0x4, 0x9f, 0x70, 0x4f, 0xf9, 0x1b, 0xb6, 0x2,
                0xf6, 0xdc, 0xa3, 0x4b, 0x94, 0xfa, 0xf8, 0x2d, 0xed, 0xf5, 0x83, 0xf0, 0x1a, 0x28,
                0x94, 0xe2, 0x62, 0xf2, 0x1d, 0x3c, 0x5d, 0x40, 0xab, 0x6, 0x7, 0xb2, 0x7f, 0x30,
                0x1f, 0xab, 0x93, 0x6d, 0x57, 0xc, 0x94, 0x6e, 0xf7, 0x7f, 0xf9, 0xd7, 0xf7, 0x7f,
                0x95, 0x44, 0x14, 0x0, 0x1d, 0x1a, 0x4b, 0xfe, 0x19, 0xe3
            ]
        );

        // long sequence with long label
        let mut sho = ShoSha256::new(&block64);
        sho.pad_block();
        sho.squeeze(64);
        sho.squeeze(17);
        sho.absorb(&block31);
        sho.pad_block();
        sho.absorb(&block32);
        sho.squeeze(128);
        sho.absorb(&block33);
        sho.squeeze(32);
        sho.absorb(&block31);
        sho.absorb(&block31);
        sho.pad_block();
        sho.pad_block();
        sho.absorb(&block32);
        sho.absorb(&block32);
        sho.squeeze(1);
        sho.absorb(&block63);
        sho.squeeze(33);
        sho.squeeze(31);
        sho.absorb(&block64);
        sho.squeeze(1025);
        sho.absorb(&block65);
        sho.squeeze(63);
        sho.absorb(&[0u8]);
        let out = sho.squeeze(15);
        assert!(
            out == vec![
                0x61, 0x6d, 0x7b, 0x38, 0xcf, 0xcf, 0xf8, 0x72, 0x70, 0x9d, 0x7f, 0xf5, 0x90, 0x9b,
                0xde
            ]
        );
    }
}
