//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::error::{Error, Result};
use aes::cipher::{FromBlockCipher, StreamCipher, StreamCipherSeek};
use aes::{Aes256, NewBlockCipher};

/// A wrapper around [`aes::Aes256Ctr`] that uses a smaller nonce and supports an initial counter.
pub struct Aes256Ctr32(aes::Aes256Ctr);

impl Aes256Ctr32 {
    pub const CTR_NONCE_SIZE: usize = aes::BLOCK_SIZE - 4;

    const NONCE_SIZE: usize = Self::CTR_NONCE_SIZE;

    pub fn new(aes256: Aes256, nonce: &[u8], init_ctr: u32) -> Result<Self> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::InvalidNonceSize);
        }

        let mut nonce_block = [0u8; aes::BLOCK_SIZE];
        nonce_block[0..Self::NONCE_SIZE].copy_from_slice(nonce);

        let mut ctr = aes::Aes256Ctr::from_block_cipher(aes256, &nonce_block.into());
        ctr.seek((aes::BLOCK_SIZE as u64) * (init_ctr as u64));

        Ok(Self(ctr))
    }

    pub fn from_key(key: &[u8], nonce: &[u8], init_ctr: u32) -> Result<Self> {
        Self::new(
            Aes256::new_from_slice(key).map_err(|_| Error::InvalidKeySize)?,
            nonce,
            init_ctr,
        )
    }

    pub fn process(&mut self, buf: &mut [u8]) -> Result<()> {
        self.0.apply_keystream(buf);
        Ok(())
    }
}
