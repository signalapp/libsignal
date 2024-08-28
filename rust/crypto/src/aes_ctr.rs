//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use aes::cipher::typenum::Unsigned;
use aes::cipher::{InnerIvInit, KeyInit, StreamCipher, StreamCipherSeek};
use aes::Aes256;

use crate::error::{Error, Result};

/// A wrapper around [`ctr::Ctr32BE`] that uses a smaller nonce and supports an initial counter.
pub struct Aes256Ctr32(ctr::Ctr32BE<Aes256>);

impl Aes256Ctr32 {
    pub const NONCE_SIZE: usize = <Aes256 as aes::cipher::BlockSizeUser>::BlockSize::USIZE - 4;

    pub fn new(aes256: Aes256, nonce: &[u8], init_ctr: u32) -> Result<Self> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::InvalidNonceSize);
        }

        let mut nonce_block = [0u8; <Aes256 as aes::cipher::BlockSizeUser>::BlockSize::USIZE];
        nonce_block[0..Self::NONCE_SIZE].copy_from_slice(nonce);

        let mut ctr =
            ctr::Ctr32BE::from_core(ctr::CtrCore::inner_iv_init(aes256, &nonce_block.into()));
        ctr.seek(
            (<Aes256 as aes::cipher::BlockSizeUser>::BlockSize::USIZE as u64) * (init_ctr as u64),
        );

        Ok(Self(ctr))
    }

    pub fn from_key(key: &[u8], nonce: &[u8], init_ctr: u32) -> Result<Self> {
        Self::new(
            Aes256::new_from_slice(key).map_err(|_| Error::InvalidKeySize)?,
            nonce,
            init_ctr,
        )
    }

    pub fn process(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }
}
