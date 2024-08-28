//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use ghash::universal_hash::UniversalHash;
use ghash::GHash;
use subtle::ConstantTimeEq;

use crate::{Aes256Ctr32, Error, Result};

pub const TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;

#[derive(Clone)]
struct GcmGhash {
    ghash: GHash,
    ghash_pad: [u8; TAG_SIZE],
    msg_buf: [u8; TAG_SIZE],
    msg_buf_offset: usize,
    ad_len: usize,
    msg_len: usize,
}

impl GcmGhash {
    fn new(h: &[u8; TAG_SIZE], ghash_pad: [u8; TAG_SIZE], associated_data: &[u8]) -> Result<Self> {
        let mut ghash = GHash::new(h.into());

        ghash.update_padded(associated_data);

        Ok(Self {
            ghash,
            ghash_pad,
            msg_buf: [0u8; TAG_SIZE],
            msg_buf_offset: 0,
            ad_len: associated_data.len(),
            msg_len: 0,
        })
    }

    fn update(&mut self, msg: &[u8]) {
        if self.msg_buf_offset > 0 {
            let taking = std::cmp::min(msg.len(), TAG_SIZE - self.msg_buf_offset);
            self.msg_buf[self.msg_buf_offset..self.msg_buf_offset + taking]
                .copy_from_slice(&msg[..taking]);
            self.msg_buf_offset += taking;
            assert!(self.msg_buf_offset <= TAG_SIZE);

            self.msg_len += taking;

            if self.msg_buf_offset == TAG_SIZE {
                self.ghash
                    .update(std::slice::from_ref(ghash::Block::from_slice(
                        &self.msg_buf,
                    )));
                self.msg_buf_offset = 0;
                return self.update(&msg[taking..]);
            } else {
                return;
            }
        }

        self.msg_len += msg.len();

        assert_eq!(self.msg_buf_offset, 0);
        let full_blocks = msg.len() / 16;
        let leftover = msg.len() - 16 * full_blocks;
        assert!(leftover < TAG_SIZE);
        if full_blocks > 0 {
            // Transmute [u8] to [[u8; 16]], like slice::as_chunks.
            // Then transmute [[u8; 16]] to [GenericArray<U16>], per repr(transparent).
            let blocks = unsafe {
                std::slice::from_raw_parts(msg[..16 * full_blocks].as_ptr().cast(), full_blocks)
            };
            assert_eq!(
                std::mem::size_of_val(blocks) + leftover,
                std::mem::size_of_val(msg)
            );
            self.ghash.update(blocks);
        }

        self.msg_buf[0..leftover].copy_from_slice(&msg[full_blocks * 16..]);
        self.msg_buf_offset = leftover;
        assert!(self.msg_buf_offset < TAG_SIZE);
    }

    fn finalize(mut self) -> [u8; TAG_SIZE] {
        if self.msg_buf_offset > 0 {
            self.ghash
                .update_padded(&self.msg_buf[..self.msg_buf_offset]);
        }

        let mut final_block = [0u8; 16];
        final_block[..8].copy_from_slice(&(8 * self.ad_len as u64).to_be_bytes());
        final_block[8..].copy_from_slice(&(8 * self.msg_len as u64).to_be_bytes());

        self.ghash.update(&[final_block.into()]);
        let mut hash = self.ghash.finalize();

        for (i, b) in hash.iter_mut().enumerate() {
            *b ^= self.ghash_pad[i];
        }

        hash.into()
    }
}

fn setup_gcm(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<(Aes256Ctr32, GcmGhash)> {
    /*
    GCM supports other sizes but 12 bytes is standard and other
    sizes require special handling
     */
    if nonce.len() != NONCE_SIZE {
        return Err(Error::InvalidNonceSize);
    }

    let aes256 = Aes256::new_from_slice(key).map_err(|_| Error::InvalidKeySize)?;
    let mut h = [0u8; TAG_SIZE];
    aes256.encrypt_block(GenericArray::from_mut_slice(&mut h));

    let mut ctr = Aes256Ctr32::new(aes256, nonce, 1)?;

    let mut ghash_pad = [0u8; 16];
    ctr.process(&mut ghash_pad);

    let ghash = GcmGhash::new(&h, ghash_pad, associated_data)?;
    Ok((ctr, ghash))
}

pub struct Aes256GcmEncryption {
    ctr: Aes256Ctr32,
    ghash: GcmGhash,
}

impl Aes256GcmEncryption {
    pub const TAG_SIZE: usize = TAG_SIZE;
    pub const NONCE_SIZE: usize = NONCE_SIZE;

    pub fn new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<Self> {
        let (ctr, ghash) = setup_gcm(key, nonce, associated_data)?;
        Ok(Self { ctr, ghash })
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) {
        self.ctr.process(buf);
        self.ghash.update(buf);
    }

    pub fn compute_tag(self) -> [u8; TAG_SIZE] {
        self.ghash.finalize()
    }
}

pub struct Aes256GcmDecryption {
    ctr: Aes256Ctr32,
    ghash: GcmGhash,
}

impl Aes256GcmDecryption {
    pub const TAG_SIZE: usize = TAG_SIZE;
    pub const NONCE_SIZE: usize = NONCE_SIZE;

    pub fn new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<Self> {
        let (ctr, ghash) = setup_gcm(key, nonce, associated_data)?;
        Ok(Self { ctr, ghash })
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) {
        self.ghash.update(buf);
        self.ctr.process(buf);
    }

    pub fn verify_tag(self, tag: &[u8]) -> Result<()> {
        if tag.len() != TAG_SIZE {
            return Err(Error::InvalidTag);
        }

        let computed_tag = self.ghash.finalize();

        let tag_ok = tag.ct_eq(&computed_tag);

        if !bool::from(tag_ok) {
            return Err(Error::InvalidTag);
        }

        Ok(())
    }
}
