//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Utilities for exporting backups.
//!
//! See `encrypt_backup` or `generation/mod.rs` for how they fit together.

use aes::cipher::{BlockEncryptMut as _, BlockSizeUser as _, KeyIvInit as _};
use async_compression::futures::bufread::GzipEncoder;
use futures::{AsyncBufRead, AsyncReadExt as _};
use hmac::Mac as _;
use sha2::Sha256;

use crate::frame::{AES_IV_SIZE, AES_KEY_SIZE};

pub fn gzip_compress<R: AsyncBufRead + Unpin>(contents: R) -> Vec<u8> {
    let mut compressed_contents = Vec::new();
    futures::executor::block_on(GzipEncoder::new(contents).read_to_end(&mut compressed_contents))
        .expect("failed to compress");

    compressed_contents
}

pub fn pad_gzipped_bucketed(out: &mut Vec<u8>) {
    let len = u32::try_from(out.len()).expect("backup < 4GB");
    out.resize(
        crate::padded_length(len).try_into().expect("usize >= u32"),
        0,
    );
}

/// Encrypts `contents` in-place.
pub fn aes_cbc_encrypt(
    aes_key: &[u8; AES_KEY_SIZE],
    iv: &[u8; AES_IV_SIZE],
    contents: &mut Vec<u8>,
) {
    let len_to_encrypt = contents.len();
    // Leave room for Pkcs7 padding.
    contents.resize(len_to_encrypt + aes::Aes256::block_size(), 0);
    let encryptor = cbc::Encryptor::<aes::Aes256>::new(aes_key.into(), iv.into());
    let len_encrypted = encryptor
        .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut *contents, len_to_encrypt)
        .expect("provided enough room for padding")
        .len();
    contents.truncate(len_encrypted);
}

pub fn hmac_checksum(
    hmac_key: &[u8; 32],
    iv: &[u8; AES_IV_SIZE],
    encrypted_contents: &[u8],
) -> [u8; 32] {
    let mut hmac =
        hmac::Hmac::<Sha256>::new_from_slice(hmac_key.as_slice()).expect("correct key size");
    hmac.update(iv);
    hmac.update(encrypted_contents);
    hmac.finalize().into_bytes().into()
}
