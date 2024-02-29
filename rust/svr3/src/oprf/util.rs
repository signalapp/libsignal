//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::cmp;
use std::convert::{TryFrom, TryInto};

use super::errors::OPRFError;
use sha2::{Digest, Sha512};

const SHA512_BLOCK_BYTES: usize = 128usize;
const SHA512_OUTPUT_BYTES: usize = 64usize;

pub fn i2osp_u8(n: u8) -> [u8; 1] {
    n.to_be_bytes()
}

pub fn i2osp_u16(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

fn block_xor(
    lhs: [u8; SHA512_OUTPUT_BYTES],
    rhs: [u8; SHA512_OUTPUT_BYTES],
) -> [u8; SHA512_OUTPUT_BYTES] {
    let mut result = [0u8; SHA512_OUTPUT_BYTES];
    for i in 0..SHA512_OUTPUT_BYTES {
        result[i] = lhs[i] ^ rhs[i];
    }
    result
}

pub fn expand_message_xmd_sha512(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: u16,
    result: &mut [u8],
) -> Result<(), OPRFError> {
    if len_in_bytes == 0 || usize::from(len_in_bytes) != result.len() {
        return Err(OPRFError::ExpandMessageError);
    }

    let b_in_bytes: u16 = SHA512_OUTPUT_BYTES.try_into().unwrap();
    let ell = u8::try_from((len_in_bytes + b_in_bytes - 1) / b_in_bytes)
        .map_err(|_| OPRFError::ExpandMessageError)?;
    let l_i_b_arr = i2osp_u16(len_in_bytes);
    let z_pad = [0u8; SHA512_BLOCK_BYTES];
    let zero_byte = [0u8];

    // msg_prime = z_pad + msg + l_i_b_str + I2OSP(0,1) + dst_prime
    let b0_hasher = Sha512::new();
    let b0: [u8; SHA512_OUTPUT_BYTES] = b0_hasher
        .chain_update(z_pad)
        .chain_update(msg)
        .chain_update(l_i_b_arr)
        .chain_update(zero_byte)
        .chain_update(dst)
        .chain_update(i2osp_u8(dst.len().try_into().unwrap()))
        .finalize()
        .into();

    let b1_hasher = Sha512::new();
    let b1: [u8; SHA512_OUTPUT_BYTES] = b1_hasher
        .chain_update(b0)
        .chain_update([1u8])
        .chain_update(dst)
        .chain_update(i2osp_u8(dst.len().try_into().unwrap()))
        .finalize()
        .into();

    let bytes_to_copy = cmp::min(SHA512_OUTPUT_BYTES, usize::from(len_in_bytes));
    result[0..bytes_to_copy].copy_from_slice(&b1[0..bytes_to_copy]);
    let mut b_last = b1;
    for i in 2..=ell {
        let hasher = Sha512::new();
        let b_next: [u8; SHA512_OUTPUT_BYTES] = hasher
            .chain_update(block_xor(b0, b_last))
            .chain_update([i])
            .chain_update(dst)
            .chain_update(i2osp_u8(dst.len().try_into().unwrap()))
            .finalize()
            .into();

        let offset = usize::from(i - 1) * SHA512_OUTPUT_BYTES;
        let bytes_to_copy = cmp::min(SHA512_OUTPUT_BYTES, usize::from(len_in_bytes) - offset);
        result[offset..offset + bytes_to_copy].copy_from_slice(&b_next[0..bytes_to_copy]);
        b_last.copy_from_slice(&b_next);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    #[test]
    fn expand_message_xmd_1() {
        let dst = "QUUX-V01-CS02-with-expander-SHA512-256";
        let msg = "abc";
        let len_in_bytes = 0x80u16;
        let mut uniform_bytes = [0u8; 0x80];
        super::expand_message_xmd_sha512(
            msg.as_bytes(),
            dst.as_bytes(),
            len_in_bytes,
            &mut uniform_bytes,
        )
        .expect("expand failed");
        assert_eq!(uniform_bytes, hex!("
    7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b488431851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1
    "));
    }

    #[test]
    fn expand_message_xmd_2() {
        let dst = "QUUX-V01-CS02-with-expander-SHA512-256";
        let msg = "abcdef0123456789";
        let len_in_bytes = 0x20u16;
        let mut uniform_bytes = [0u8; 0x20];
        super::expand_message_xmd_sha512(
            msg.as_bytes(),
            dst.as_bytes(),
            len_in_bytes,
            &mut uniform_bytes,
        )
        .expect("expand failed");
        assert_eq!(
            uniform_bytes,
            hex!(
                "
      087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58
      "
            )
        );
    }
}
