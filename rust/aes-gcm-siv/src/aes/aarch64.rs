//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::error::{Error, Result};

use core::arch::aarch64::*;
use std::convert::TryInto;

unsafe fn se_word(x: u32) -> u32 {
    let x4 = [x, x, x, x]; // vdupq_n_u32
    let a = vld1q_u8(x4.as_ptr() as *const u8);
    let zero = vdupq_n_u8(0);
    let sa = vaeseq_u8(a, zero);
    vgetq_lane_u32(std::mem::transmute(sa), 0)
}

pub struct Aes256Aarch64 {
    ek: [u32; 60],
}

impl Aes256Aarch64 {
    pub unsafe fn new(key: &[u8]) -> Result<Aes256Aarch64> {
        if key.len() != 32 {
            return Err(Error::InvalidKeySize);
        }

        let rcon: [u32; 10] = [
            0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
            0x80000000, 0x1B000000, 0x36000000,
        ];

        let mut ek: [u32; 60] = [0; 60];

        let x = 32 / 4;

        for i in 0..x {
            ek[i] = u32::from_be_bytes(key[(i * 4)..(i * 4 + 4)].try_into().expect("correct size"));
        }

        for i in (x..60).step_by(x) {
            ek[i] = ek[i - x] ^ rcon[(i - x) / x] ^ se_word(ek[i - 1]).rotate_left(8);

            for j in 1..x {
                if i + j < ek.len() {
                    ek[i + j] = ek[i + j - x];

                    if j == 4 {
                        ek[i + j] ^= se_word(ek[i + j - 1]);
                    } else {
                        ek[i + j] ^= ek[i + j - 1];
                    }
                }
            }
        }

        for k in &mut ek {
            *k = k.swap_bytes();
        }

        Ok(Self { ek })
    }

    #[target_feature(enable = "crypto")]
    pub unsafe fn encrypt(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() % 16 != 0 {
            return Err(Error::InvalidInputSize);
        }

        let kp = self.ek.as_ptr() as *const u8;
        let k0 = vld1q_u8(kp.offset(0));
        let k1 = vld1q_u8(kp.offset(16));
        let k2 = vld1q_u8(kp.offset(16 * 2));
        let k3 = vld1q_u8(kp.offset(16 * 3));
        let k4 = vld1q_u8(kp.offset(16 * 4));
        let k5 = vld1q_u8(kp.offset(16 * 5));
        let k6 = vld1q_u8(kp.offset(16 * 6));
        let k7 = vld1q_u8(kp.offset(16 * 7));
        let k8 = vld1q_u8(kp.offset(16 * 8));
        let k9 = vld1q_u8(kp.offset(16 * 9));
        let k10 = vld1q_u8(kp.offset(16 * 10));
        let k11 = vld1q_u8(kp.offset(16 * 11));
        let k12 = vld1q_u8(kp.offset(16 * 12));
        let k13 = vld1q_u8(kp.offset(16 * 13));
        let k14 = vld1q_u8(kp.offset(16 * 14));

        let unroll_to = 4 * 16;

        for blocks in buf.chunks_mut(unroll_to) {
            if blocks.len() == unroll_to {
                let buf_ptr = blocks.as_mut_ptr();
                let mut b0 = vld1q_u8(buf_ptr);
                let mut b1 = vld1q_u8(buf_ptr.offset(16));
                let mut b2 = vld1q_u8(buf_ptr.offset(32));
                let mut b3 = vld1q_u8(buf_ptr.offset(48));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k0));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k0));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k0));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k0));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k1));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k1));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k1));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k1));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k2));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k2));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k2));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k2));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k3));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k3));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k3));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k3));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k4));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k4));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k4));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k4));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k5));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k5));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k5));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k5));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k6));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k6));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k6));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k6));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k7));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k7));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k7));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k7));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k8));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k8));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k8));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k8));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k9));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k9));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k9));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k9));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k10));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k10));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k10));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k10));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k11));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k11));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k11));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k11));

                b0 = vaesmcq_u8(vaeseq_u8(b0, k12));
                b1 = vaesmcq_u8(vaeseq_u8(b1, k12));
                b2 = vaesmcq_u8(vaeseq_u8(b2, k12));
                b3 = vaesmcq_u8(vaeseq_u8(b3, k12));

                b0 = veorq_u8(vaeseq_u8(b0, k13), k14);
                b1 = veorq_u8(vaeseq_u8(b1, k13), k14);
                b2 = veorq_u8(vaeseq_u8(b2, k13), k14);
                b3 = veorq_u8(vaeseq_u8(b3, k13), k14);

                let b0: [u8; 16] = std::mem::transmute(b0);
                let b1: [u8; 16] = std::mem::transmute(b1);
                let b2: [u8; 16] = std::mem::transmute(b2);
                let b3: [u8; 16] = std::mem::transmute(b3);
                buf_ptr.copy_from_nonoverlapping(b0.as_ptr(), 16);
                buf_ptr.offset(16).copy_from_nonoverlapping(b1.as_ptr(), 16);
                buf_ptr.offset(32).copy_from_nonoverlapping(b2.as_ptr(), 16);
                buf_ptr.offset(48).copy_from_nonoverlapping(b3.as_ptr(), 16);
            } else {
                // handle any partial trailing blocks
                for block in blocks.chunks_mut(16) {
                    let buf_ptr = block.as_mut_ptr();
                    let mut b0 = vld1q_u8(buf_ptr);

                    b0 = vaesmcq_u8(vaeseq_u8(b0, k0));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k1));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k2));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k3));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k4));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k5));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k6));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k7));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k8));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k9));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k10));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k11));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k12));
                    b0 = veorq_u8(vaeseq_u8(b0, k13), k14);

                    // Missing store instructions wtf
                    let b0: [u8; 16] = std::mem::transmute(b0);
                    buf_ptr.copy_from_nonoverlapping(b0.as_ptr(), 16);
                }
            }
        }

        Ok(())
    }
}
