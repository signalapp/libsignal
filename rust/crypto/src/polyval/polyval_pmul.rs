//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::error::{Error, Result};

use core::arch::aarch64::*;

use std::mem::transmute as cast;

#[derive(Clone)]
pub struct PolyvalPmul {
    h: uint8x16_t,
    s: uint8x16_t,
}

unsafe fn swap_halves(x: uint8x16_t) -> uint8x16_t {
    // Equivalent of _mm_shuffle_epi32(x, _MM_SHUFFLE(1,0,3,2))

    let hi = vgetq_lane_u64(cast(x), 1);
    let lo = vgetq_lane_u64(cast(x), 0);
    cast(vcombine_u64(cast(hi), cast(lo)))
}

impl PolyvalPmul {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(Error::InvalidKeySize);
        }

        unsafe {
            Ok(Self {
                h: vld1q_u8(key.as_ptr()),
                s: vdupq_n_u8(0),
            })
        }
    }

    #[target_feature(enable = "crypto")]
    unsafe fn process_block(&mut self, chunk: *const u8) {
        let poly: poly64_t = cast(0xc200000000000000u64);

        let h = self.h;

        let h0 = vgetq_lane_u64(cast(h), 0);
        let h1 = vgetq_lane_u64(cast(h), 1);

        let input = vld1q_u8(chunk);
        let t = veorq_u8(self.s, input);

        let t0 = vgetq_lane_u64(cast(t), 0);
        let t1 = vgetq_lane_u64(cast(t), 1);

        let pl: uint8x16_t = cast(vmull_p64(cast(t0), cast(h0)));
        let ph: uint8x16_t = cast(vmull_p64(cast(t1), cast(h1)));

        let pm = veorq_u8(
            cast(vmull_p64(cast(t0), cast(h1))),
            cast(vmull_p64(cast(t1), cast(h0))),
        );

        let t0 = veorq_u8(vextq_u8(vdupq_n_u8(0), pm, 8), pl);
        let t1 = veorq_u8(vextq_u8(pm, vdupq_n_u8(0), 8), ph);

        let rp0: uint8x16_t = cast(vmull_p64(cast(vgetq_lane_u64(cast(t0), 0)), poly));
        let r0 = veorq_u8(swap_halves(t0), rp0);

        let rp1: uint8x16_t = cast(vmull_p64(cast(vgetq_lane_u64(cast(r0), 0)), poly));
        let r1 = veorq_u8(swap_halves(r0), rp1);

        self.s = veorq_u8(t1, r1);
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        assert_eq!(data.len() % 16, 0);

        unsafe {
            for chunk in data.chunks_exact(16) {
                self.process_block(chunk.as_ptr())
            }
        }
        Ok(())
    }

    pub fn update_padded(&mut self, data: &[u8]) -> Result<()> {
        let full_blocks = data.len() / 16;
        let remainder = data.len() % 16;

        self.update(&data[0..full_blocks * 16])?;

        if remainder > 0 {
            let mut rembytes = [0u8; 16];
            rembytes[0..remainder].copy_from_slice(&data[full_blocks * 16..]);
            self.update(&rembytes)?;
        }
        Ok(())
    }

    pub fn finalize(self) -> Result<[u8; 16]> {
        Ok(unsafe { std::mem::transmute(self.s) })
    }
}
