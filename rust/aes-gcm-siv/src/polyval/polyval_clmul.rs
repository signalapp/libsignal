//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::error::{Error, Result};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[derive(Clone)]
pub struct PolyvalClmul {
    h: __m128i,
    s: __m128i,
}

impl PolyvalClmul {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(Error::InvalidKeySize);
        }

        unsafe {
            Ok(Self {
                h: _mm_loadu_si128(key.as_ptr() as *const __m128i),
                s: _mm_setzero_si128(),
            })
        }
    }

    #[target_feature(enable = "pclmulqdq")]
    unsafe fn process_block(&mut self, chunk: *const u8) {
        let poly = _mm_set_epi32(-0x3e000000, 0, 0, 0);

        let h = self.h;

        let input = _mm_loadu_si128(chunk as *const __m128i);
        let t = _mm_xor_si128(self.s, input);

        /*
        https://blog.quarkslab.com/reversing-a-finite-field-multiplication-optimization.html
        https://www.intel.com/content/dam/www/public/us/en/documents/software-support/enabling-high-performance-gcm.pdf
         */
        let pm = _mm_xor_si128(
            _mm_clmulepi64_si128(t, h, 0x01),
            _mm_clmulepi64_si128(t, h, 0x10),
        );

        let pl = _mm_clmulepi64_si128(t, h, 0x00);
        let ph = _mm_clmulepi64_si128(t, h, 0x11);

        let t0 = _mm_xor_si128(_mm_slli_si128(pm, 8), pl);
        let t1 = _mm_xor_si128(_mm_srli_si128(pm, 8), ph);

        let r0 = _mm_xor_si128(
            _mm_shuffle_epi32(t0, 0x4E),
            _mm_clmulepi64_si128(t0, poly, 0x10),
        );
        let r1 = _mm_xor_si128(
            _mm_shuffle_epi32(r0, 0x4E),
            _mm_clmulepi64_si128(r0, poly, 0x10),
        );

        self.s = _mm_xor_si128(t1, r1);
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
