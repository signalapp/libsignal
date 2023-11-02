use std::ops::{Add, AddAssign, Mul, MulAssign};

use rand::{CryptoRng, Rng};
use subtle::{Choice, ConstantTimeEq};

// Ring of GF256^32 with pointwise addition and multiplication, adapted from https://github.com/dsprenkels/sss
// The 8-bit field elements are packed into a [u32;8] to operate with 32-bit arithmetic.

#[derive(Clone, Debug, Copy)]
pub struct RingElt {
    data: [u32; 8],
}

/***
 * `bitslice` transforms 32 8-bit bytes into 8 32-bit words, but not through simple reinterprestation
 * we would get from casting a C-style array.
 *
 * Rather, the `i`-th bit of the `j`-th byte becomes the `j`-th bit of the `i`-th byte.
 *
 *             ┌─┐
 *  x x x x x x│x│x x x x x x x x x x x x x x x x x x x x x x x x x
 *             │ │
 *  x x x x x x│x│x x x x x x x x x x x x x x x x x x x x x x x x x   Output
 * ┌───────────┼─┼─────────────────────────────────────────────────┐  byte 2
 * │x x x x x x│x│x x x x x x x x x x x x x x x x x x x x x x x x x│◄────
 * └───────────┼─┼─────────────────────────────────────────────────┘
 *  x x x x x x│x│x x x x x x x x x x x x x x x x x x x x x x x x x
 *             │ │
 *  x x x x x x│x│x x x x x x x x x x x x x x x x x x x x x x x x x
 *             │ │
 *  x x x x x x│x│x x x x x x x x x x x x x x x x x x x x x x x x x
 *             │ │
 *  x x x x x x│x│x x x x x x x x x x x x x x x x x x x x x x x x x
 *             │ │
 *  x x x x x x│x│x x x x x x x x x x x x x x x x x x x x x x x x x
 *             └─┘
 *              ▲
 *              │
 *         Input byte 6
 *
 * This allows us to use machine unsigned arithmetic on `u32`s to perform SIMD field operations
 * on 32 8-bit elements of GF(256).
 */
#[allow(clippy::needless_range_loop)]
pub fn bitslice(bytes: &[u8; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    for arr_idx in 0..32 {
        let cur = bytes[arr_idx] as u32;
        for bit_idx in 0..8 {
            result[bit_idx] |= ((cur >> bit_idx) & 1) << arr_idx;
        }
    }
    result
}

#[allow(clippy::needless_range_loop)]
pub fn unbitslice(words: [u32; 8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for bit_idx in 0..8 {
        let cur = words[bit_idx];
        for arr_idx in 0..32 {
            result[arr_idx] |= (((cur >> arr_idx) & 1) << bit_idx) as u8;
        }
    }
    result
}

#[inline(always)]
fn gf256v32_mul(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
    let mut a2 = a;
    let mut r = [0u32; 8];
    // zero out r
    for i in 0..8 {
        // add
        for j in 0..8 {
            r[j] ^= a2[(8 - i + j) % 8] & b[i]
        }

        // reduce mod x^8 + x^4 + x^3 + x + 1
        a2[(8 - i) % 8] ^= a2[(15 - i) % 8]; /* reduce */
        a2[(8 + 2 - i) % 8] ^= a2[(15 - i) % 8];
        a2[(8 + 3 - i) % 8] ^= a2[(15 - i) % 8];
    }
    r
}

fn gf256v32_square(x: [u32; 8]) -> [u32; 8] {
    let mut r = [0u32; 8];
    let mut r8 = x[4];
    let mut r10 = x[5];
    let r12 = x[6];
    let r14 = x[7];
    r[6] = x[3];
    r[4] = x[2];
    r[2] = x[1];
    r[0] = x[0];

    /* Reduce with  x^8 + x^4 + x^3 + x + 1 until order is less than 8 */
    r[7] = r14; /* r[7] was 0 */
    r[6] ^= r14;
    r10 ^= r14;
    /* Skip, because r13 is always 0 */
    r[4] ^= r12;
    r[5] = r12; /* r[5] was 0 */
    r[7] ^= r12;
    r8 ^= r12;
    /* Skip, because r11 is always 0 */
    r[2] ^= r10;
    r[3] = r10; /* r[3] was 0 */
    r[5] ^= r10;
    r[6] ^= r10;
    r[1] = r14; /* r[1] was 0 */
    r[2] ^= r14; /* Substitute r9 by r14 because they will always be equal*/
    r[4] ^= r14;
    r[5] ^= r14;
    r[0] ^= r8;
    r[1] ^= r8;
    r[3] ^= r8;
    r[4] ^= r8;

    r
}

#[inline(always)]
fn gf256v32_inv(x: [u32; 8]) -> [u32; 8] {
    let mut y = gf256v32_square(x); // y = x^2
    y = gf256v32_square(y); // y = x^4
    let mut r = gf256v32_square(y); // r = x^8
    let mut z = gf256v32_mul(r, x); // z = x^9
    r = gf256v32_square(r); // r = x^16
    r = gf256v32_mul(r, z); // r = x^25
    r = gf256v32_square(r); // r = x^50
    z = gf256v32_square(r); // z = x^100
    z = gf256v32_square(z); // z = x^200
    r = gf256v32_mul(r, z); // r = x^250
    r = gf256v32_mul(r, y); // r = x^254

    r
}

impl RingElt {
    pub const ZERO: Self = Self { data: [0u32; 8] };
    pub const ONE: Self = Self {
        data: [0xffffffffu32, 0, 0, 0, 0, 0, 0, 0],
    };

    pub fn new(data: [u32; 8]) -> Self {
        RingElt { data }
    }

    pub fn bitslice(data: &[u8; 32]) -> Self {
        RingElt {
            data: bitslice(data),
        }
    }

    pub fn unbitslice(&self) -> [u8; 32] {
        unbitslice(self.data)
    }

    pub fn random<R: CryptoRng + Rng>(rng: &mut R) -> RingElt {
        let mut data = [0u8; 32];
        rng.fill_bytes(&mut data);
        RingElt::new(bitslice(&data))
    }

    pub fn repeated_field_elt(x: u8) -> Self {
        let mut data = [0u32; 8];
        let x32: u32 = x.into();
        for (idx, byte) in data.iter_mut().enumerate() {
            *byte = ((((x32 & (1 << idx)) << (31 - idx)) as i32) >> 31) as u32;
        }
        RingElt { data }
    }

    pub fn square(&self) -> Self {
        RingElt {
            data: gf256v32_square(self.data),
        }
    }

    pub fn square_assign(&mut self) {
        self.data = gf256v32_square(self.data);
    }

    pub fn inv(&self) -> Self {
        RingElt {
            data: gf256v32_inv(self.data),
        }
    }

    pub fn inv_assign(&mut self) {
        self.data = gf256v32_inv(self.data);
    }

    // TODO make equals constant time
}

impl ConstantTimeEq for RingElt {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.data.ct_eq(&rhs.data)
    }
}

impl PartialEq for RingElt {
    fn eq(&self, rhs: &Self) -> bool {
        self.ct_eq(rhs).into()
    }
}

impl Eq for RingElt {}

impl Add<RingElt> for RingElt {
    type Output = RingElt;

    fn add(self, rhs: RingElt) -> Self::Output {
        let mut lhs = self;
        lhs += rhs;
        lhs
    }
}

impl AddAssign<RingElt> for RingElt {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: RingElt) {
        for (lhs, rhs) in std::iter::zip(self.data.iter_mut(), rhs.data) {
            *lhs ^= rhs;
        }
    }
}

impl Mul<RingElt> for RingElt {
    type Output = RingElt;
    fn mul(self, rhs: RingElt) -> Self::Output {
        RingElt {
            data: gf256v32_mul(self.data, rhs.data),
        }
    }
}

impl MulAssign<RingElt> for RingElt {
    fn mul_assign(&mut self, rhs: RingElt) {
        self.data = gf256v32_mul(self.data, rhs.data);
    }
}

impl From<[u32; 8]> for RingElt {
    fn from(bitsliced: [u32; 8]) -> Self {
        RingElt { data: bitsliced }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    fn repeat_u8_to_u32(u: u8) -> u32 {
        let mut result: u32 = u.into();
        for i in 1..4 {
            result += (1u32 << (8 * i)) * Into::<u32>::into(u);
        }
        result
    }

    fn repeat_u8(u: u8) -> [u32; 8] {
        [repeat_u8_to_u32(u); 8]
    }

    #[test]
    fn test_gf256_add() {
        let a = RingElt::new(repeat_u8(170));
        let b = RingElt::new(repeat_u8(85));

        let c = a + b;
        let should_be_zero = a + a;

        assert_eq!(c.data, repeat_u8(255u8));
        assert_eq!(should_be_zero, RingElt::ZERO);
    }

    #[test]
    fn test_gf256_mul() {
        let a = RingElt::new([0u32, 0, 1, 0, 0, 0, 0, 0]);
        let b = RingElt::new([0u32, 0, 0, 0, 0, 0, 0, 1]);

        let c = a * b;
        assert_eq!(c.data, [0u32, 1, 1, 0, 1, 1, 0, 0]);
    }

    #[test]
    fn test_gf256_inv() {
        let a = RingElt::new([0xffffffffu32, 0x02020202, 3, 4, 5, 6, 7, 0x11111111u32]);
        let b = a.inv();
        let c = a * b;
        assert_eq!(c.data, [0xffffffffu32, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(c, RingElt::ONE);
    }

    #[test]
    fn test_from_bitsliced() {
        let data = [0xffffffffu32, 0x02020202, 3, 4, 5, 6, 7, 0x11111111u32];
        let a = RingElt::new(data);
        let b: RingElt = RingElt::from(data);
        assert_eq!(a, b);
    }

    #[test]
    fn test_repeated_field_elt() {
        let threes = RingElt::repeated_field_elt(3u8);
        assert_eq!(
            threes,
            RingElt::new([0xffffffffu32, 0xffffffff, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(threes.data, bitslice(&[3u8; 32]));
    }

    #[test]
    fn test_bitslice() {
        let mut rng = rand_core::OsRng;
        for _ in 0..10 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            let sliced = bitslice(&bytes);
            let unsliced = unbitslice(sliced);
            assert_eq!(bytes, unsliced);
        }
    }
}
