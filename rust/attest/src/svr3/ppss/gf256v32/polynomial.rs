use rand::{CryptoRng, Rng};
use std::ops::{Add, AddAssign, Mul, MulAssign};

use crate::svr3::ppss::gf256v32::ring_ops::RingElt;

// Polynomials over the ring GF256^32 with coordinatewise arithmetic.

#[derive(Clone, Debug, Copy)]
pub struct Polynomial<const N: usize> {
    coeffs: [RingElt; N],
}

impl<const N: usize> Polynomial<N> {
    pub const ZERO: Self = Self {
        coeffs: [RingElt::ZERO; N],
    };

    pub fn new(coeffs: [RingElt; N]) -> Self {
        Polynomial { coeffs }
    }

    pub const ONE: Self = {
        let mut coeffs = [RingElt::ZERO; N];
        coeffs[0] = RingElt::ONE;
        Polynomial { coeffs }
    };

    pub fn random<R: CryptoRng + Rng>(rng: &mut R) -> Polynomial<N> {
        let mut coeffs = [RingElt::ZERO; N];
        for coeff in coeffs.iter_mut() {
            *coeff = RingElt::random(rng);
        }
        Polynomial::new(coeffs)
    }

    pub fn degree(&self) -> i64 {
        let zero = RingElt::ZERO;
        let mut max_nonzero = 0i64;
        for i in 0..N {
            let cond = (self.coeffs[i] != zero) as i64;
            max_nonzero = cond * (i as i64) + (1 - cond) * max_nonzero;
        }
        max_nonzero
    }

    pub fn constant_coefficient(&self) -> RingElt {
        self.coeffs[0]
    }

    pub fn set_constant_coefficient(&mut self, lc: RingElt) {
        self.coeffs[0] = lc;
    }

    pub fn mul_scalar(&self, scalar: RingElt) -> Self {
        let mut result = Self::ZERO;
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i] * scalar;
        }
        result
    }

    pub fn mul_assign_scalar(&mut self, scalar: RingElt) {
        for i in 0..N {
            self.coeffs[i] *= scalar;
        }
    }

    /***
     * Leading coefficient
     */
    pub fn lc(&self) -> RingElt {
        let zero = RingElt::ZERO;
        let mut lc = RingElt::ZERO;
        for i in 0..N {
            let cond = (self.coeffs[i] == zero) as u32;
            let selector = RingElt::new([cond, 0, 0, 0, 0, 0, 0, 0]);
            let selector_plus_one = selector + RingElt::ONE; // selector_plus_one is 0 if cond, one if !cond
            lc = selector * self.coeffs[i] + selector_plus_one * lc;
        }
        lc
    }

    /***
     * Return the (quotient, remainder) when dividing this polynomial by (x - constant_term)
     */
    pub fn div_by_linear(&self, constant_term: RingElt) -> (Self, RingElt) {
        let mut q = Self::ZERO;
        let mut r = *self;

        for i in 0..N - 1 {
            q.coeffs[N - 2 - i] = r.coeffs[N - 1 - i];
            r.coeffs[N - 1 - i] = RingElt::ZERO;
            r.coeffs[N - 2 - i] += q.coeffs[N - 2 - i] * constant_term;
        }

        (q, r.coeffs[0])
    }

    /***
     * Return the (quotient, remainder) when dividing this x^N + this polynomial by (x - constant_term)
     */
    pub fn div_xn_plus_poly_by_linear(&self, constant_term: RingElt) -> (Self, RingElt) {
        assert!(N > 1);
        let mut q = Self::ZERO;
        let mut r = *self;
        q.coeffs[N - 1] = RingElt::ONE;
        r.coeffs[N - 1] += constant_term;
        for i in 0..N - 1 {
            q.coeffs[N - 2 - i] = r.coeffs[N - 1 - i];
            r.coeffs[N - 1 - i] = RingElt::ZERO;
            r.coeffs[N - 2 - i] += q.coeffs[N - 2 - i] * constant_term;
        }

        (q, r.coeffs[0])
    }

    pub fn mul_monic_linear_assign(&mut self, constant_term: RingElt) {
        for i in 0..(N - 1) {
            self.coeffs[N - 1 - i] *= constant_term;
            self.coeffs[N - 1 - i] += self.coeffs[N - 2 - i];
        }
        self.coeffs[0] *= constant_term;
    }

    pub fn eval(&self, x: RingElt) -> RingElt {
        let mut result = self.coeffs[N - 1];
        for i in 0..(N - 1) {
            result *= x;
            result += self.coeffs[N - i - 2];
        }
        result
    }
}

#[inline(always)]
fn poly_add_assign<const N: usize>(lhs: &mut Polynomial<N>, rhs: &Polynomial<N>) {
    for i in 0..N {
        lhs.coeffs[i] += rhs.coeffs[i];
    }
}

impl<const N: usize> Add<Polynomial<N>> for Polynomial<N> {
    type Output = Polynomial<N>;
    fn add(self, rhs: Polynomial<N>) -> Self::Output {
        let mut lhs = self;
        poly_add_assign(&mut lhs, &rhs);
        lhs
    }
}

impl<const N: usize> AddAssign<Polynomial<N>> for Polynomial<N> {
    fn add_assign(&mut self, rhs: Polynomial<N>) {
        poly_add_assign(self, &rhs);
    }
}

/***
 * Performs multiplication modulo x^N. In other words if the degree of the product is too high
 * it discards the high order terms.
 */
impl<const N: usize> Mul<Polynomial<N>> for Polynomial<N> {
    type Output = Polynomial<N>;
    fn mul(self, rhs: Polynomial<N>) -> Self::Output {
        let mut result = Polynomial::ZERO;
        for i in 0..N {
            for j in 0..=i {
                result.coeffs[i] += self.coeffs[i - j] * rhs.coeffs[j];
            }
        }
        result
    }
}

impl<const N: usize> MulAssign<Polynomial<N>> for Polynomial<N> {
    fn mul_assign(&mut self, rhs: Polynomial<N>) {
        let prod = (*self) * rhs;
        self.clone_from(&prod);
    }
}

/**
 * The xs must have the property that xs[i] - xs[j] is multiplicatively invertible in the
 * ring GF_{256}^{32}. In practice we will get this by creating xs as (1..=K).map(|x| RingElt::repeated_field_elt(x))
 */
pub fn lagrange_interpolant<const K: usize>(xs: [RingElt; K], ys: [RingElt; K]) -> Polynomial<K> {
    let mut result = Polynomial::<K>::ZERO;

    let mut supernumerator = Polynomial::<K>::ONE;

    #[allow(clippy::needless_range_loop)]
    for i in 0..K {
        supernumerator.mul_monic_linear_assign(xs[i]);
    }

    for i in 0..K {
        let mut denom = RingElt::ONE;
        let (num, rem) = supernumerator.div_xn_plus_poly_by_linear(xs[i]);
        assert_eq!(rem, RingElt::ZERO);
        for j in 0..K {
            if i != j {
                denom *= xs[i] + xs[j];
            }
        }
        result += num.mul_scalar(ys[i] * denom.inv());
        assert_eq!(num.eval(xs[i]), denom);
        assert_eq!(result.eval(xs[i]), ys[i]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    impl<const N: usize> PartialEq for Polynomial<N> {
        fn eq(&self, other: &Self) -> bool {
            self.coeffs == other.coeffs
        }
    }

    #[test]
    fn test_mul_scalar() {
        let fours = RingElt::new([0u32, 0, 0xffffffff, 0, 0, 0, 0, 0]);
        let twos = RingElt::new([0u32, 0xffffffff, 0, 0, 0, 0, 0, 0]);
        let ones = RingElt::ONE;
        let coeffs = [twos, ones];

        let poly = Polynomial::new(coeffs);
        let twopoly = poly.mul_scalar(twos);

        assert_eq!(twopoly.coeffs[0], fours);
        assert_eq!(twopoly.coeffs[1], twos);
        assert_eq!(twopoly, Polynomial::new([fours, twos]));
    }

    #[test]
    fn test_mul_assign_scalar() {
        let fours = RingElt::new([0u32, 0, 0xffffffff, 0, 0, 0, 0, 0]);
        let twos = RingElt::new([0u32, 0xffffffff, 0, 0, 0, 0, 0, 0]);
        let ones = RingElt::ONE;
        let coeffs = [twos, ones];

        let mut poly = Polynomial::new(coeffs);
        poly.mul_assign_scalar(twos);

        assert_eq!(poly.coeffs[0], fours);
        assert_eq!(poly.coeffs[1], twos);
        assert_eq!(poly, Polynomial::new([fours, twos]));
    }

    #[test]
    fn test_mul() {
        let tens = RingElt::new([0u32, 0xffffffff, 0, 0xffffffff, 0, 0, 0, 0]);
        let fours = RingElt::new([0u32, 0, 0xffffffff, 0, 0, 0, 0, 0]);
        let twos = RingElt::new([0u32, 0xffffffff, 0, 0, 0, 0, 0, 0]);
        let ones = RingElt::ONE;
        let zero = RingElt::ZERO;
        let coeffs0 = [twos, ones, zero, zero];
        let coeffs1 = [twos, fours, zero, zero];

        let a = Polynomial::new(coeffs0);
        let b = Polynomial::new(coeffs1);
        let c = a * b;

        assert_eq!(c, Polynomial::new([fours, tens, fours, zero]));
    }

    #[test]
    fn test_random_mul_associative() {
        let num_tests = 10;
        let mut rng = rand_core::OsRng;
        for _ in 0..num_tests {
            let a = Polynomial::<10>::random(&mut rng);
            let b = Polynomial::<10>::random(&mut rng);
            let c = Polynomial::<10>::random(&mut rng);
            let ab = a * b;
            let bc = b * c;
            let ab_c = ab * c;
            let a_bc = a * bc;
            assert_eq!(ab_c, a_bc);
        }
    }

    #[test]
    fn test_random_mul_distributive() {
        let num_tests = 10;
        let mut rng = rand_core::OsRng;
        for _ in 0..num_tests {
            let a = Polynomial::<10>::random(&mut rng);
            let b = Polynomial::<10>::random(&mut rng);
            let c = Polynomial::<10>::random(&mut rng);
            let ab = a * b;
            let ac = a * c;
            assert_eq!(a * (b + c), ab + ac);
        }
    }

    #[test]
    fn test_div_rem() {
        let fours = RingElt::new([0u32, 0, 0xffffffff, 0, 0, 0, 0, 0]);
        let twos = RingElt::new([0u32, 0xffffffff, 0, 0, 0, 0, 0, 0]);
        let ones = RingElt::ONE;
        let zero = RingElt::ZERO;
        let coeffs0 = [twos, ones, zero, zero];
        let coeffs1 = [twos, fours, zero, zero];

        let a = Polynomial::new(coeffs0);
        let b = Polynomial::new(coeffs1);
        let c = a * b;
        let (q, r) = c.div_by_linear(twos);
        assert_eq!(q, b);
        assert_eq!(r, RingElt::ZERO);
    }

    #[test]
    fn test_random_div_linear() {
        let num_tests = 10;
        let zero = RingElt::ZERO;
        let mut rng = rand_core::OsRng;
        for _ in 0..num_tests {
            let mut a = Polynomial::<10>::random(&mut rng);
            let mut b = Polynomial::<10>::random(&mut rng);
            let c = Polynomial::<10>::new([
                RingElt::random(&mut rng),
                zero,
                zero,
                zero,
                zero,
                zero,
                zero,
                zero,
                zero,
                zero,
            ]);

            // Clear the top bit of a and make b linear monic
            a.coeffs[9] = zero;
            for i in 0..8 {
                b.coeffs[9 - i] = zero;
            }
            b.coeffs[1] = RingElt::new([0xffffffffu32, 0, 0, 0, 0, 0, 0, 0]);

            let ab = a * b;
            let ab_p_c = ab + c;
            let (q, r) = ab_p_c.div_by_linear(b.coeffs[0]);
            assert_eq!(c.coeffs[0], r);
            assert_eq!(q, a);
        }
    }

    #[test]
    fn test_random_mul_monic_linear() {
        let num_tests = 10;
        let zero = RingElt::ZERO;
        let mut rng = rand_core::OsRng;
        for _ in 0..num_tests {
            let mut a = Polynomial::<10>::random(&mut rng);
            let c = Polynomial::<10>::new([
                RingElt::random(&mut rng),
                zero,
                zero,
                zero,
                zero,
                zero,
                zero,
                zero,
                zero,
                zero,
            ]);

            // Clear the top bit of a
            a.coeffs[9] = zero;
            let b_const_term = RingElt::random(&mut rng);

            let mut ab = a;
            ab.mul_monic_linear_assign(b_const_term);

            let ab_p_c = ab + c;
            let (q, r) = ab_p_c.div_by_linear(b_const_term);
            assert_eq!(c.coeffs[0], r);
            assert_eq!(q, a);
        }
    }

    #[test]
    fn test_lagrange() {
        let mut rng = rand_core::OsRng;
        let mut a = Polynomial::<10>::random(&mut rng);
        let mut xs = [RingElt::ZERO; 10];
        let mut ys = [RingElt::ZERO; 10];
        a.coeffs[2] = RingElt::ZERO;

        for i in 1..=10 {
            xs[i - 1] = RingElt::repeated_field_elt(i as u8);
            ys[i - 1] = a.eval(xs[i - 1]);
        }

        let p = lagrange_interpolant(xs, ys);
        assert_eq!(p, a);
    }
}
