use crate::arithmetic::fq::*;
use crate::arithmetic::zetas::*;
use crate::arithmetic::params::*;

pub const POLY_BYTES: usize = ELEM_BYTES * D;

pub type Poly = [Elem; D]; // R_q


pub fn poly_init() -> Poly {
    [fp_init(); D]
}


pub fn poly_add(a: Poly, b: Poly) -> Poly {
    let mut c: Poly = poly_init();

    for i in 0..D {
        add(&mut c[i], a[i], b[i]);
    }

    c
}

pub fn poly_fromM(ap: &mut Poly) {
    let mut t: Elem = fp_init();

    for i in 0..D {
        fromM(&mut t, ap[i]);
        ap[i] = t;
    }
}

pub fn poly_toM(ap: &mut Poly) {
    let mut t: Elem = fp_init();

    for i in 0..D {
        toM(&mut t, ap[i]);
        ap[i] = t;
    }
}

/*
 * Schoolbook multiplication in polynomials (testing purposes only)
 */
fn schoolbook_mul(a: Poly, b: Poly) -> Poly {
    let mut c: Poly = poly_init();
    let mut t0: Elem;
    let mut t1: Elem = fp_init();

    for i in 0..D {
        for j in 0..D {
            mul(&mut t1, a[i], b[j]);
            t0 = c[(i+j) % D];
            if 256 <= i + j {
                sub(&mut c[(i+j) % D], t0, t1);
            } else {
                add(&mut c[(i+j) % D], t0, t1);
            }
        }
    }

    c
}

/*
 * Base-multiplication in a polynomials
 */
pub fn poly_basemul(a: Poly, b: Poly) -> Poly {
    let mut c: Poly = poly_init();
    let mut t0: Elem = fp_init();
    let mut t1: Elem = fp_init();
    let mut zeta: Elem;
    let mut zoff: usize = D/4;
    let mut i: usize = 0;

    while(i < D) {
        zeta = ZETAS[zoff];
        zoff += 1;

        mul(&mut t0, a[i+1], b[i+1]);
        mul(&mut t1, t0, zeta);

        mul(&mut t0, a[i], b[i]);
        add(&mut c[i], t0, t1);

        mul(&mut t0, a[i], b[i+1]);
        mul(&mut t1, a[i+1], b[i]);
        add(&mut c[i+1], t0, t1);

        i += 2;

        mul(&mut t0, a[i+1], b[i+1]);
        mul(&mut t1, t0, zeta);

        mul(&mut t0, a[i], b[i]);
        sub(&mut c[i], t0, t1); // -zeta ?

        mul(&mut t0, a[i], b[i+1]);
        mul(&mut t1, a[i+1], b[i]);
        add(&mut c[i+1], t0, t1);

        i += 2;
    }

    c
}

/*
 * In-place NTT
 */
pub fn poly_ntt(a: &mut Poly) {
    let mut len: usize = D>>1;
    let mut off: usize;
    let mut joff: usize;
    let mut zoff: usize = 0;
    let mut t: Elem;
    let mut r: Elem = fp_init();

    for _i in 0..7 {
        off = 0;
        while(off < D) {
            zoff += 1;
            joff = off;
            for _j in 0..len {
                t = a[joff+len];
                mul(&mut r, t, ZETAS[zoff]);
                t = a[joff];
                add(&mut a[joff], t, r);
                sub(&mut a[joff+len], t, r);
                joff += 1;
            }
            off = joff + len;
        }
        len >>= 1;
    }
}

/*
 * In-place Inverse NTT
 */
pub fn poly_invntt(a: &mut Poly) {
    let mut len: usize = 2;
    let mut off: usize;
    let mut joff: usize;
    let mut zoff: usize = 0;
    let mut t: Elem;
    let mut r: Elem;
    let mut m: Elem = fp_init();

    for i in 0..7 {
        off = 0;
        while(off < D) {
            joff = off;
            for _j in 0..len {
                t = a[joff];
                r = a[joff+len];
                add(&mut a[joff], t, r);
                sub(&mut m, t, r);
                mul(&mut a[joff+len], m, ZETAS_INV[zoff]);
                joff += 1;
            }
            off = joff + len;
            zoff += 1;
        }
        len <<= 1;
    }

    for i in 0..D {
        t = a[i];
        mul(&mut t, a[i], ZETAS_INV[D/2-1]);
        a[i] = t;
    }
}

/*
 * Deserializes polynomial
 */
pub fn poly_frombytes(rp: &[u8; POLY_BYTES]) -> Poly {
    let mut p: Poly = poly_init();

    for i in 0..D {
        p[i] = elem_frombytes(rp[ELEM_BYTES*i..ELEM_BYTES*i+ELEM_BYTES].try_into().unwrap());
    }

    p
}

/*
 * Seralizes polynomial
 */
pub fn poly_tobytes(a: Poly) -> [u8; POLY_BYTES] {
    let mut r: [u8; POLY_BYTES] = [0; POLY_BYTES];

    for i in 0..D {
        r[ELEM_BYTES*i..ELEM_BYTES*(i+1)].copy_from_slice(&elem_tobytes(a[i]));
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_add() {
        let mut a: Poly = [QQ.clone(); D];
        let mut b: Poly = [HQ.clone(); D];
        let rc: Poly = [TQQ.clone(); D];
        let mut c: Poly = poly_init();

        c = poly_add(a, b);

        assert_eq!(rc, c, "poly_add: polynomials don't match");
    }

    #[test]
    fn test_poly_basemul() {
        let mut a: Poly = [QQ.clone(); D];
        let mut b: Poly = [[0x02, 0x0, 0x0, 0x0]; D];
        let mut aM: Poly = a;
        let mut c: Poly;
        let mut rc: Poly;

        poly_toM(&mut aM);
        rc = schoolbook_mul(aM, b);

        poly_ntt(&mut a);
        poly_ntt(&mut b);
        c = poly_basemul(a, b);
        poly_invntt(&mut c);

        assert_eq!(c, rc, "poly_basemul: polynomials don't match");
    }

    #[test]
    fn test_poly_ntt() {
        let a: Poly = [HQ.clone(); D];
        let mut b: Poly = a.clone();

        poly_ntt(&mut b);
        poly_invntt(&mut b);
        poly_fromM(&mut b);

        assert_eq!(a, b, "poly_ntt: polynomial vectors don't match");
    }

    #[test]
    fn test_poly_bytes() {
        let a: Poly = [TQQ.clone(); D];
        let mut r: Poly = poly_init();
        let mut b: [u8; POLY_BYTES] = [0; POLY_BYTES];

        b = poly_tobytes(a);
        r = poly_frombytes(&b);
        assert_eq!(a, r, "poly_bytes: Values don't match");
    }
}
