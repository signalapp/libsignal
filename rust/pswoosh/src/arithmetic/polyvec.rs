use crate::arithmetic::params::*;
use crate::arithmetic::poly::*;

pub const POLYVEC_BYTES: usize = POLY_BYTES * N;

pub type PolyVec = [Poly; N]; // R_q^N

pub fn polyvec_init() -> PolyVec {
    [poly_init(); N]
}

pub fn polyvec_add(a: PolyVec, b: PolyVec) -> PolyVec {
    let mut c: PolyVec = polyvec_init();

    for i in 0..N {
        c[i] = poly_add(a[i], b[i]);
    }

    c
}

/*
 * Base-multiplication in a polynomials
 */
pub fn polyvec_basemul_acc(a: PolyVec, b: PolyVec) -> Poly {
    let mut c: Poly;
    let mut t: Poly;

    c = poly_basemul(a[0], b[0]);

    for i in 1..N {
        t = poly_basemul(a[i], b[i]);
        c = poly_add(c, t);
    }

    c
}

pub fn polyvec_ntt(a: &mut PolyVec) {
    for i in 0..N {
        poly_ntt(&mut a[i]);
    }
}

pub fn polyvec_invntt(a: &mut PolyVec) {
    for i in 0..N {
        poly_invntt(&mut a[i]);
    }
}

pub fn polyvec_from_m(a: &mut PolyVec) {
    for i in 0..N {
        poly_from_m(&mut a[i]);
    }
}

pub fn polyvec_to_m(a: &mut PolyVec) {
    for i in 0..N {
        poly_to_m(&mut a[i]);
    }
}

pub fn polyvec_frombytes(a: &[u8; POLYVEC_BYTES]) -> PolyVec {
    let mut pv: PolyVec = polyvec_init();

    for i in 0..N {
        pv[i] = poly_frombytes(
            a[POLY_BYTES * i..POLY_BYTES * i + POLY_BYTES]
                .try_into()
                .unwrap(),
        );
    }

    pv
}

pub fn polyvec_tobytes(a: PolyVec) -> [u8; POLYVEC_BYTES] {
    let mut r: [u8; POLYVEC_BYTES] = [0; POLYVEC_BYTES];

    for i in 0..N {
        r[POLY_BYTES * i..POLY_BYTES * i + POLY_BYTES].copy_from_slice(&poly_tobytes(a[i]));
    }

    r
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::fq::*;
    use std::thread;

    const STACK_SIZE: usize = 10 * 1024 * 1024;

    // Increase stack size for the tests
    fn run_test_with_stack<F>(test_fn: F, test_name: &str)
    where
        F: FnOnce() + Send + 'static,
    {
        let builder = thread::Builder::new().stack_size(STACK_SIZE);
        let test_name = String::from(test_name);
        let handler = builder
            .spawn(move || {
                println!("Running {} with 10MB stack", test_name);
                test_fn();
            })
            .unwrap();

        handler.join().unwrap();
    }

    #[test]
    fn test_polyvec_add() {
        run_test_with_stack(
            || {
                let a: PolyVec = [[HQ.clone(); D]; N];
                let b: PolyVec = [[QQ.clone(); D]; N];
                let rc: PolyVec = [[TQQ.clone(); D]; N];
                let c: PolyVec = polyvec_add(a, b);

                assert_eq!(rc, c, "polyvec_add: polynomial vectors don't match");
            },
            "test_polyvec_add",
        );
        
    }

    #[test]
    fn test_polyvec_bytes() {
        run_test_with_stack(
            || {
                let a: PolyVec = [[HQ.clone(); D]; N];
                let b1: [u8; POLYVEC_BYTES] = polyvec_tobytes(a);
                let r: PolyVec = polyvec_frombytes(&b1);
                let b2: [u8; POLYVEC_BYTES] = polyvec_tobytes(r);

                assert_eq!(b1, b2, "polyvec_bytes: buffers don't match");
                assert_eq!(a, r, "polyvec_bytes: polynomial vectors don't match");
            },
            "test_polyvec_bytes",
        );
        
    }
}
