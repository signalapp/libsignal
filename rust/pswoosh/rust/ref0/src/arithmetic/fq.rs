pub const NLIMBS: usize = 4;
pub type Elem = [u64; NLIMBS];
const K: usize = 214; // bit size of q
pub const ELEM_BYTES: usize = K/8+1;
const RAD: usize = 64; //radix

/* Q = 2^214-255 */   /* 2^0              2^64               2^128              2^192   */
pub const Q: Elem =   [0xffffffffffffff01,0xffffffffffffffff,0xffffffffffffffff,0x3fffff];
/* HQ = Q/2 */
pub const HQ: Elem =  [0xffffffffffffff80,0xffffffffffffffff,0xffffffffffffffff,0x1fffff];
/* QQ = Q/4 */
pub const QQ: Elem =  [0xffffffffffffffc0,0xffffffffffffffff,0xffffffffffffffff,0xfffff];
/* TQQ = 3Q/4 */
pub const TQQ: Elem = [0xffffffffffffff40,0xffffffffffffffff,0xffffffffffffffff,0x2fffff]; 

#[link(name = "fq", kind="static")]
extern {
    fn fp_add(rp: *const u64, ap: *const u64, bp: *const u64);
    fn fp_sub(rp: *const u64, ap: *const u64, bp: *const u64);
    fn fp_mul(rp: *const u64, ap: *const u64, bp: *const u64);
    fn fp_toM(rp: *const u64, ap: *const u64);
    fn fp_fromM(rp: *const u64, ap: *const u64);
}

pub fn add(c: &mut Elem, a: Elem, b: Elem) {
    unsafe {
        fp_add(c.as_ptr(), a.as_ptr(), b.as_ptr());
    }
}

pub fn sub(c: &mut Elem, a: Elem, b: Elem) {
    unsafe {
        fp_sub(c.as_ptr(), a.as_ptr(), b.as_ptr());
    }
}

pub fn mul(c: &mut Elem, a: Elem, b: Elem) {
    unsafe {
        fp_mul(c.as_ptr(), a.as_ptr(), b.as_ptr());
    }
}

pub fn toM(aM: &mut Elem, a: Elem) {
    unsafe {
        fp_toM(aM.as_ptr(), a.as_ptr());
    }
}

pub fn fromM(a: &mut Elem, aM: Elem) {
    unsafe {
        fp_fromM(a.as_ptr(), aM.as_ptr());
    }
}

pub fn fp_init() -> Elem {
    [0; NLIMBS]
}


/* Description: Constant time comparison of two field elements
 *
 * Returns -1 if a < b; 0 if a = b; 1 if a > b
 */
pub fn cmp(a: Elem, b: Elem) -> u8 {
    let mut r: u8 = 0;
    let mut mask: u8 = 0xff;
    let mut s_ai: i64;
    let mut s_bi: i64;
    let mut gt: u8;
    let mut lt: u8;

    for i in (0..NLIMBS).rev() {
        s_ai = a[i] as i64;
        s_bi = b[i] as i64;

        lt = (((s_ai - s_bi) as u64) >> 63) as u8;
        gt = (((s_bi - s_ai) as u64) >> 63) as u8;

        //  high order limb comparisons take precedence
        lt &= mask;
        gt &= mask;

        mask ^= (lt | gt);
        r |= (lt << 7);
        r |= gt;
    }

    r
}

/*
 * Converts stream of bytes into value of type Elem
 */
pub fn elem_frombytes(ep: &[u8; ELEM_BYTES]) -> Elem {
    let mut e: Elem = fp_init();
    let mut t: [u8; 8] = [0; 8];

    for i in 0..NLIMBS-1 {
        e[i] = u64::from_le_bytes(ep[8*i..8*i+8].try_into().unwrap());
    }

    t[0..ELEM_BYTES-8*(NLIMBS-1)].copy_from_slice(&ep[8*(NLIMBS-1)..8*(NLIMBS-1)+3]);
    e[NLIMBS-1] = u64::from_le_bytes(t);

    e
}
/*
 * Converts field element into a byte buffer
 */
pub fn elem_tobytes(e: Elem) -> [u8; ELEM_BYTES] {
    let mut r: [u8; ELEM_BYTES] = [0; ELEM_BYTES];

    for i in 0..NLIMBS-1 {
        r[8*i..8*i+8].copy_from_slice(&e[i].to_le_bytes());
    }

    r[8*(NLIMBS-1)..8*(NLIMBS-1)+3].copy_from_slice(&e[NLIMBS-1].to_le_bytes()[0..3]); //remove trailing bytes

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp_add() {
        let a: Elem = QQ.clone();
        let b: Elem = QQ.clone();
        let rc: Elem = HQ.clone();
        let mut c: Elem = fp_init();

        add(&mut c, a, b); // q/4 + q/4

        assert_eq!(rc, c, "fp_add: Values don't match");
    }

    #[test]
    fn test_fp_sub() {
        let a: Elem = HQ.clone();
        let b: Elem = QQ.clone();
        let rc: Elem = QQ.clone();
        let mut c: Elem = fp_init();

        sub(&mut c, a, b); // q/2 - q/4

        assert_eq!(rc, c, "fp_sub: Values don't match");
    }

    #[test]
    fn test_fp_mul() {
        let a: Elem = QQ.clone();
        let mut aM: Elem = fp_init();
        let b: Elem = [0x03, 0x0, 0x0, 0x0];
        let mut bM: Elem = fp_init();
        let rc: Elem = TQQ.clone();
        let mut c: Elem = fp_init();
        let mut cM: Elem = fp_init();

        toM(&mut aM, a);
        toM(&mut bM, b);
        mul(&mut cM, aM, bM); // q/4 * 3
        fromM(&mut c, cM);

        assert_eq!(rc, c, "fp_mul: Values don't match");
    }

    #[test]
    fn test_fp_bytes() {
        let a: Elem = QQ.clone();
        let mut r: Elem;
        let mut b: [u8; ELEM_BYTES] = [0; ELEM_BYTES];

        b = elem_tobytes(a);
        r = elem_frombytes(&b);
        assert_eq!(a, r, "fp_bytes: Values don't match");
    }

    #[test]
    fn test_cmp() {
        let a: Elem = HQ.clone();

        assert_eq!(cmp(a, HQ), 0x00);
        assert_eq!(cmp(a, QQ), 0x01);
        assert_eq!(cmp(a, TQQ), 0x80);
    }
}
