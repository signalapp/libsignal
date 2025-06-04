use ref0::*;
use ref0::sysA::*;
use ref0::{util::*, arithmetic::{poly::*, polyvec::*, params::*}};
use getrandom;

fn main() {
    let mut seed: [u8; SYMBYTES] = [0; SYMBYTES];
    let mut buf: [u8; NOISE_BYTES] = [0; NOISE_BYTES];
    let rin: [u8; POLYVEC_BYTES * 2] = [0; POLYVEC_BYTES * 2];
    let mut pkp: [u8; PUBLICKEY_BYTES] = [0; PUBLICKEY_BYTES];
    let mut skp: [u8; SECRETKEY_BYTES] = [0; SECRETKEY_BYTES];
    let mut ss: [u8; SYMBYTES] = [0; SYMBYTES];
    let mut t: [u64; NRUNS] = [0; NRUNS];
    let mut s: PolyVec = polyvec_init();

    getrandom::getrandom(&mut seed).expect("getrandom failed");

    for i in 0..NRUNS {
        t[i] = rdtsc();
        s = getnoise_spec(&mut seed, 0);
    }
    println!("getnoise_spec (cycles): ");
    print_res(&mut t);

    for i in 0..NRUNS {
        t[i] = rdtsc();
        s = getnoise(&mut seed, 0);
    }
    println!("getnoise (cycles): ");
    print_res(&mut t);

    for i in 0..NRUNS {
        t[i] = rdtsc();
        expand_seed(&seed, (i % 256) as u8, &mut buf);
    }
    println!("expand_seed (cycles): ");
    print_res(&mut t);

    for i in 0..NRUNS {
        t[i] = rdtsc();
        expand_seed_aes(&seed, (i % 256) as u8, &mut buf);
    }
    println!("expand_seed_aes (cycles): ");
    print_res(&mut t);

    for i in 0..NRUNS {
        t[i] = rdtsc();
        s[i % N] = genoffset(&rin);
    }
    println!("genoffset (cycles): ");
    print_res(&mut t);

    for i in 0..NRUNS {
        t[i] = rdtsc();
        poly_ntt(&mut s[i % N]);
    }
    println!("poly_ntt (cycles):");
    print_res(&mut t);

    for i in 0..NRUNS {
        t[i] = rdtsc();
        poly_invntt(&mut s[i % N]);
    }
    println!("poly_invntt (cycles):");
    print_res(&mut t);

    for i in 0..NRUNS {
        t[i] = rdtsc();
        s[i % N] = polyvec_basemul_acc(A[i % N], A[(i + 1) % N]);
    }
    println!("polyvec_basemul_acc (cycles): ");
    print_res(&mut t);

    for i in 0..NRUNS {
        t[i] = rdtsc();
        (skp, pkp) = pswoosh_keygen(&A, true);
    }
    println!("keygen (cycles): ");
    print_res(&mut t);

    for i in 0..NRUNS {
        t[i] = rdtsc();
        ss = pswoosh_skey_deriv(&pkp, &pkp, &skp, true);
    }
    println!("skey_deriv (cycles): ");
    print_res(&mut t);
}
