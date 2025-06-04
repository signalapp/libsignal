use core::arch::x86_64;

pub const NRUNS: usize = 10000;

fn median_u128(t: &mut [u128; NRUNS]) -> u128 {
    t.sort();

    if(NRUNS % 2 == 1) {
        t[NRUNS/2]
    } else {
        (t[NRUNS/2-1] + t[NRUNS/2])/2
    }
}

fn average_u128(t: &[u128; NRUNS]) -> u128 {
    let mut a: u128 = 0;

    for i in 0..NRUNS-1 {
        a += t[i];
    }

    a/(NRUNS as u128)
}

pub fn print_res_u128(t: &mut [u128; NRUNS]) {
    for i in 0..NRUNS-1 {
        t[i] = t[i+1] - t[i];
    }

    println!("average: {}", average_u128(t));
    println!("median: {}\n", median_u128(t));
}

pub fn rdtsc() -> u64 {
    unsafe { x86_64::_rdtsc() }
}

fn median(t: &mut [u64; NRUNS]) -> u64 {
    t.sort();

    if(NRUNS % 2 == 1) {
        t[NRUNS/2]
    } else {
        (t[NRUNS/2-1] + t[NRUNS/2])/2
    }
}

fn average(t: &[u64; NRUNS]) -> u64 {
    let mut a: u64 = 0;

    for i in 0..NRUNS-1 {
        a += t[i];
    }

    a/(NRUNS as u64)
}

pub fn print_res(t: &mut [u64; NRUNS]) {
    for i in 0..NRUNS-1 {
        t[i] = t[i+1] - t[i];
    }

    println!("average: {}", average(t));
    println!("median: {}\n", median(t));
}
