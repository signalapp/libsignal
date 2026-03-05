use sha2::{Digest, Sha256};

pub fn compute_zb_demo(context: &[u8], nonce: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"PVRF_DEMO_ZB_V0");
    h.update(context);
    h.update(nonce);
    let digest = h.finalize(); // 32 bytes

    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub fn compute_sas_demo(nonce16: &[u8], zb16: &[u8]) -> [u8; 16] {
    // Expect 16-byte inputs; caller should enforce.
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = nonce16[i] ^ zb16[i];
    }
    out
}