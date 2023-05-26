//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto;

use chacha20poly1305::aead::{AeadInPlace, NewAead};
use chacha20poly1305::ChaCha20Poly1305;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use snow::error::Error as SnowError;
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::CryptoResolver;
use snow::types::{Cipher, Dh, Hash, Random};
use x25519_dalek as x25519;

const TAGLEN: usize = 16;

struct Rng<T>(T);
impl<T: RngCore> RngCore for Rng<T> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<T: CryptoRng> CryptoRng for Rng<T> {}
impl<T: RngCore + CryptoRng + Send + Sync> Random for Rng<T> {}

// From snow's resolvers/default.rs
#[derive(Default)]
struct Dh25519 {
    privkey: [u8; 32],
    pubkey: [u8; 32],
}
impl Dh for Dh25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, privkey: &[u8]) {
        self.privkey.copy_from_slice(privkey);
        self.pubkey = x25519::x25519(self.privkey, x25519::X25519_BASEPOINT_BYTES);
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        rng.fill_bytes(&mut self.privkey);
        self.pubkey = x25519::x25519(self.privkey, x25519::X25519_BASEPOINT_BYTES);
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn privkey(&self) -> &[u8] {
        &self.privkey
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), SnowError> {
        let result = x25519::x25519(self.privkey, pubkey[..self.pub_len()].try_into().unwrap());
        out[..result.len()].copy_from_slice(&result);
        Ok(())
    }
}

// Based on snow's resolvers/default.rs
#[derive(Default)]
struct HashSHA256 {
    hasher: Sha256,
}
impl Hash for HashSHA256 {
    fn name(&self) -> &'static str {
        "sha256"
    }

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn reset(&mut self) {
        self.hasher = Sha256::default();
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let hash = self.hasher.finalize_reset();
        out[..hash.len()].copy_from_slice(&hash);
    }
}

// Based on snow's resolvers/default.rs
#[derive(Default)]
struct CipherChaChaPoly {
    key: [u8; 32],
}

macro_rules! copy_slices {
    ($inslice:expr, $outslice:expr) => {
        $outslice[..$inslice.len()].copy_from_slice(&$inslice[..])
    };
}

impl Cipher for CipherChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8]) {
        copy_slices!(key, &mut self.key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0u8; 12];
        copy_slices!(&nonce.to_le_bytes(), &mut nonce_bytes[4..]);

        copy_slices!(plaintext, out);

        let tag = ChaCha20Poly1305::new(&self.key.into())
            .encrypt_in_place_detached(&nonce_bytes.into(), authtext, &mut out[0..plaintext.len()])
            .unwrap();

        copy_slices!(tag, &mut out[plaintext.len()..]);

        plaintext.len() + tag.len()
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SnowError> {
        let mut nonce_bytes = [0u8; 12];
        copy_slices!(&nonce.to_le_bytes(), &mut nonce_bytes[4..]);

        let message_len = ciphertext.len() - TAGLEN;

        copy_slices!(ciphertext[..message_len], out);

        let result = ChaCha20Poly1305::new(&self.key.into()).decrypt_in_place_detached(
            &nonce_bytes.into(),
            authtext,
            &mut out[..message_len],
            ciphertext[message_len..].into(),
        );

        match result {
            Ok(_) => Ok(message_len),
            Err(_) => Err(SnowError::Decrypt),
        }
    }
}

pub struct Resolver;

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(Rng(rand_core::OsRng)))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::Curve25519 => Some(Box::<Dh25519>::default()),
            _ => panic!("{:?} not supported", choice),
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        match choice {
            HashChoice::SHA256 => Some(Box::<HashSHA256>::default()),
            _ => panic!("{:?} not supported", choice),
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match choice {
            CipherChoice::ChaChaPoly => Some(Box::<CipherChaChaPoly>::default()),
            _ => panic!("{:?} not supported", choice),
        }
    }
}
