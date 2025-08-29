//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use blake2::{Blake2b, Blake2b512};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use libcrux_ml_kem::mlkem1024;
use rand_core::TryRngCore as _;
use sha2::{Digest, Sha256};
use snow::error::Error as SnowError;
use snow::params::{CipherChoice, DHChoice, HashChoice, KemChoice};
use snow::resolvers::CryptoResolver;
use snow::types::{Cipher, Dh, Hash, Kem, Random};
use x25519_dalek as x25519;

const TAGLEN: usize = 16;

struct Rng<T>(T);

impl<T: rand_core::RngCore + rand_core::CryptoRng + Send + Sync> Random for Rng<T> {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), SnowError> {
        rand_core::RngCore::fill_bytes(&mut self.0, dest);
        Ok(())
    }
}

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

    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), SnowError> {
        rng.try_fill_bytes(&mut self.privkey)?;
        self.pubkey = x25519::x25519(self.privkey, x25519::X25519_BASEPOINT_BYTES);
        Ok(())
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
struct HashBLAKE2b {
    hasher: Blake2b512,
}

impl Hash for HashBLAKE2b {
    fn name(&self) -> &'static str {
        "BLAKE2b"
    }

    fn block_len(&self) -> usize {
        128
    }

    fn hash_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        self.hasher = Blake2b::default();
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let hash = self.hasher.finalize_reset();
        out[..64].copy_from_slice(&hash);
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

    fn set(&mut self, key: &[u8; 32]) {
        self.key = *key;
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

// Struct and implementation copied from snow/src/resolvers/default.rs
struct Kyber1024 {
    pubkey: mlkem1024::MlKem1024PublicKey,
    privkey: mlkem1024::MlKem1024PrivateKey,
}

impl Default for Kyber1024 {
    fn default() -> Self {
        Self {
            pubkey: mlkem1024::MlKem1024PublicKey::from(
                [0u8; mlkem1024::MlKem1024PublicKey::len()],
            ),
            privkey: mlkem1024::MlKem1024PrivateKey::from(
                [0u8; mlkem1024::MlKem1024PrivateKey::len()],
            ),
        }
    }
}

impl Kem for Kyber1024 {
    fn name(&self) -> &'static str {
        "Kyber1024"
    }

    /// The length in bytes of a public key for this primitive.
    fn pub_len(&self) -> usize {
        mlkem1024::MlKem1024PublicKey::len()
    }

    /// The length in bytes the Kem cipherthext for this primitive.
    fn ciphertext_len(&self) -> usize {
        mlkem1024::MlKem1024Ciphertext::len()
    }

    /// Shared secret length in bytes that this Kem encapsulates.
    fn shared_secret_len(&self) -> usize {
        libcrux_ml_kem::SHARED_SECRET_SIZE
    }

    /// Generate a new private key.
    fn generate(&mut self, rng: &mut dyn Random) {
        let mut randomness = [0u8; 64];
        rng.try_fill_bytes(&mut randomness)
            .expect("can generate random bytes");
        let keypair = mlkem1024::generate_key_pair(randomness);
        (self.privkey, self.pubkey) = keypair.into_parts();
    }

    /// Get the public key.
    fn pubkey(&self) -> &[u8] {
        self.pubkey.as_ref()
    }

    /// Generate a shared secret and encapsulate it using this Kem.
    fn encapsulate(
        &self,
        pubkey: &[u8],
        shared_secret_out: &mut [u8],
        ciphertext_out: &mut [u8],
    ) -> Result<(usize, usize), SnowError> {
        let mlkem_pubkey = {
            let key =
                mlkem1024::MlKem1024PublicKey::try_from(pubkey).map_err(|_| SnowError::Input)?;
            mlkem1024::validate_public_key(&key).then_some(key)
        }
        .ok_or(SnowError::Input)?;
        // We don't get a RNG passed in, so currently we use OsRng directly:
        let mut randomness = [0u8; 32];
        rand_core::OsRng.try_fill_bytes(&mut randomness).unwrap();
        let (ciphertext, shared_secret) = mlkem1024::encapsulate(&mlkem_pubkey, randomness);
        shared_secret_out.copy_from_slice(shared_secret.as_ref());
        ciphertext_out.copy_from_slice(ciphertext.as_ref());
        Ok((shared_secret.len(), mlkem1024::MlKem1024Ciphertext::len()))
    }

    /// Decapsulate a ciphertext producing a shared secret.
    fn decapsulate(
        &self,
        ciphertext: &[u8],
        shared_secret_out: &mut [u8],
    ) -> Result<usize, SnowError> {
        let ciphertext =
            mlkem1024::MlKem1024Ciphertext::try_from(ciphertext).map_err(|_| SnowError::Input)?;
        let shared_secret = mlkem1024::decapsulate(&self.privkey, &ciphertext);
        shared_secret_out.copy_from_slice(shared_secret.as_ref());
        Ok(libcrux_ml_kem::SHARED_SECRET_SIZE)
    }
}

pub struct Resolver;

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(Rng(rand_core::OsRng.unwrap_err())))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::Curve25519 => Some(Box::<Dh25519>::default()),
            _ => panic!("{choice:?} not supported"),
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        match choice {
            HashChoice::SHA256 => Some(Box::<HashSHA256>::default()),
            HashChoice::Blake2b => Some(Box::<HashBLAKE2b>::default()),
            _ => panic!("{choice:?} not supported"),
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match choice {
            CipherChoice::ChaChaPoly => Some(Box::<CipherChaChaPoly>::default()),
            _ => panic!("{choice:?} not supported"),
        }
    }

    fn resolve_kem(&self, choice: &KemChoice) -> Option<Box<dyn Kem>> {
        match choice {
            KemChoice::Kyber1024 => Some(Box::new(Kyber1024::default())),
        }
    }
}
