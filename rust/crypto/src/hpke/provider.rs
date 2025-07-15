//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hkdf::Hkdf;
use hpke_rs_crypto::error::Error as HpkeError;
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_crypto::{CryptoRng, HpkeCrypto, HpkeTestRng, RngCore};
use libsignal_core::curve::{PrivateKey, PublicKey};
use rand_core::{SeedableRng, TryRngCore};

/// An implementation of [`HpKeCrypto`] that only supports what we use, to save on code size.
#[derive(Debug, Default)]
pub struct CryptoProvider;

impl HpkeCrypto for CryptoProvider {
    type HpkePrng = Rng;

    fn name() -> String {
        "SignalHpkeCryptoProvider".into()
    }

    fn supports_kdf(alg: KdfAlgorithm) -> Result<(), HpkeError> {
        match alg {
            KdfAlgorithm::HkdfSha256 => Ok(()),
            _ => Err(HpkeError::UnknownKdfAlgorithm),
        }
    }

    fn supports_kem(alg: KemAlgorithm) -> Result<(), HpkeError> {
        match alg {
            KemAlgorithm::DhKem25519 => Ok(()),
            _ => Err(HpkeError::UnknownKemAlgorithm),
        }
    }

    fn supports_aead(alg: AeadAlgorithm) -> Result<(), HpkeError> {
        match alg {
            AeadAlgorithm::Aes256Gcm => Ok(()),
            _ => Err(HpkeError::UnknownAeadAlgorithm),
        }
    }

    fn prng() -> Self::HpkePrng {
        Default::default()
    }

    fn kdf_extract(alg: KdfAlgorithm, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, HpkeError> {
        match alg {
            KdfAlgorithm::HkdfSha256 => {}
            _ => return Err(HpkeError::UnknownKdfAlgorithm),
        }

        Ok(Hkdf::<sha2::Sha256>::extract(Some(salt), ikm).0.to_vec())
    }

    fn kdf_expand(
        alg: KdfAlgorithm,
        prk: &[u8],
        info: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, HpkeError> {
        match alg {
            KdfAlgorithm::HkdfSha256 => {}
            _ => return Err(HpkeError::UnknownKdfAlgorithm),
        }

        let hkdf = Hkdf::<sha2::Sha256>::from_prk(prk)
            .map_err(|e| HpkeError::CryptoLibraryError(e.to_string()))?;
        let mut result = vec![0; output_size];
        hkdf.expand(info, &mut result)
            .map_err(|e| HpkeError::CryptoLibraryError(e.to_string()))?;
        Ok(result)
    }

    fn dh(alg: KemAlgorithm, pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, HpkeError> {
        match alg {
            KemAlgorithm::DhKem25519 => {}
            _ => return Err(HpkeError::UnknownKemAlgorithm),
        }
        let pk =
            PublicKey::from_djb_public_key_bytes(pk).map_err(|_| HpkeError::KemInvalidPublicKey)?;
        let sk = PrivateKey::deserialize(sk).map_err(|_| HpkeError::KemInvalidSecretKey)?;
        Ok(sk
            .calculate_agreement(&pk)
            .expect("cannot fail when using X25519")
            .into_vec())
    }

    fn secret_to_public(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, HpkeError> {
        match alg {
            KemAlgorithm::DhKem25519 => {}
            _ => return Err(HpkeError::UnknownKemAlgorithm),
        }
        let sk = PrivateKey::deserialize(sk).map_err(|_| HpkeError::KemInvalidSecretKey)?;
        Ok(sk
            .public_key()
            .expect("can always get a public key for X25519")
            .public_key_bytes()
            .to_vec())
    }

    fn kem_key_gen(
        _alg: KemAlgorithm,
        _prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
        // Panicking is more useful than returning an error here; hpke-rs doesn't propagate errors
        // very well, whereas with a panic our tests will point right to the failing operation.
        unimplemented!("unused with DH-based KEM");
    }

    fn kem_key_gen_derand(
        _alg: KemAlgorithm,
        _seed: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
        unimplemented!("unused with DH-based KEM");
    }

    fn kem_encaps(
        _alg: KemAlgorithm,
        _pk_r: &[u8],
        _prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
        unimplemented!("unused with DH-based KEM");
    }

    fn kem_decaps(_alg: KemAlgorithm, _ct: &[u8], _sk_r: &[u8]) -> Result<Vec<u8>, HpkeError> {
        unimplemented!("unused with DH-based KEM");
    }

    fn dh_validate_sk(_alg: KemAlgorithm, _sk: &[u8]) -> Result<Vec<u8>, HpkeError> {
        unimplemented!("unused with unauthenticated (Base) mode");
    }

    fn aead_seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        match alg {
            AeadAlgorithm::Aes256Gcm => {}
            _ => return Err(HpkeError::UnknownAeadAlgorithm),
        }

        let mut enc = crate::aes_gcm::Aes256GcmEncryption::new(key, nonce, aad)
            .map_err(|_| HpkeError::AeadInvalidNonce)?;
        let mut output =
            Vec::with_capacity(msg.len() + crate::aes_gcm::Aes256GcmEncryption::TAG_SIZE);
        output.extend_from_slice(msg);
        enc.encrypt(&mut output[..msg.len()]);
        output.extend_from_slice(&enc.compute_tag());
        Ok(output)
    }

    fn aead_open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        match alg {
            AeadAlgorithm::Aes256Gcm => {}
            _ => return Err(HpkeError::UnknownAeadAlgorithm),
        }

        let mut dec = crate::aes_gcm::Aes256GcmDecryption::new(key, nonce, aad)
            .map_err(|_| HpkeError::AeadInvalidNonce)?;
        let (msg, tag) = msg
            .split_last_chunk::<{ crate::aes_gcm::Aes256GcmDecryption::TAG_SIZE }>()
            .ok_or(HpkeError::AeadInvalidCiphertext)?;
        let mut output = msg.to_vec();
        dec.decrypt(&mut output);
        dec.verify_tag(tag).map_err(|_| HpkeError::AeadOpenError)?;
        Ok(output)
    }
}

// Matching https://github.com/cryspen/hpke-rs/blob/v0.3.0/rust_crypto_provider/src/lib.rs#L38
type RngImpl = rand_chacha::ChaCha20Rng;

pub struct Rng {
    rng: RngImpl,
}

impl Default for Rng {
    fn default() -> Self {
        Self {
            rng: RngImpl::from_os_rng(),
        }
    }
}

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.rng.fill_bytes(dst);
    }
}

impl CryptoRng for Rng where RngImpl: CryptoRng {}

impl HpkeTestRng for Rng {
    type Error = <RngImpl as TryRngCore>::Error;

    fn try_fill_test_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.try_fill_bytes(dest)
    }

    fn seed(&mut self, seed: &[u8]) {
        // It's okay that this might discard entropy, since it's only supposed to be used for tests.
        const REQUIRED_SEED_LEN: usize = 32;
        let mut padded_or_truncated_seed = [0; REQUIRED_SEED_LEN];
        if seed.len() >= REQUIRED_SEED_LEN {
            padded_or_truncated_seed.copy_from_slice(&seed[..REQUIRED_SEED_LEN]);
        } else {
            padded_or_truncated_seed[..seed.len()].copy_from_slice(seed);
        }
        self.rng = SeedableRng::from_seed(padded_or_truncated_seed);
    }
}
