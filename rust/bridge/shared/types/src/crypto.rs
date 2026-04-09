//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

use ::signal_crypto;
use rand::rand_core::UnwrapErr;
use rand::rngs::OsRng;
use rand::{CryptoRng, SeedableRng};
use signal_crypto::*;

use crate::*;

static ALLOW_DETERMINISTIC_RNG: AtomicBool = AtomicBool::new(false);
pub enum RandomNumberGenerator {
    OsRandom,
    DeterministicForTesting { seed: u64 },
}
impl From<i64> for RandomNumberGenerator {
    fn from(value: i64) -> Self {
        if value < 0 {
            Self::OsRandom
        } else {
            Self::DeterministicForTesting { seed: value as u64 }
        }
    }
}
impl RandomNumberGenerator {
    pub fn enable_deterministic_rng() {
        log::info!("Deterministic rng is now allowed");
        ALLOW_DETERMINISTIC_RNG.store(true, Ordering::Relaxed);
    }
    pub fn create(&self) -> RngInstance {
        match self {
            RandomNumberGenerator::OsRandom => RngInstance::OsRng(UnwrapErr(OsRng)),
            RandomNumberGenerator::DeterministicForTesting { seed } => {
                Self::check_deterministic_rng_allowed();
                RngInstance::DeterministicRng(Box::new(rand_chacha::ChaCha20Rng::seed_from_u64(
                    *seed,
                )))
            }
        }
    }

    #[track_caller]
    fn check_deterministic_rng_allowed() {
        assert!(ALLOW_DETERMINISTIC_RNG.load(Ordering::Relaxed));
    }
}

pub enum RngInstance {
    OsRng(UnwrapErr<OsRng>),
    DeterministicRng(Box<rand_chacha::ChaCha20Rng>),
}
impl Deref for RngInstance {
    type Target = dyn CryptoRng + Send;
    fn deref(&self) -> &Self::Target {
        match self {
            RngInstance::OsRng(x) => x,
            RngInstance::DeterministicRng(x) => {
                RandomNumberGenerator::check_deterministic_rng_allowed();
                x
            }
        }
    }
}
impl DerefMut for RngInstance {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            RngInstance::OsRng(x) => x,
            RngInstance::DeterministicRng(x) => {
                RandomNumberGenerator::check_deterministic_rng_allowed();
                x
            }
        }
    }
}

pub struct Aes256GcmEncryption {
    gcm: Option<signal_crypto::Aes256GcmEncryption>,
}

impl Aes256GcmEncryption {
    pub fn new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<Self> {
        let gcm = signal_crypto::Aes256GcmEncryption::new(key, nonce, associated_data)?;
        Ok(Self { gcm: Some(gcm) })
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) {
        self.gcm.as_mut().expect("not yet finalized").encrypt(buf);
    }

    pub fn compute_tag(&mut self) -> Vec<u8> {
        let gcm = self.gcm.take().expect("not yet finalized");
        gcm.compute_tag().to_vec()
    }
}

pub struct Aes256GcmDecryption {
    gcm: Option<signal_crypto::Aes256GcmDecryption>,
}

impl Aes256GcmDecryption {
    pub fn new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<Self> {
        let gcm = signal_crypto::Aes256GcmDecryption::new(key, nonce, associated_data)?;
        Ok(Self { gcm: Some(gcm) })
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) {
        self.gcm.as_mut().expect("not yet finalized").decrypt(buf);
    }

    pub fn verify_tag(&mut self, tag: &[u8]) -> Result<bool> {
        let gcm = self.gcm.take().expect("not yet finalized");
        match gcm.verify_tag(tag) {
            Ok(()) => Ok(true),
            Err(Error::InvalidTag) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

// Explicit wrapper for cbindgen purposes.
pub struct Aes256GcmSiv(pub aes_gcm_siv::Aes256GcmSiv);

bridge_as_handle!(CryptographicHash, mut = true, ffi = false, node = false);
bridge_as_handle!(CryptographicMac, mut = true, ffi = false, node = false);
bridge_as_handle!(Aes256GcmSiv);
bridge_as_handle!(Aes256Ctr32, mut = true, node = false);
bridge_as_handle!(Aes256GcmEncryption, mut = true, node = false);
bridge_as_handle!(Aes256GcmDecryption, mut = true, node = false);
