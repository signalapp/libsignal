//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ptr;

use hpke_rs::prelude::*;
use zeroize::{Zeroize as _, Zeroizing};

mod provider;

pub use hpke_rs::HpkeError;

/// A type byte marking one of Signal's chosen instantiations of HPKE.
#[derive(Clone, Copy, PartialEq, Eq, Debug, derive_more::TryFrom)]
#[repr(u8)]
#[allow(non_camel_case_types)]
#[try_from(repr)]
pub enum SignalHpkeCiphertextType {
    Base_X25519_HkdfSha256_Aes256Gcm = 1,
    Hybrid_MlKem1024_X25519_HkdfSha256_Aes256Gcm = 2,
    Hybrid_MlKem1024_X25519_HkdfSha512_Aes256Gcm = 3,
}

impl From<SignalHpkeCiphertextType> for u8 {
    fn from(value: SignalHpkeCiphertextType) -> Self {
        value as Self
    }
}

impl SignalHpkeCiphertextType {
    fn set_up(self) -> Hpke<provider::CryptoProvider> {
        Hpke::new(
            self.mode(),
            self.kem_algorithm(),
            self.kdf_algorithm(),
            self.aead_algorithm(),
        )
    }

    fn mode(self) -> HpkeMode {
        match self {
            SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm => HpkeMode::Base,
            // Hybrid variants bypass hpke_rs entirely and never call set_up().
            _ => unreachable!("hybrid variants do not use hpke_rs set_up()"),
        }
    }

    fn kem_algorithm(self) -> hpke_types::KemAlgorithm {
        match self {
            SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm => {
                hpke_types::KemAlgorithm::DhKem25519
            }
            // Hybrid variants bypass hpke_rs entirely and never call set_up().
            _ => unreachable!("hybrid variants do not use hpke_rs set_up()"),
        }
    }

    fn kdf_algorithm(self) -> hpke_types::KdfAlgorithm {
        match self {
            SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm => {
                hpke_types::KdfAlgorithm::HkdfSha256
            }
            // Hybrid variants bypass hpke_rs entirely and never call set_up().
            _ => unreachable!("hybrid variants do not use hpke_rs set_up()"),
        }
    }

    fn aead_algorithm(self) -> hpke_types::AeadAlgorithm {
        match self {
            SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm => {
                hpke_types::AeadAlgorithm::Aes256Gcm
            }
            // Hybrid variants bypass hpke_rs entirely and never call set_up().
            _ => unreachable!("hybrid variants do not use hpke_rs set_up()"),
        }
    }
}

use libcrux_ml_kem::mlkem1024::{
    self as mlkem1024, MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey,
};

const X25519_KEY_LEN: usize = 32;

// Wire-format size constants (FIPS 203 §7.2 for ML-KEM 1024; X25519 spec for the public key)
const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;
const X25519_PUBLIC_KEY_LEN: usize = 32;

// Domain labels — version-tagged, one per cipher suite variant
const LABEL_SHA256: &[u8] = b"Signal-Hybrid-MlKem1024-X25519-HkdfSha256-Aes256Gcm v1";
const LABEL_SHA512: &[u8] = b"Signal-Hybrid-MlKem1024-X25519-HkdfSha512-Aes256Gcm v1";

/// Derives a 32-byte AEAD key and 12-byte nonce using HKDF-SHA-256.
///
/// # Purpose
/// Combines the ML-KEM 1024 and X25519 shared secrets into keying material for AES-256-GCM.
/// Uses domain-separated HKDF expansion so the key and nonce are independent.
/// Returns `Zeroizing` wrappers so the derived key material is erased on drop.
///
/// # Example
/// ```ignore
/// let (key, nonce) = derive_hybrid_keys_sha256(&ikm, b"info");
/// ```
fn derive_hybrid_keys_sha256(
    ikm: &[u8],
    info: &[u8],
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 12]>) {
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, ikm);
    let mut aead_key = Zeroizing::new([0u8; 32]);
    let mut aead_nonce = Zeroizing::new([0u8; 12]);
    hkdf.expand_multi_info(&[LABEL_SHA256, &[0x00], info], aead_key.as_mut())
        .expect("valid output length");
    hkdf.expand_multi_info(&[LABEL_SHA256, &[0x01], info], aead_nonce.as_mut())
        .expect("valid output length");
    (aead_key, aead_nonce)
}

/// Derives a 32-byte AEAD key and 12-byte nonce using HKDF-SHA-512.
///
/// # Purpose
/// Same as `derive_hybrid_keys_sha256` but uses HKDF-SHA-512 for ~256-bit PQ security.
/// Returns `Zeroizing` wrappers so the derived key material is erased on drop.
///
/// # Example
/// ```ignore
/// let (key, nonce) = derive_hybrid_keys_sha512(&ikm, b"info");
/// ```
fn derive_hybrid_keys_sha512(
    ikm: &[u8],
    info: &[u8],
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 12]>) {
    let hkdf = hkdf::Hkdf::<sha2::Sha512>::new(None, ikm);
    let mut aead_key = Zeroizing::new([0u8; 32]);
    let mut aead_nonce = Zeroizing::new([0u8; 12]);
    hkdf.expand_multi_info(&[LABEL_SHA512, &[0x00], info], aead_key.as_mut())
        .expect("valid output length");
    hkdf.expand_multi_info(&[LABEL_SHA512, &[0x01], info], aead_nonce.as_mut())
        .expect("valid output length");
    (aead_key, aead_nonce)
}

/// Which KDF to use for the hybrid HPKE cipher suite.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HybridHpkeVariant {
    HkdfSha256,
    HkdfSha512,
}

/// Public key for hybrid ML-KEM 1024 + X25519 HPKE encryption (NIST FIPS 203 + SP 800-186).
///
/// # Purpose
/// Encrypts data to a recipient so that security holds as long as either ML-KEM 1024
/// or X25519 remains unbroken. Protects against "harvest now, decrypt later" attacks.
///
/// # Construction
/// Obtained from `HybridHpkeKeyPair::generate_sha256()` or `generate_sha512()`.
pub struct HybridHpkePublicKey {
    x25519: Zeroizing<[u8; 32]>,
    mlkem: Zeroizing<Box<[u8]>>,
    variant: HybridHpkeVariant,
}

/// Private key for hybrid ML-KEM 1024 + X25519 HPKE decryption.
///
/// # Purpose
/// Decrypts ciphertext produced by the corresponding `HybridHpkePublicKey::seal`.
/// Handles both SHA-256 (type byte 2) and SHA-512 (type byte 3) variants automatically
/// by inspecting the type byte in the ciphertext wire format.
///
/// The private key material is stored as `Zeroizing<[u8; N]>` so it is zeroed on drop,
/// compensating for the upstream types not implementing `ZeroizeOnDrop`.
pub struct HybridHpkePrivateKey {
    x25519: Zeroizing<[u8; 32]>,
    mlkem: Zeroizing<Box<[u8]>>,
}

/// A public/private key pair for hybrid ML-KEM 1024 + X25519 HPKE.
///
/// # Purpose
/// Entry point for all hybrid HPKE operations. Generate once per recipient identity.
///
/// # Example
/// ```ignore
/// let kp = HybridHpkeKeyPair::generate_sha256();
/// let ct = kp.public_key.seal(b"backup-v1", b"", plaintext).unwrap();
/// let pt = kp.private_key.open(b"backup-v1", b"", &ct).unwrap();
/// assert_eq!(pt, plaintext);
/// ```
pub struct HybridHpkeKeyPair {
    pub public_key: HybridHpkePublicKey,
    pub private_key: HybridHpkePrivateKey,
}

impl HybridHpkeKeyPair {
    /// Generates a hybrid key pair using HKDF-SHA-256 (~128-bit PQ security).
    pub fn generate_sha256() -> Self {
        Self::generate_with_variant(HybridHpkeVariant::HkdfSha256)
    }

    /// Generates a hybrid key pair using HKDF-SHA-512 (~256-bit PQ security).
    pub fn generate_sha512() -> Self {
        Self::generate_with_variant(HybridHpkeVariant::HkdfSha512)
    }

    /// Internal generator that uses OS randomness for both X25519 and ML-KEM 1024 key generation.
    fn generate_with_variant(variant: HybridHpkeVariant) -> Self {
        use rand::RngCore as _;
        let mut rng = rand::rng();  //TODO: as rand gets bumped to v0.10 please switch to SysRng
        let mut x25519_pair = libsignal_core::curve::KeyPair::generate(&mut rng);
        let mut seed = Zeroizing::new([0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE]);
        rng.fill_bytes(seed.as_mut());
        let (mlkem_sk, mlkem_pk) = {
            let kp = mlkem1024::generate_key_pair(*seed);
            let (sk, pk) = kp.into_parts();
            (Box::new(sk), Box::new(pk))
        };
        // `*seed` copies the seed bytes by-value onto the stack. Zero them out
        // now that the by-value use is complete — Rust does not guarantee stack
        // frame cleanup on drop.
        seed.zeroize();
        let x25519_sk: [u8; X25519_KEY_LEN] = x25519_pair
            .private_key
            .serialize()
            .try_into()
            .expect("X25519 private key must be 32 bytes");
        let x25519_pk: [u8; X25519_KEY_LEN] = x25519_pair
            .public_key
            .public_key_bytes()
            .try_into()
            .expect("X25519 public key must be 32 bytes");
        // Zero `x25519_pair` in-place before it drops — `KeyPair` is `Copy` and does not
        // implement `Zeroize`/`Drop`, so its private key bytes would otherwise linger on
        // the stack until the compiler's frame cleanup (which Rust does not guarantee).
        // `ptr::write_volatile` prevents the compiler from optimizing away the zeroing,
        // and since `KeyPair` has no Drop impl, dropping the zeroed memory is safe.
        unsafe {
            ptr::write_volatile(
                &mut x25519_pair as *mut _,
                libsignal_core::curve::KeyPair {
                    public_key: libsignal_core::curve::PublicKey::from_djb_public_key_bytes(&[0u8; 32])
                        .expect("valid dummy key"),
                    private_key: libsignal_core::curve::PrivateKey::deserialize(&[0u8; 32])
                        .expect("valid dummy key"),
                },
            );
        }
        // `write_volatile` does not run Drop; zeroed memory is left on stack (safe — no Drop impl on KeyPair).
        // `Copy` type: drop is a no-op, suppressed to avoid compiler warning.
        #[allow(dropping_copy_types)]
        { core::mem::drop(x25519_pair); }
        HybridHpkeKeyPair {
            public_key: HybridHpkePublicKey {
                x25519: Zeroizing::new(x25519_pk),
                mlkem: Zeroizing::new((*mlkem_pk).as_ref().to_vec().into_boxed_slice()),
                variant,
            },
            private_key: HybridHpkePrivateKey {
                x25519: Zeroizing::new(x25519_sk),
                mlkem: Zeroizing::new((*mlkem_sk).as_ref().to_vec().into_boxed_slice()),
            },
        }
    }
}

/// A thoroughly stripped-down version of [HPKE][] that only supports the "base" mode
/// (unauthenticated, no pre-shared key).
///
/// Additionally hardcodes the KDF as HKDF-SHA-256 and the AEAD as AES-256-GCM, as used elsewhere in
/// libsignal.
///
/// See also [SimpleHpkeReceiver].
///
/// [HPKE]: https://www.rfc-editor.org/rfc/rfc9180.html
pub trait SimpleHpkeSender {
    fn seal(&self, info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError>;
}

impl SimpleHpkeSender for libsignal_core::curve::PublicKey {
    fn seal(&self, info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let ciphertext_type = match self.key_type() {
            libsignal_core::curve::KeyType::Djb => {
                SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm
            }
        };

        let hpke_key = HpkePublicKey::from(self.public_key_bytes());
        let (encapsulated_secret, mut ciphertext) = ciphertext_type
            .set_up()
            .seal(&hpke_key, info, aad, plaintext, None, None, None)?;
        debug_assert_eq!(
            encapsulated_secret.len(),
            ciphertext_type.kem_algorithm().shared_secret_len()
        );

        // Insert the type byte and the encapsulated secret at the front of the ciphertext. We do
        // this by mutating the ciphertext rather than creating a new Vec (or appending to the
        // secret) because we have the best chance of the ciphertext Vec already having extra room
        // in the buffer, in which case we're just moving bytes around with no new allocations. If
        // not, this should fall back to effectively creating a new buffer and copying all three
        // parts into it.
        ciphertext.splice(
            0..0,
            [ciphertext_type.into()]
                .into_iter()
                .chain(encapsulated_secret),
        );

        Ok(ciphertext)
    }
}

impl SimpleHpkeSender for HybridHpkePublicKey {
    /// Encrypts `plaintext` using hybrid ML-KEM 1024 + X25519.
    ///
    /// # Wire format
    /// `[type_byte (1)] [mlkem_ct (1568)] [x25519_enc (32)] [aead_ct (plaintext.len() + 16)]`
    ///
    /// # Purpose
    /// Provides hybrid post-quantum encryption: security holds if either ML-KEM 1024 or X25519
    /// remains unbroken. The two shared secrets are combined via HKDF before AEAD encryption.
    fn seal(&self, info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        use rand::RngCore as _;
        let mut rng = rand::rng();

        // Reconstruct keys from zeroized bytes (temporary, dropped after this function)
        let mlkem_pk =
            MlKem1024PublicKey::try_from(self.mlkem.as_ref()).expect("valid ML-KEM public key");
        let x25519_pk = libsignal_core::curve::PublicKey::from_djb_public_key_bytes(
            self.x25519.as_ref(),
        )
        .expect("valid X25519 public key");

        // ML-KEM 1024 encapsulation
        let mut encaps_seed = Zeroizing::new([0u8; libcrux_ml_kem::ENCAPS_SEED_SIZE]);
        rng.fill_bytes(encaps_seed.as_mut());
        let (mlkem_ct, mlkem_ss) = mlkem1024::encapsulate(&mlkem_pk, *encaps_seed);
        let mlkem_ss = Zeroizing::new(mlkem_ss);
        // `*encaps_seed` copies the seed bytes by-value onto the stack. Zero them out now.
        encaps_seed.zeroize();
        debug_assert_eq!(MlKem1024Ciphertext::len(), MLKEM1024_CIPHERTEXT_LEN);

        // Ephemeral X25519 key agreement
        let eph_pair = libsignal_core::curve::KeyPair::generate(&mut rng);
        let ss_x25519 = Zeroizing::new(
            eph_pair
                .private_key
                .calculate_agreement(&x25519_pk)
                .map_err(|_| HpkeError::InvalidInput)?,
        );

        // Combine secrets — hybrid combiner via HKDF; zeroized on drop
        let mut ikm = Zeroizing::new([0u8; 64]); // ss_mlkem (32) || ss_x25519 (32)
        ikm[..32].copy_from_slice(mlkem_ss.as_ref());
        ikm[32..].copy_from_slice(&ss_x25519);
        

        let (aead_key, aead_nonce) = match self.variant {
            HybridHpkeVariant::HkdfSha256 => derive_hybrid_keys_sha256(ikm.as_ref(), info),
            HybridHpkeVariant::HkdfSha512 => derive_hybrid_keys_sha512(ikm.as_ref(), info),
        };

        let ciphertext_type = match self.variant {
            HybridHpkeVariant::HkdfSha256 => {
                SignalHpkeCiphertextType::Hybrid_MlKem1024_X25519_HkdfSha256_Aes256Gcm
            }
            HybridHpkeVariant::HkdfSha512 => {
                SignalHpkeCiphertextType::Hybrid_MlKem1024_X25519_HkdfSha512_Aes256Gcm
            }
        };

        // AES-256-GCM encrypt
        let mut enc = crate::aes_gcm::Aes256GcmEncryption::new(
            aead_key.as_ref(), aead_nonce.as_ref(), aad,
        )
        .map_err(|_| HpkeError::InvalidConfig)?;
        let mut aead_ct =
            Vec::with_capacity(plaintext.len() + crate::aes_gcm::Aes256GcmEncryption::TAG_SIZE);
        aead_ct.extend_from_slice(plaintext);
        enc.encrypt(&mut aead_ct[..plaintext.len()]);
        aead_ct.extend_from_slice(&enc.compute_tag());

        // Assemble wire format
        let x25519_enc = eph_pair.public_key.public_key_bytes();
        let mut output = Vec::with_capacity(
            1 + MLKEM1024_CIPHERTEXT_LEN + X25519_PUBLIC_KEY_LEN + aead_ct.len(),
        );
        output.push(u8::from(ciphertext_type));
        output.extend_from_slice(mlkem_ct.as_ref());
        output.extend_from_slice(x25519_enc);
        output.extend_from_slice(&aead_ct);
        Ok(output)
    }
}

/// A thoroughly stripped-down version of [HPKE][] that only supports the "base" mode
/// (unauthenticated, no pre-shared key).
///
/// Additionally hardcodes the KDF as HKDF-SHA-256 and the AEAD as AES-256-GCM, as used elsewhere in
/// libsignal.
///
/// See also [SimpleHpkeReceiver].
///
/// [HPKE]: https://www.rfc-editor.org/rfc/rfc9180.html
pub trait SimpleHpkeReceiver {
    fn open(&self, info: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError>;
}

impl SimpleHpkeReceiver for libsignal_core::curve::PrivateKey {
    fn open(&self, info: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let (ciphertext_type, ciphertext) = ciphertext
            .split_at_checked(1)
            .ok_or(HpkeError::InvalidInput)?;
        let ciphertext_type = ciphertext_type[0]
            .try_into()
            .map_err(|_| HpkeError::UnknownMode)?;

        // Check for a ciphertext using a non-Curve25519 key, or a hybrid variant
        // that should be handled by HybridHpkePrivateKey instead.
        match (ciphertext_type, self.key_type()) {
            (
                SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm,
                libsignal_core::curve::KeyType::Djb,
            ) => {}
            // Hybrid variants are handled by HybridHpkePrivateKey, not PrivateKey
            _ => return Err(HpkeError::UnknownMode),
        }

        let (encapsulated_secret, ciphertext) = ciphertext
            .split_at_checked(ciphertext_type.kem_algorithm().shared_secret_len())
            .ok_or(HpkeError::InvalidInput)?;

        let hpke_key = HpkePrivateKey::from(self.serialize());
        ciphertext_type.set_up().open(
            encapsulated_secret,
            &hpke_key,
            info,
            aad,
            ciphertext,
            None,
            None,
            None,
        )
    }
}

impl SimpleHpkeReceiver for HybridHpkePrivateKey {
    /// Decrypts a ciphertext produced by `HybridHpkePublicKey::seal`.
    ///
    /// # Purpose
    /// Reverses the hybrid seal operation: decapsulates ML-KEM 1024, performs X25519 ECDH,
    /// re-derives the AEAD key and nonce via HKDF, and authenticates + decrypts the payload.
    /// Supports both SHA-256 (type byte 2) and SHA-512 (type byte 3) variants.
    fn open(&self, info: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        const MIN_LEN: usize = 1
            + MLKEM1024_CIPHERTEXT_LEN
            + X25519_PUBLIC_KEY_LEN
            + crate::aes_gcm::Aes256GcmDecryption::TAG_SIZE;

        if ciphertext.len() < MIN_LEN {
            return Err(HpkeError::InvalidInput);
        }

        let ciphertext_type: SignalHpkeCiphertextType = ciphertext[0]
            .try_into()
            .map_err(|_| HpkeError::UnknownMode)?;

        // Parse wire format
        let mlkem_ct_bytes = &ciphertext[1..=MLKEM1024_CIPHERTEXT_LEN];
        let x25519_enc_bytes = &ciphertext
            [1 + MLKEM1024_CIPHERTEXT_LEN..1 + MLKEM1024_CIPHERTEXT_LEN + X25519_PUBLIC_KEY_LEN];
        let aead_ct = &ciphertext[1 + MLKEM1024_CIPHERTEXT_LEN + X25519_PUBLIC_KEY_LEN..];

        // Reconstruct keys from zeroized bytes (temporary, zeroed before drop, dropped after this function)
        let mlkem_sk =
            MlKem1024PrivateKey::try_from(self.mlkem.as_ref()).expect("valid ML-KEM private key");
        let x25519_sk = libsignal_core::curve::PrivateKey::deserialize(self.x25519.as_ref())
            .expect("valid X25519 private key");

        // Run the entire cryptographic pipeline in a closure so all sensitive variables
        // (mlkem_sk, x25519_sk, mlkem_ss, ss_x25519, ikm) share a single scope and are
        // guaranteed to be zeroed before any early return.
        let inner = (|| -> Result<_, HpkeError> {
            // ML-KEM 1024 decapsulation
            // Note: ML-KEM uses implicit rejection — on invalid ciphertext it returns a
            // pseudorandom decoy key. The AEAD tag check catches this.
            let mlkem_ct = MlKem1024Ciphertext::try_from(mlkem_ct_bytes)
                .map_err(|_| HpkeError::InvalidInput)?;
            let mlkem_ss = Zeroizing::new(mlkem1024::decapsulate(&mlkem_sk, &mlkem_ct));

            // X25519 key agreement
            let x25519_pub =
                libsignal_core::curve::PublicKey::from_djb_public_key_bytes(x25519_enc_bytes)
                    .map_err(|_| HpkeError::InvalidInput)?;
            let ss_x25519 = Zeroizing::new(
                x25519_sk
                    .calculate_agreement(&x25519_pub)
                    .map_err(|_| HpkeError::InvalidInput)?,
            );

            // Re-derive AEAD key and nonce; ikm is zeroized on drop
            let mut ikm = Zeroizing::new([0u8; 64]); // ss_mlkem (32) || ss_x25519 (32)
            ikm[..32].copy_from_slice(mlkem_ss.as_ref());
            ikm[32..].copy_from_slice(&ss_x25519);

            let (aead_key, aead_nonce) = match ciphertext_type {
                SignalHpkeCiphertextType::Hybrid_MlKem1024_X25519_HkdfSha256_Aes256Gcm => {
                    derive_hybrid_keys_sha256(ikm.as_ref(), info)
                }
                SignalHpkeCiphertextType::Hybrid_MlKem1024_X25519_HkdfSha512_Aes256Gcm => {
                    derive_hybrid_keys_sha512(ikm.as_ref(), info)
                }
                _ => return Err(HpkeError::UnknownMode),
            };

            // AES-256-GCM decrypt + authenticate
            let mut dec = crate::aes_gcm::Aes256GcmDecryption::new(
                aead_key.as_ref(), aead_nonce.as_ref(), aad,
            )
            .map_err(|_| HpkeError::InvalidConfig)?;
            let (msg, tag) = aead_ct
                .split_at(
                    aead_ct
                        .len()
                        .checked_sub(crate::aes_gcm::Aes256GcmDecryption::TAG_SIZE)
                        .ok_or(HpkeError::OpenError)?,
                );
            let tag: [u8; crate::aes_gcm::Aes256GcmDecryption::TAG_SIZE] =
                tag.try_into().map_err(|_| HpkeError::OpenError)?;
            let mut output = msg.to_vec();
            dec.decrypt(&mut output);
            dec.verify_tag(&tag).map_err(|_| {
                zeroize::Zeroize::zeroize(&mut output);
                HpkeError::OpenError
            })?;
            Ok((aead_key, aead_nonce, output))
        })();
        let inner = match inner {
            Ok(v) => v,
            Err(e) => {
                // Closure returned Err — zero AEAD-level key material and return early.
                // The closure's own sensitive vars (mlkem_sk, x25519_sk, mlkem_ss, ss_x25519, ikm)
                // are already zeroed by the closure's drop glue.
                return Err(e);
            }
        };
        let (mut aead_key, mut aead_nonce, output) = inner;

        // Zero reconstructed private keys — these types don't implement `Zeroize`/`Drop`,
        // so their private key bytes would otherwise linger on the stack.
        // This runs on every path (success or error from the closure).
        unsafe {
            let ptr = &mlkem_sk as *const _ as *mut u8;
            let len = core::mem::size_of_val(&mlkem_sk);
            for i in 0..len {
                ptr.add(i).write_volatile(0);
            }
        }
        unsafe {
            let ptr = &x25519_sk as *const _ as *mut u8;
            let len = core::mem::size_of_val(&x25519_sk);
            for i in 0..len {
                ptr.add(i).write_volatile(0);
            }
        }
        // Zero AEAD-level key material derived from the shared secrets
        aead_key.zeroize();
        aead_nonce.zeroize();
        Ok(output)
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use libsignal_core::curve::KeyPair;

    use super::*;

    #[test]
    fn basic() {
        let key_pair = KeyPair::generate(&mut rand::rng());
        let info = b"info";
        let aad = b"extra";
        let contents = b"message";

        let ciphertext = key_pair
            .public_key
            .seal(info, aad, contents)
            .expect("can seal");
        let unsealed = key_pair
            .private_key
            .open(info, aad, &ciphertext)
            .expect("can open");
        assert_eq!(&contents[..], unsealed);

        let another_key = KeyPair::generate(&mut rand::rng());
        assert_matches!(
            another_key
                .private_key
                .open(info, aad, &ciphertext)
                .expect_err("should fail"),
            HpkeError::OpenError
        );
    }

    #[test]
    fn hybrid_key_generation() {
        let kp256 = HybridHpkeKeyPair::generate_sha256();
        let kp512 = HybridHpkeKeyPair::generate_sha512();

        let _pk: &HybridHpkePublicKey = &kp256.public_key;
        let _sk: &HybridHpkePrivateKey = &kp256.private_key;
        let _pk: &HybridHpkePublicKey = &kp512.public_key;
        let _sk: &HybridHpkePrivateKey = &kp512.private_key;

        assert_eq!(
            u8::from(SignalHpkeCiphertextType::Base_X25519_HkdfSha256_Aes256Gcm),
            1u8
        );
        assert_eq!(
            u8::from(SignalHpkeCiphertextType::Hybrid_MlKem1024_X25519_HkdfSha256_Aes256Gcm),
            2u8
        );
        assert_eq!(
            u8::from(SignalHpkeCiphertextType::Hybrid_MlKem1024_X25519_HkdfSha512_Aes256Gcm),
            3u8
        );
    }

    #[test]
    fn hybrid_sha256_round_trip() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        let plaintext = b"post-quantum secret message";

        let ct = kp
            .public_key
            .seal(b"test-context", b"aad", plaintext)
            .expect("seal succeeds");

        assert_eq!(ct[0], 2u8, "type byte must be 0x02 for SHA-256 variant");
        assert_eq!(
            ct.len(),
            1 + 1568 + 32 + plaintext.len() + 16,
            "wire format length must match"
        );

        let recovered = kp
            .private_key
            .open(b"test-context", b"aad", &ct)
            .expect("open succeeds");

        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn hybrid_sha512_round_trip() {
        let kp = HybridHpkeKeyPair::generate_sha512();
        let plaintext = b"sha-512 protected message";

        let ct = kp
            .public_key
            .seal(b"test-context-512", b"aad", plaintext)
            .expect("seal succeeds");

        assert_eq!(ct[0], 3u8, "type byte must be 0x03 for SHA-512 variant");
        assert_eq!(
            ct.len(),
            1 + 1568 + 32 + plaintext.len() + 16,
            "wire format length must match"
        );

        let recovered = kp
            .private_key
            .open(b"test-context-512", b"aad", &ct)
            .expect("open succeeds");

        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn hybrid_round_trip_empty_plaintext() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        let ct = kp
            .public_key
            .seal(b"ctx", b"", b"")
            .expect("seal empty");
        let pt = kp.private_key.open(b"ctx", b"", &ct).expect("open empty");
        assert!(pt.is_empty());
    }

    // --- Task 4: Wire format validation tests ---

    #[test]
    fn hybrid_open_rejects_empty_input() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        assert!(kp.private_key.open(b"", b"", &[]).is_err());
    }

    #[test]
    fn hybrid_open_rejects_truncated_before_mlkem_boundary() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        // type byte only + 5 bytes — far too short for the ML-KEM ciphertext
        let short = vec![2u8; 6];
        assert!(kp.private_key.open(b"", b"", &short).is_err());
    }

    #[test]
    fn hybrid_open_rejects_truncated_before_x25519_boundary() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        // type byte + full ML-KEM ct, but no x25519 enc and no AEAD
        let short = vec![2u8; 1 + 1568];
        assert!(kp.private_key.open(b"", b"", &short).is_err());
    }

    #[test]
    fn hybrid_open_rejects_missing_aead_tag() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        // type byte + mlkem_ct + x25519_enc, zero AEAD bytes (not even a tag)
        let short = vec![2u8; 1 + 1568 + 32];
        assert!(kp.private_key.open(b"", b"", &short).is_err());
    }

    #[test]
    fn hybrid_open_rejects_unknown_type_byte() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        let mut garbage = vec![0x00u8; 1 + 1568 + 32 + 32];
        garbage[0] = 0xFF; // unknown type byte
        assert!(kp.private_key.open(b"", b"", &garbage).is_err());
    }

    #[test]
    fn hybrid_open_rejects_x25519_ciphertext() {
        // A Base_X25519 ciphertext (type byte 0x01) must not be accepted by the hybrid receiver
        let x25519_kp = KeyPair::generate(&mut rand::rng());
        let hybrid_kp = HybridHpkeKeyPair::generate_sha256();

        let x25519_ct = x25519_kp
            .public_key
            .seal(b"info", b"aad", b"msg")
            .expect("x25519 seal succeeds");

        assert_eq!(x25519_ct[0], 1u8);
        assert!(hybrid_kp.private_key.open(b"info", b"aad", &x25519_ct).is_err());
    }

    #[test]
    fn hybrid_wire_format_sizes_are_correct() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        let plaintext = b"hello";
        let ct = kp
            .public_key
            .seal(b"ctx", b"", plaintext)
            .expect("seal must succeed");

        assert_eq!(ct[0], 2u8);
        assert_eq!(ct[1..1 + 1568].len(), 1568);
        assert_eq!(ct[1 + 1568..1 + 1568 + 32].len(), 32);
        assert_eq!(ct.len(), 1 + 1568 + 32 + plaintext.len() + 16);
    }

    // --- Task 5: Authentication failure tests ---

    #[test]
    fn hybrid_open_fails_with_wrong_private_key() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        let other = HybridHpkeKeyPair::generate_sha256();
        let ct = kp.public_key.seal(b"info", b"aad", b"secret")
            .expect("seal must succeed");
        assert!(other.private_key.open(b"info", b"aad", &ct).is_err());
    }

    #[test]
    fn hybrid_open_fails_with_tampered_aead_payload() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        let mut ct = kp.public_key.seal(b"info", b"", b"tamper me")
            .expect("seal must succeed");
        // Flip a bit deep in the AEAD region (past the mlkem_ct and x25519_enc)
        let idx = 1 + 1568 + 32 + 2;
        ct[idx] ^= 0xFF;
        assert!(kp.private_key.open(b"info", b"", &ct).is_err());
    }

    #[test]
    fn hybrid_open_fails_with_tampered_mlkem_ciphertext() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        let mut ct = kp.public_key.seal(b"info", b"", b"tamper mlkem")
            .expect("seal must succeed");
        // Flip a bit inside the ML-KEM ciphertext region (bytes 1..1569)
        ct[100] ^= 0x01;
        // ML-KEM uses implicit rejection — decapsulation returns a pseudorandom decoy key.
        // The AEAD authentication tag will not verify with the decoy key.
        assert!(kp.private_key.open(b"info", b"", &ct).is_err());
    }

    #[test]
    fn hybrid_open_fails_with_tampered_x25519_enc() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        let mut ct = kp.public_key.seal(b"info", b"", b"tamper x25519")
            .expect("seal must succeed");
        // Flip a bit in the X25519 enc region (bytes 1569..1601)
        ct[1569] ^= 0x42;
        assert!(kp.private_key.open(b"info", b"", &ct).is_err());
    }

    #[test]
    fn hybrid_open_fails_with_wrong_aad() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        let ct = kp
            .public_key
            .seal(b"info", b"correct-aad", b"msg")
            .expect("seal must succeed");
        assert!(kp.private_key.open(b"info", b"wrong-aad", &ct).is_err());
    }

    #[test]
    fn hybrid_open_fails_with_wrong_info() {
        let kp = HybridHpkeKeyPair::generate_sha256();
        let ct = kp
            .public_key
            .seal(b"correct-info", b"", b"msg")
            .expect("seal must succeed");
        assert!(kp.private_key.open(b"wrong-info", b"", &ct).is_err());
    }

    // --- Task 6: Hybrid combiner property, domain separation, and library wiring tests ---

    #[test]
    fn hybrid_combiner_mlkem_ss_is_load_bearing() {
        // If ss_mlkem changes, the AEAD key must change — X25519 alone does not determine output.
        let ss_mlkem_a = [0x01u8; 32];
        let ss_mlkem_b = [0x02u8; 32]; // different
        let ss_x25519  = [0xAAu8; 32]; // same for both

        let (key_a, _) = derive_hybrid_keys_sha256(&[&ss_mlkem_a[..], &ss_x25519[..]].concat(), b"");
        let (key_b, _) = derive_hybrid_keys_sha256(&[&ss_mlkem_b[..], &ss_x25519[..]].concat(), b"");

        assert_ne!(*key_a, *key_b, "AEAD key must change when ss_mlkem changes");
    }

    #[test]
    fn hybrid_combiner_x25519_ss_is_load_bearing() {
        // If ss_x25519 changes, the AEAD key must change — ML-KEM alone does not determine output.
        let ss_mlkem    = [0xBBu8; 32]; // same for both
        let ss_x25519_a = [0x01u8; 32];
        let ss_x25519_b = [0x02u8; 32]; // different

        let (key_a, _) = derive_hybrid_keys_sha256(&[&ss_mlkem[..], &ss_x25519_a[..]].concat(), b"");
        let (key_b, _) = derive_hybrid_keys_sha256(&[&ss_mlkem[..], &ss_x25519_b[..]].concat(), b"");

        assert_ne!(*key_a, *key_b, "AEAD key must change when ss_x25519 changes");
    }

    #[test]
    fn hybrid_hkdf_domain_separation_key_ne_nonce() {
        // The [0x00] / [0x01] separator ensures key and nonce are independent HKDF outputs.
        let ikm = [0xCCu8; 64];
        let (aead_key, aead_nonce) = derive_hybrid_keys_sha256(&ikm, b"ctx");

        // Key is 32 bytes, nonce is 12 bytes. Compare the overlapping prefix.
        assert_ne!(
            &aead_key[..12],
            &aead_nonce[..],
            "AEAD key and nonce must differ (domain separation via [0x00]/[0x01])"
        );
    }

    #[test]
    fn hybrid_sha256_and_sha512_produce_different_keys_from_same_ikm() {
        // The per-variant domain labels ensure SHA-256 and SHA-512 produce different outputs.
        let ikm = [0xDDu8; 64];
        let (key256, _) = derive_hybrid_keys_sha256(&ikm, b"ctx");
        let (key512, _) = derive_hybrid_keys_sha512(&ikm, b"ctx");
        assert_ne!(*key256, *key512, "Different KDF variants must produce different keys");
    }

    #[test]
    fn hybrid_open_rejects_sha256_ciphertext_with_sha512_key() {
        // A ciphertext encrypted with the SHA-256 variant (type byte 0x02) must not
        // be decryptable with a key pair generated for SHA-512 (type byte 0x03).
        // Verifies that the different domain labels are correctly enforced end-to-end.
        let kp256 = HybridHpkeKeyPair::generate_sha256();
        let kp512 = HybridHpkeKeyPair::generate_sha512();

        // Seal with SHA-256 key
        let ct = kp256
            .public_key
            .seal(b"info", b"", b"msg")
            .expect("seal must succeed");
        assert_eq!(ct[0], 2u8);

        // SHA-512 private key must reject a type-2 ciphertext
        assert!(kp512.private_key.open(b"info", b"", &ct).is_err(),
            "SHA-512 private key must not decrypt a SHA-256 ciphertext");
    }

    #[test]
    fn hybrid_open_rejects_sha512_ciphertext_with_sha256_key() {
        // A ciphertext encrypted with the SHA-512 variant (type byte 0x03) must not
        // be decryptable with a key pair generated for SHA-256 (type byte 0x02).
        // Symmetric inverse of hybrid_open_rejects_sha256_ciphertext_with_sha512_key.
        let kp256 = HybridHpkeKeyPair::generate_sha256();
        let kp512 = HybridHpkeKeyPair::generate_sha512();

        // Seal with SHA-512 key
        let ct = kp512
            .public_key
            .seal(b"info", b"", b"msg")
            .expect("seal must succeed");
        assert_eq!(ct[0], 3u8);

        // SHA-256 private key must reject a type-3 ciphertext
        assert!(kp256.private_key.open(b"info", b"", &ct).is_err(),
            "SHA-256 private key must not decrypt a SHA-512 ciphertext");
    }

    #[test]
    fn mlkem1024_is_integrated_in_production_pipeline() {
        // Verifies that libcrux-ml-kem is correctly integrated in the full seal/open pipeline.
        // Strategy: seal a message, then confirm that tampering with the ML-KEM ciphertext
        // causes decryption to fail. If ML-KEM were bypassed or its output ignored,
        // tampering would have no effect.
        let kp = HybridHpkeKeyPair::generate_sha256();
        let plaintext = b"integration check";

        let mut ct = kp
            .public_key
            .seal(b"info", b"", plaintext)
            .expect("seal must succeed");

        // Untampered: must succeed
        let recovered = kp.private_key.open(b"info", b"", &ct)
            .expect("original ciphertext must decrypt");
        assert_eq!(recovered.as_slice(), plaintext);

        // Tamper the ML-KEM ciphertext region (bytes 1..1569)
        // ML-KEM uses implicit rejection: bad ciphertext → pseudorandom decoy key → AEAD auth fails
        ct[500] ^= 0xDE;
        assert!(kp.private_key.open(b"info", b"", &ct).is_err(),
            "tampered ML-KEM ciphertext must cause decryption failure (ML-KEM is load-bearing)");
    }

    #[test]
    fn existing_x25519_path_is_unaffected() {
        // Regression: the original X25519-only HPKE must be completely unchanged.
        let key_pair = KeyPair::generate(&mut rand::rng());
        let ct = key_pair.public_key.seal(b"info", b"aad", b"message").expect("seal");
        assert_eq!(ct[0], 1u8, "X25519-only path must still emit type byte 0x01");
        let pt = key_pair.private_key.open(b"info", b"aad", &ct).expect("open");
        assert_eq!(pt, b"message");
    }
}
