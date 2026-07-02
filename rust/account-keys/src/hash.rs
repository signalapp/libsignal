//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! A library for hashing pins
//!
//! This library provides two pin hashing mechanisms:
//!   1. Transforming a pin to be suitable for use with a Secure Value Recovery service. The pin
//!      is hashed with Argon2 into 64 bytes. One half of these bytes are provided to the service
//!      as a password protecting some arbitrary data. The other half is used as an encryption key
//!      for that data. See `PinHash`
//!   2. Creating a [PHC-string encoded](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#specification)
//!      password hash of the pin that can be stored locally and validated against the pin later.
//!
//! In either case, all pins are UTF-8 encoded bytes that must be normalized *before* being provided
//! to this library. Normalizing a string pin requires the following steps:
//!  1. The string should be trimmed for leading and trailing whitespace.
//!  2. If the whole string consists of digits, then non-arabic digits must be replaced with their
//!     arabic 0-9 equivalents.
//!  3. The string must then be [NFKD normalized](https://unicode.org/reports/tr15/#Norm_Forms)
//!

use argon2::password_hash::{Salt, SaltString, rand_core};
use argon2::{
    Algorithm, Argon2, ParamsBuilder, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use hkdf::Hkdf;
use libsignal_core::try_derive_arrays;
use sha2::Sha256;

use crate::error::Result;

#[derive(Clone, Debug)]
pub struct PinHash {
    /// A key that can be used to encrypt or decrypt values before uploading them to a secure store.
    /// The 32 byte prefix of the 64 byte hashed pin.
    pub encryption_key: [u8; 32],

    /// A secret that can be used to access a value in a secure store. The 32 byte suffix of
    /// the 64 byte hashed pin.
    pub access_key: [u8; 32],
}

impl PinHash {
    /// Hash an arbitrary pin into an encryption key and access key that can be used to interact
    /// with a Secure Value Recovery service.
    ///
    /// # Arguments
    /// * `pin` - UTF-8 encoding of the pin. The pin *must* be normalized first.
    /// * `salt` - An arbitrary 32 byte value that should be unique to the user
    pub fn create(pin: &[u8], salt: &[u8; 32]) -> Result<PinHash> {
        let hasher = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            ParamsBuilder::new()
                .m_cost(1024 * 16) // 16 MiB
                .p_cost(1)
                .t_cost(32)
                .output_len(64)
                .build()
                .expect("valid params"),
        );
        let (encryption_key, access_key, []) = try_derive_arrays(|output_key_material| {
            hasher.hash_password_into(pin, salt, output_key_material)
        })?;
        Ok(PinHash {
            encryption_key,
            access_key,
        })
    }

    /// Create a salt from a username and the group id of the SVR service. This
    /// function should always be used to create pin salts for SVR2.
    ///
    /// # Arguments
    /// * `username` - The Basic Auth username credential retrieved from the chat service and used to authenticate with the SVR service
    /// * `group_id` - The attested group id returned by the SVR service
    pub fn make_salt(username: &str, group_id: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&group_id.to_be_bytes()), username.as_bytes())
            .expand(&[], &mut out)
            .expect("should expand");
        out
    }

    /// Turn a master key into an encrypted blob to be stored in SVR2 using
    /// HMAC-SHA256-SIV.
    ///
    /// The returned value is a concatenation of (16 byte IV || 32 byte ciphertext).
    pub fn encode_master_key(&self, m: &[u8; 32]) -> [u8; 48] {
        hmac_sha256_siv::encrypt(&self.encryption_key, m)
    }

    /// Decipher the master key from an SVR2 stored binary blob.
    ///
    /// Returns None if the tag verification failed.
    pub fn decode_master_key(&self, iv_c: &[u8; 48]) -> Option<[u8; 32]> {
        hmac_sha256_siv::decrypt(&self.encryption_key, iv_c)
    }
}

/// HMAC-SHA256-SIV is a minimal fixed-length encryption scheme
///
/// It is built on HMAC-SHA256, making use of _a_ synthetic IV (not to be
/// confused with [SIV](https://datatracker.ietf.org/doc/html/rfc5297)).
mod hmac_sha256_siv {
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;
    use subtle::ConstantTimeEq;

    // The returned value is a concatenation of (16 byte IV || 32 byte ciphertext).
    pub(super) fn encrypt(key: &[u8; 32], m: &[u8; 32]) -> [u8; 48] {
        fn concat(iv: &[u8; 16], ciphertext: &[u8; 32]) -> [u8; 48] {
            let mut ret = [0u8; 48];
            ret[..16].copy_from_slice(iv);
            ret[16..].copy_from_slice(ciphertext);
            ret
        }

        let k_a = hmac_sha256(key, b"auth");
        let k_e = hmac_sha256(key, b"enc");
        let iv = *hmac_sha256(&k_a, m)
            .first_chunk()
            .expect("IV is shorter than SHA-256 output");
        let k_x = hmac_sha256(&k_e, &iv);
        let mut c = k_x;
        c.iter_mut().zip(m).for_each(|(c_i, m_i)| *c_i ^= m_i);

        concat(&iv, &c)
    }

    pub(super) fn decrypt(key: &[u8; 32], iv_c: &[u8; 48]) -> Option<[u8; 32]> {
        const IV_SIZE: usize = 16;
        let k_a = hmac_sha256(key, b"auth");
        let k_e = hmac_sha256(key, b"enc");
        let (iv, c): (&[u8; IV_SIZE], &[u8]) = iv_c.split_first_chunk().expect("valid iv_c size");
        let k_x = hmac_sha256(&k_e, iv);
        let mut m = k_x;
        m.iter_mut().zip(c).for_each(|(c_i, m_i)| *c_i ^= m_i);
        let expected_iv: [u8; IV_SIZE] = *hmac_sha256(&k_a, &m)
            .first_chunk()
            .expect("IV is shorter than SHA-256 output");
        bool::from(iv.ct_eq(&expected_iv)).then_some(m)
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        Hmac::<Sha256>::new_from_slice(key)
            .expect("should construct")
            .chain_update(data)
            .finalize()
            .into_bytes()
            .into()
    }
}

/// Create a PHC encoded password hash string. This string may be verified later with
/// `verify_local_pin_hash`.
///
/// # Arguments
/// * `pin` - UTF-8 encoding of the pin. The pin *must* be normalized first.
pub fn local_pin_hash(pin: &[u8]) -> Result<String> {
    static_assertions::const_assert_eq!(Salt::RECOMMENDED_LENGTH, 16);
    let salt = SaltString::generate(&mut rand_core::OsRng);
    local_pin_hash_with_salt(pin, &salt)
}

fn local_pin_hash_with_salt<'a>(pin: &[u8], salt: impl Into<Salt<'a>>) -> Result<String> {
    let hasher = Argon2::new(
        Algorithm::Argon2i,
        Version::V0x13,
        ParamsBuilder::new()
            .m_cost(512)
            .p_cost(1)
            .t_cost(64)
            .output_len(32)
            .build()
            .expect("valid params"),
    );
    let hash = hasher.hash_password(pin, salt)?;
    Ok(hash.to_string())
}

/// Verify an encoded password hash against a pin
///
/// # Arguments
/// * `pin` - UTF-8 encoding of the pin. The pin *must* be normalized first.
/// * `encoded_hash` - A PHC-string formatted representation of the hash, as returned by `local_pin_hash`
pub fn verify_local_pin_hash(encoded_hash: &str, pin: &[u8]) -> Result<bool> {
    let parsed = PasswordHash::new(encoded_hash)?;
    Ok(Argon2::default().verify_password(pin, &parsed).is_ok())
}

#[cfg(test)]
mod test {
    use const_str::hex;
    use test_case::test_case;

    use super::{hmac_sha256_siv, *};
    use crate::hash::{PinHash, local_pin_hash, verify_local_pin_hash};

    fn compare_known_hash(
        pin: &[u8],
        salt: [u8; 32],
        master_key: [u8; 32],
        expected_access_key: [u8; 32],
        expected_encrypted: [u8; 48],
    ) {
        let hashed = PinHash::create(pin, &salt).expect("should hash");
        assert_eq!(hashed.access_key, expected_access_key);

        let encrypted = hashed.encode_master_key(&master_key);
        assert_eq!(expected_encrypted, encrypted);
    }

    #[test]
    fn known_hash() {
        compare_known_hash(
            b"password",
            hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            hex!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            hex!("ab7e8499d21f80a6600b3b9ee349ac6d72c07e3359fe885a934ba7aa844429f8"),
            hex!(
                "3f33ce58eb25b40436592a30eae2a8fabab1899095f4e2fba6e2d0dc43b4a2d9cac5a3931748522393951e0e54dec769"
            ),
        );
    }

    #[test]
    fn known_hash2() {
        compare_known_hash(
            b"anotherpassword",
            hex!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            hex!("88a787415a2ecd79da0d1016a82a27c5c695c9a19b88b0aa1d35683280aa9a67"),
            hex!("301d9dd1e96f20ce51083f67d3298fd37b97525de8324d5e12ed2d407d3d927b"),
            hex!(
                "9d9b05402ea39c17ff1c9298c8a0e86784a352aa02a74943bf8bcf07ec0f4b574a5b786ad0182c8d308d9eb06538b8c9"
            ),
        );
    }

    #[test]
    fn known_phc_string() {
        let pin = b"apassword";
        let phc_string = "$argon2i$v=19$m=512,t=64,p=1$ICEiIyQlJicoKSorLC0uLw$NeZzhiNv4cRmRMct9scf7d838bzmHJvrZtU/0BH0v/U";
        let salt = SaltString::encode_b64(&hex!("202122232425262728292A2B2C2D2E2F")).unwrap();

        let actual = local_pin_hash_with_salt(pin, &salt).unwrap();
        assert_eq!(phc_string, actual);

        assert!(verify_local_pin_hash(phc_string, pin).unwrap());
        assert!(!verify_local_pin_hash(phc_string, b"wrongpin").unwrap());
    }

    #[test]
    fn verify() {
        let pin = b"hunter2";
        let phc_string = local_pin_hash(pin).expect("should hash");
        assert!(verify_local_pin_hash(&phc_string, pin).unwrap());
        assert!(!verify_local_pin_hash(&phc_string, b"wrongpin").unwrap());
    }

    proptest::proptest! {
        #[test]
        fn encrypt_decrypt_roundtrip(encryption_key: [u8; 32], master_key: [u8; 32]) {
            let encrypted = hmac_sha256_siv::encrypt(&encryption_key, &master_key);
            let decrypted = hmac_sha256_siv::decrypt(&encryption_key, &encrypted)
                .expect("should decrypt");
            assert_eq!(master_key, decrypted);
        }
    }

    #[test]
    fn encrypt_is_deterministic() {
        let encryption_key =
            hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let master_key = hex!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

        assert_eq!(
            hmac_sha256_siv::encrypt(&encryption_key, &master_key),
            hmac_sha256_siv::encrypt(&encryption_key, &master_key),
        );
    }

    #[test]
    fn decrypt_known_ciphertext() {
        let encryption_key =
            hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let expected_master_key =
            hex!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        let ciphertext = hex!(
            "f27036915a60d704b04d452ef0d55a5d1668e7d91339daba9c950d985b7556471d13cc609e59eec62fb1ce27f5c5a342"
        );

        assert_eq!(
            Some(expected_master_key),
            hmac_sha256_siv::decrypt(&encryption_key, &ciphertext),
        );
    }

    #[test_case(|bytes| bytes[0] ^= 1; "bad IV")]
    #[test_case(|bytes| bytes[47] ^= 1; "bad ciphertext")]
    fn decrypt_rejects(corrupt: impl FnOnce(&mut [u8; 48])) {
        let encryption_key =
            hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let master_key = hex!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

        let mut encrypted = hmac_sha256_siv::encrypt(&encryption_key, &master_key);
        corrupt(&mut encrypted);
        assert_eq!(None, hmac_sha256_siv::decrypt(&encryption_key, &encrypted));
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let mut encryption_key =
            hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let master_key = hex!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

        let encrypted = hmac_sha256_siv::encrypt(&encryption_key, &master_key);
        encryption_key[0] ^= 1;
        assert_eq!(None, hmac_sha256_siv::decrypt(&encryption_key, &encrypted));
    }

    #[test]
    fn known_salt() {
        let username = "username";
        let group_id = 3862621253427332054u64;
        assert_eq!(
            PinHash::make_salt(username, group_id),
            hex!("d6159ba30f90b6eb6ccf1ec844427f052baaf0705da849767471744cdb3f8a5e"),
        );
    }
}
