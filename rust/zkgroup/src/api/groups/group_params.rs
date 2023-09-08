//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto;

use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::{api, crypto};
use aead::generic_array::GenericArray;
use aead::{Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize, Default)]
pub struct GroupMasterKey {
    pub(crate) bytes: [u8; GROUP_MASTER_KEY_LEN],
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct GroupSecretParams {
    reserved: ReservedBytes,
    master_key: GroupMasterKey,
    group_id: GroupIdentifierBytes,
    blob_key: AesKeyBytes,
    pub(crate) uid_enc_key_pair: crypto::uid_encryption::KeyPair,
    pub(crate) profile_key_enc_key_pair: crypto::profile_key_encryption::KeyPair,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct GroupPublicParams {
    reserved: ReservedBytes,
    group_id: GroupIdentifierBytes,
    pub(crate) uid_enc_public_key: crypto::uid_encryption::PublicKey,
    pub(crate) profile_key_enc_public_key: crypto::profile_key_encryption::PublicKey,
}

impl GroupMasterKey {
    pub fn new(bytes: [u8; GROUP_MASTER_KEY_LEN]) -> Self {
        GroupMasterKey { bytes }
    }
}

const ENCRYPTED_BLOB_PADDING_LENGTH_SIZE: usize = std::mem::size_of::<u32>();

impl GroupSecretParams {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_GroupSecretParams_Generate",
            &randomness,
        );
        let mut master_key: GroupMasterKey = Default::default();
        master_key
            .bytes
            .copy_from_slice(&sho.squeeze(GROUP_MASTER_KEY_LEN)[..]);
        GroupSecretParams::derive_from_master_key(master_key)
    }

    pub fn derive_from_master_key(master_key: GroupMasterKey) -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_GroupMasterKey_GroupSecretParams_DeriveFromMasterKey",
            &master_key.bytes,
        );
        let mut group_id: GroupIdentifierBytes = Default::default();
        let mut blob_key: AesKeyBytes = Default::default();
        group_id.copy_from_slice(&sho.squeeze(GROUP_IDENTIFIER_LEN)[..]);
        blob_key.copy_from_slice(&sho.squeeze(AES_KEY_LEN)[..]);
        let uid_enc_key_pair = crypto::uid_encryption::KeyPair::derive_from(&mut sho);
        let profile_key_enc_key_pair =
            crypto::profile_key_encryption::KeyPair::derive_from(&mut sho);

        Self {
            reserved: Default::default(),
            master_key,
            group_id,
            blob_key,
            uid_enc_key_pair,
            profile_key_enc_key_pair,
        }
    }

    pub fn get_master_key(&self) -> GroupMasterKey {
        self.master_key
    }

    pub fn get_group_identifier(&self) -> GroupIdentifierBytes {
        self.group_id
    }

    pub fn get_public_params(&self) -> GroupPublicParams {
        GroupPublicParams {
            reserved: Default::default(),
            uid_enc_public_key: self.uid_enc_key_pair.get_public_key(),
            profile_key_enc_public_key: self.profile_key_enc_key_pair.get_public_key(),
            group_id: self.group_id,
        }
    }

    pub fn encrypt_service_id(
        &self,
        service_id: libsignal_protocol::ServiceId,
    ) -> api::groups::UuidCiphertext {
        let uid = crypto::uid_struct::UidStruct::from_service_id(service_id);
        self.encrypt_uid_struct(uid)
    }

    pub fn encrypt_uid_struct(
        &self,
        uid: crypto::uid_struct::UidStruct,
    ) -> api::groups::UuidCiphertext {
        let ciphertext = self.uid_enc_key_pair.encrypt(uid);
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext,
        }
    }

    pub fn decrypt_service_id(
        &self,
        ciphertext: api::groups::UuidCiphertext,
    ) -> Result<libsignal_protocol::ServiceId, ZkGroupVerificationFailure> {
        self.uid_enc_key_pair.decrypt(ciphertext.ciphertext)
    }

    pub fn encrypt_profile_key(
        &self,
        profile_key: api::profiles::ProfileKey,
        user_id: libsignal_protocol::Aci,
    ) -> api::groups::ProfileKeyCiphertext {
        self.encrypt_profile_key_bytes(profile_key.bytes, user_id)
    }

    pub fn encrypt_profile_key_bytes(
        &self,
        profile_key_bytes: ProfileKeyBytes,
        user_id: libsignal_protocol::Aci,
    ) -> api::groups::ProfileKeyCiphertext {
        let profile_key = crypto::profile_key_struct::ProfileKeyStruct::new(
            profile_key_bytes,
            uuid::Uuid::from(user_id).into_bytes(),
        );
        let ciphertext = self.profile_key_enc_key_pair.encrypt(profile_key);
        api::groups::ProfileKeyCiphertext {
            reserved: Default::default(),
            ciphertext,
        }
    }

    pub fn decrypt_profile_key(
        &self,
        ciphertext: api::groups::ProfileKeyCiphertext,
        user_id: libsignal_protocol::Aci,
    ) -> Result<api::profiles::ProfileKey, ZkGroupVerificationFailure> {
        let profile_key_struct = self.profile_key_enc_key_pair.decrypt(
            ciphertext.ciphertext,
            uuid::Uuid::from(user_id).into_bytes(),
        )?;
        Ok(api::profiles::ProfileKey {
            bytes: profile_key_struct.bytes,
        })
    }

    pub fn encrypt_blob(&self, randomness: RandomnessBytes, plaintext: &[u8]) -> Vec<u8> {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_GroupSecretParams_EncryptBlob",
            &randomness,
        );
        let nonce_vec = sho.squeeze(AESGCM_NONCE_LEN);
        let mut ciphertext_vec =
            self.encrypt_blob_aesgcmsiv(&self.blob_key, &nonce_vec[..], plaintext);
        ciphertext_vec.extend(nonce_vec);
        ciphertext_vec.extend([0u8]); // reserved byte
        ciphertext_vec
    }

    pub fn encrypt_blob_with_padding(
        &self,
        randomness: RandomnessBytes,
        plaintext: &[u8],
        padding_len: u32,
    ) -> Vec<u8> {
        let full_length =
            ENCRYPTED_BLOB_PADDING_LENGTH_SIZE + plaintext.len() + padding_len as usize;
        let mut padded_plaintext = Vec::with_capacity(full_length);
        padded_plaintext.extend_from_slice(&padding_len.to_be_bytes());
        padded_plaintext.extend_from_slice(plaintext);
        padded_plaintext.resize(full_length, 0);
        self.encrypt_blob(randomness, &padded_plaintext)
    }

    pub fn decrypt_blob(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
        if ciphertext.len() < AESGCM_NONCE_LEN + 1 {
            // AESGCM_NONCE_LEN = 12 bytes for IV
            return Err(ZkGroupVerificationFailure);
        }
        let unreserved_len = ciphertext.len() - 1;
        let nonce = &ciphertext[unreserved_len - AESGCM_NONCE_LEN..unreserved_len];
        let ciphertext = &ciphertext[..unreserved_len - AESGCM_NONCE_LEN];
        self.decrypt_blob_aesgcmsiv(&self.blob_key, nonce, ciphertext)
    }

    pub fn decrypt_blob_with_padding(
        &self,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
        let mut decrypted = self.decrypt_blob(ciphertext)?;

        if decrypted.len() < ENCRYPTED_BLOB_PADDING_LENGTH_SIZE {
            return Err(ZkGroupVerificationFailure);
        }
        let (padding_len_bytes, plaintext_plus_padding) =
            decrypted.split_at(ENCRYPTED_BLOB_PADDING_LENGTH_SIZE);

        let padding_len = u32::from_be_bytes(padding_len_bytes.try_into().expect("correct size"));
        if plaintext_plus_padding.len() < padding_len as usize {
            return Err(ZkGroupVerificationFailure);
        }

        decrypted.truncate(decrypted.len() - padding_len as usize);
        decrypted.drain(..ENCRYPTED_BLOB_PADDING_LENGTH_SIZE);
        Ok(decrypted)
    }

    fn encrypt_blob_aesgcmsiv(&self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let key = GenericArray::from_slice(key);
        let aead_cipher = Aes256GcmSiv::new(key);
        let nonce = GenericArray::from_slice(nonce);
        aead_cipher
            .encrypt(nonce, plaintext)
            .expect("aead encrypt failure")
    }

    fn decrypt_blob_aesgcmsiv(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
        if ciphertext.len() < AESGCM_TAG_LEN {
            // AESGCM_TAG_LEN = 16 bytes for tag
            return Err(ZkGroupVerificationFailure);
        }
        let key = GenericArray::from_slice(key);
        let aead_cipher = Aes256GcmSiv::new(key);
        let nonce = GenericArray::from_slice(nonce);
        match aead_cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext_vec) => Ok(plaintext_vec),
            Err(_) => Err(ZkGroupVerificationFailure),
        }
    }
}

impl GroupPublicParams {
    pub fn get_group_identifier(&self) -> GroupIdentifierBytes {
        self.group_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aesgcmsiv_vec1() {
        // https://tools.ietf.org/html/rfc8452#appendix-C

        let group_secret_params = GroupSecretParams::generate([0u8; RANDOMNESS_LEN]);

        let plaintext_vec = vec![
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let key_vec = vec![
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let nonce_vec = vec![
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let ciphertext_vec = vec![
            0x4a, 0x6a, 0x9d, 0xb4, 0xc8, 0xc6, 0x54, 0x92, 0x01, 0xb9, 0xed, 0xb5, 0x30, 0x06,
            0xcb, 0xa8, 0x21, 0xec, 0x9c, 0xf8, 0x50, 0x94, 0x8a, 0x7c, 0x86, 0xc6, 0x8a, 0xc7,
            0x53, 0x9d, 0x02, 0x7f, 0xe8, 0x19, 0xe6, 0x3a, 0xbc, 0xd0, 0x20, 0xb0, 0x06, 0xa9,
            0x76, 0x39, 0x76, 0x32, 0xeb, 0x5d,
        ];

        let calc_ciphertext =
            group_secret_params.encrypt_blob_aesgcmsiv(&key_vec, &nonce_vec, &plaintext_vec);

        assert!(calc_ciphertext[..ciphertext_vec.len()] == ciphertext_vec[..]);

        let calc_plaintext = group_secret_params
            .decrypt_blob_aesgcmsiv(&key_vec, &nonce_vec, &calc_ciphertext)
            .unwrap();
        assert!(calc_plaintext[..] == plaintext_vec[..]);
    }

    #[test]
    fn test_aesgcmsiv_vec2() {
        // https://tools.ietf.org/html/rfc8452#appendix-C

        let group_secret_params = GroupSecretParams::generate([0u8; RANDOMNESS_LEN]);

        let plaintext_vec = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x4d, 0xb9, 0x23, 0xdc, 0x79, 0x3e, 0xe6, 0x49, 0x7c, 0x76, 0xdc, 0xc0,
            0x3a, 0x98, 0xe1, 0x08,
        ];

        let key_vec = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let nonce_vec = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let ciphertext_vec = vec![
            0xf3, 0xf8, 0x0f, 0x2c, 0xf0, 0xcb, 0x2d, 0xd9, 0xc5, 0x98, 0x4f, 0xcd, 0xa9, 0x08,
            0x45, 0x6c, 0xc5, 0x37, 0x70, 0x3b, 0x5b, 0xa7, 0x03, 0x24, 0xa6, 0x79, 0x3a, 0x7b,
            0xf2, 0x18, 0xd3, 0xea, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let calc_ciphertext =
            group_secret_params.encrypt_blob_aesgcmsiv(&key_vec, &nonce_vec, &plaintext_vec);

        assert!(calc_ciphertext[..ciphertext_vec.len()] == ciphertext_vec[..]);

        let calc_plaintext = group_secret_params
            .decrypt_blob_aesgcmsiv(&key_vec, &nonce_vec, &calc_ciphertext)
            .unwrap();
        assert!(calc_plaintext[..] == plaintext_vec[..]);
    }

    #[test]
    fn test_encrypt_with_padding() {
        let group_secret_params = GroupSecretParams::generate([0u8; RANDOMNESS_LEN]);
        let plaintext = b"secret team";

        {
            let expected_ciphertext_hex = "3798afe9c65ffb35a63b2c048b16f19dd50ee9acc33cc925667a9abad4d4c6f86675fa8e32243e0831203700";

            let calc_ciphertext =
                group_secret_params.encrypt_blob_with_padding([0u8; RANDOMNESS_LEN], plaintext, 0);
            assert_eq!(hex::encode(&calc_ciphertext), expected_ciphertext_hex);

            let calc_plaintext = group_secret_params
                .decrypt_blob_with_padding(&calc_ciphertext)
                .unwrap();
            assert_eq!(calc_plaintext[..], plaintext[..]);
        }

        {
            let expected_ciphertext_hex = "880a70e071b33f81e1219842c8514f34901abb734c191292ac325455d898da000484080099c620f86675fa8e32243e0831203700";

            let calc_ciphertext =
                group_secret_params.encrypt_blob_with_padding([0u8; RANDOMNESS_LEN], plaintext, 8);
            assert_eq!(hex::encode(&calc_ciphertext), expected_ciphertext_hex);

            let calc_plaintext = group_secret_params
                .decrypt_blob_with_padding(&calc_ciphertext)
                .unwrap();
            assert_eq!(calc_plaintext[..], plaintext[..]);
        }
    }
}
