//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::errors::*;
use crate::common::serialization::ReservedByte;
use crate::common::sho::*;
use crate::crypto::uid_encryption;
use crate::{api, crypto};

#[derive(Copy, Clone, Serialize, Deserialize, PartialDefault)]
pub struct CallLinkSecretParams {
    reserved: ReservedByte,
    pub(crate) uid_enc_key_pair:
        zkcredential::attributes::KeyPair<crypto::uid_encryption::UidEncryptionDomain>,
}

impl AsRef<uid_encryption::KeyPair> for CallLinkSecretParams {
    fn as_ref(&self) -> &uid_encryption::KeyPair {
        &self.uid_enc_key_pair
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialDefault)]
pub struct CallLinkPublicParams {
    reserved: ReservedByte,
    pub(crate) uid_enc_public_key:
        zkcredential::attributes::PublicKey<crypto::uid_encryption::UidEncryptionDomain>,
}

impl CallLinkSecretParams {
    const ROOT_KEY_MAX_BYTES_FOR_SHO: usize = 16;

    pub fn derive_from_root_key(root_key: &[u8]) -> Self {
        let byte_count = Self::ROOT_KEY_MAX_BYTES_FOR_SHO.min(root_key.len());
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20230419_CallLinkSecretParams_DeriveFromRootKey",
            &root_key[..byte_count],
        );
        let uid_enc_key_pair = zkcredential::attributes::KeyPair::derive_from(sho.as_mut());

        Self {
            reserved: Default::default(),
            uid_enc_key_pair,
        }
    }

    pub fn get_public_params(&self) -> CallLinkPublicParams {
        CallLinkPublicParams {
            reserved: Default::default(),
            uid_enc_public_key: self.uid_enc_key_pair.public_key,
        }
    }

    pub fn encrypt_uid(&self, user_id: libsignal_core::Aci) -> api::groups::UuidCiphertext {
        let uid = crypto::uid_struct::UidStruct::from_service_id(user_id.into());
        self.encrypt_uid_struct(uid)
    }

    fn encrypt_uid_struct(
        &self,
        uid: crypto::uid_struct::UidStruct,
    ) -> api::groups::UuidCiphertext {
        let ciphertext = self.uid_enc_key_pair.encrypt(&uid);
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext,
        }
    }

    pub fn decrypt_uid(
        &self,
        ciphertext: api::groups::UuidCiphertext,
    ) -> Result<libsignal_core::Aci, ZkGroupVerificationFailure> {
        let uid = crypto::uid_encryption::UidEncryptionDomain::decrypt(
            &self.uid_enc_key_pair,
            &ciphertext.ciphertext,
        )?;
        uid.try_into().map_err(|_| ZkGroupVerificationFailure)
    }
}

#[cfg(test)]
mod tests {
    use crate::call_links::CallLinkSecretParams;

    #[test]
    fn test_call_link_secret_params_ignores_extra_bytes() {
        let bytes_0 = b"0123456789012345";
        let bytes_1 = b"012345678901234512345";

        assert_eq!(
            bytes_0.len(),
            CallLinkSecretParams::ROOT_KEY_MAX_BYTES_FOR_SHO
        );

        assert!(bytes_1.len() > CallLinkSecretParams::ROOT_KEY_MAX_BYTES_FOR_SHO);

        let secret_params_0 = CallLinkSecretParams::derive_from_root_key(bytes_0);
        let secret_params_1 = CallLinkSecretParams::derive_from_root_key(bytes_1);

        assert_eq!(
            secret_params_0.uid_enc_key_pair.a1,
            secret_params_1.uid_enc_key_pair.a1
        );
        assert_eq!(
            secret_params_0.uid_enc_key_pair.a2,
            secret_params_1.uid_enc_key_pair.a2
        );
        assert!(
            secret_params_0.uid_enc_key_pair.public_key
                == secret_params_1.uid_enc_key_pair.public_key
        );
    }
}
