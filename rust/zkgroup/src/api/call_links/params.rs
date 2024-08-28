//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::errors::*;
use crate::common::serialization::ReservedByte;
use crate::common::sho::*;
use crate::{api, crypto};

#[derive(Copy, Clone, Serialize, Deserialize, PartialDefault)]
pub struct CallLinkSecretParams {
    reserved: ReservedByte,
    pub(crate) uid_enc_key_pair:
        zkcredential::attributes::KeyPair<crypto::uid_encryption::UidEncryptionDomain>,
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialDefault)]
pub struct CallLinkPublicParams {
    reserved: ReservedByte,
    pub(crate) uid_enc_public_key:
        zkcredential::attributes::PublicKey<crypto::uid_encryption::UidEncryptionDomain>,
}

impl CallLinkSecretParams {
    pub fn derive_from_root_key(root_key: &[u8]) -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20230419_CallLinkSecretParams_DeriveFromRootKey",
            root_key,
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
