//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::{api, crypto};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct CallLinkSecretParams {
    reserved: ReservedBytes,
    pub(crate) uid_enc_key_pair: crypto::uid_encryption::KeyPair,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct CallLinkPublicParams {
    reserved: ReservedBytes,
    pub(crate) uid_enc_public_key: crypto::uid_encryption::PublicKey,
}

impl CallLinkSecretParams {
    pub fn derive_from_root_key(root_key: &[u8]) -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20230419_CallLinkSecretParams_DeriveFromRootKey",
            root_key,
        );
        let uid_enc_key_pair = crypto::uid_encryption::KeyPair::derive_from(&mut sho);

        Self {
            reserved: Default::default(),
            uid_enc_key_pair,
        }
    }

    pub fn get_public_params(&self) -> CallLinkPublicParams {
        CallLinkPublicParams {
            reserved: Default::default(),
            uid_enc_public_key: self.uid_enc_key_pair.get_public_key(),
        }
    }

    pub fn encrypt_uid(&self, user_id: libsignal_protocol::Aci) -> api::groups::UuidCiphertext {
        let uid = crypto::uid_struct::UidStruct::from_service_id(user_id.into());
        self.encrypt_uid_struct(uid)
    }

    fn encrypt_uid_struct(
        &self,
        uid: crypto::uid_struct::UidStruct,
    ) -> api::groups::UuidCiphertext {
        let ciphertext = self.uid_enc_key_pair.encrypt(uid);
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext,
        }
    }

    pub fn decrypt_uid(
        &self,
        ciphertext: api::groups::UuidCiphertext,
    ) -> Result<libsignal_protocol::Aci, ZkGroupVerificationFailure> {
        let uid = self.uid_enc_key_pair.decrypt(ciphertext.ciphertext)?;
        uid.try_into().map_err(|_| ZkGroupVerificationFailure)
    }
}
