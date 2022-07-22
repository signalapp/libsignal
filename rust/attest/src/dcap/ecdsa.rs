//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use boring::bn::BigNum;
use boring::ec::EcKeyRef;
use boring::ecdsa::{EcdsaSig, EcdsaSigRef};
use boring::pkey::Public;
use sha2::Digest;

use crate::dcap::{Error, Result};

/// Deserialize a 64 byte ECDSA Signature
pub(crate) fn ecdsa_signature_from_bytes(bytes: &[u8; 64]) -> Result<EcdsaSig> {
    let bnr = BigNum::from_slice(&bytes[..32]).expect("can always create a 32-byte bignum");
    let bns = BigNum::from_slice(&bytes[32..]).expect("can always create a 32-byte bignum");
    Ok(EcdsaSig::from_private_components(bnr, bns)?)
}

pub(crate) fn deserialize_ecdsa_signature<'de, D>(de: D) -> std::result::Result<EcdsaSig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let array: [u8; 64] = hex::deserialize(de)?;
    ecdsa_signature_from_bytes(&array).map_err(|_| {
        serde::de::Error::invalid_value(
            serde::de::Unexpected::Bytes(&array),
            &"a valid raw ECDSA signature",
        )
    })
}

pub(crate) trait EcdsaSigned {
    fn data(&self) -> &[u8];
    fn signature(&self) -> &EcdsaSigRef;

    fn verify_signature(&self, public_key: &EcKeyRef<Public>) -> crate::dcap::Result<()> {
        let hash = sha2::Sha256::digest(self.data());
        let result = self.signature().verify(&hash, public_key).unwrap_or(false);

        if !result {
            #[cfg(not(fuzzing))]
            return Err(Error::new("data did not match signature"));
        }

        Ok(())
    }
}
