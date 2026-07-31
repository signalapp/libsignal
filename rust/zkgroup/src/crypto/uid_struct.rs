//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use curve25519_dalek::ristretto::RistrettoPoint;
use libsignal_core::ServiceId;
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::common::sho::*;
use crate::common::simple_types::*;

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub struct UidStruct {
    // Currently unused. It would be possible to convert this back to the correct kind of ServiceId
    // using the same technique as decryption: comparing possible M1 points and seeing which one
    // matches. But we don't have a need for that, and therefore it's better if that operation
    // remains part of decryption, so that you're guaranteed to get a valid result or an error in
    // one step.
    //
    // At the same time, we can't just remove the field: it's serialized as part of AuthCredential
    // and AuthCredentialWithPni, which clients store locally.
    #[serde(rename = "bytes")]
    raw_uuid_bytes: UidBytes,
    pub(crate) M1: RistrettoPoint,
    pub(crate) M2: RistrettoPoint,
}

impl UidStruct {
    pub fn from_service_id(service_id: ServiceId) -> Self {
        let M1 = Self::calc_M1(Self::seed_M1(), service_id);
        let raw_uuid_bytes = service_id.raw_uuid().into_bytes();
        let M2 = RistrettoPoint::lizard_encode::<Sha256>(&raw_uuid_bytes);
        UidStruct {
            raw_uuid_bytes,
            M1,
            M2,
        }
    }

    pub(crate) fn for_false_pni_derived_from_aci(aci: libsignal_core::Aci, salt: &[u8]) -> Self {
        // A v7 UUID generated on 2026-07-28.
        const FALSE_PNI_NAMESPACE: uuid::Uuid = uuid::uuid!("019faa2b-7bcb-70c2-ac7f-cd770414689a");
        // Hash the salt so that it less directly affects the older SHA-1 used by UUIDv5.
        let hashed_salt = Sha256::digest(salt);
        let false_pni = libsignal_core::Pni::from(new_v5_uuid(
            &FALSE_PNI_NAMESPACE,
            &hashed_salt,
            uuid::Uuid::from(aci).as_bytes(),
        ));
        Self {
            // Nothing reads this field; it's present only for debugging and backwards
            // compatibility. Filling it with zeros marks that it's not useful anyway.
            raw_uuid_bytes: uuid::Uuid::nil().into_bytes(),
            ..Self::from_service_id(false_pni.into())
        }
    }

    pub(crate) fn seed_M1() -> Sho {
        Sho::new_seed(b"Signal_ZKGroup_20200424_UID_CalcM1")
    }

    pub(crate) fn calc_M1(mut seed: Sho, service_id: ServiceId) -> RistrettoPoint {
        seed.absorb_and_ratchet(&service_id.service_id_binary());
        seed.get_point()
    }
}

impl zkcredential::attributes::Attribute for UidStruct {
    fn as_points(&self) -> [RistrettoPoint; 2] {
        [self.M1, self.M2]
    }
}

/// A reimplementation of `uuid::Uuid::new_v5` using the RustCrypto `sha1` crate.
///
/// `first_name_part` and `second_name_part` are directly concatenated; as such, one or the other of
/// them should be fixed-width to avoid "foo || bar" and "foob || ar" resulting in the same UUID.
///
/// See <https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-5>.
fn new_v5_uuid(
    namespace: &uuid::Uuid,
    first_name_part: &[u8],
    second_name_part: &[u8],
) -> uuid::Uuid {
    use sha1::Digest as _;
    let uuid_v5_style_hash = sha1::Sha1::new()
        .chain_update(namespace.as_bytes())
        .chain_update(first_name_part)
        .chain_update(second_name_part)
        .finalize();
    uuid::Builder::from_sha1_bytes(
        *uuid_v5_style_hash
            .first_chunk()
            .expect("SHA-1 hashes are longer than UUIDs"),
    )
    .into_uuid()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn v5_uuid_test_vector_from_rfc() {
        let dns_namespace = uuid::uuid!("6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        assert_eq!(
            new_v5_uuid(&dns_namespace, b"www.example.com", b""),
            uuid::uuid!("2ed6657d-e927-568b-95e1-2665a8aea6a2")
        );
        assert_eq!(
            new_v5_uuid(&dns_namespace, b"www.", b"example.com"),
            uuid::uuid!("2ed6657d-e927-568b-95e1-2665a8aea6a2")
        );
    }
}
