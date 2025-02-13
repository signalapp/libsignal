//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use std::sync::LazyLock;

use curve25519_dalek_signal::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek_signal::ristretto::RistrettoPoint;
use curve25519_dalek_signal::scalar::Scalar;
use hex_literal::hex;
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::array_utils::{ArrayLike, OneBased};
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::receipt_struct::ReceiptStruct;
use crate::crypto::timestamp_struct::TimestampStruct;
use crate::crypto::{
    profile_key_credential_request, receipt_credential_request, receipt_struct, uid_struct,
};
use crate::{
    NUM_AUTH_CRED_ATTRIBUTES, NUM_PROFILE_KEY_CRED_ATTRIBUTES, NUM_RECEIPT_CRED_ATTRIBUTES,
};

static SYSTEM_PARAMS: LazyLock<SystemParams> =
    LazyLock::new(|| crate::deserialize::<SystemParams>(SystemParams::SYSTEM_HARDCODED).unwrap());

const NUM_SUPPORTED_ATTRS: usize = 6;
#[derive(Copy, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemParams {
    pub(crate) G_w: RistrettoPoint,
    pub(crate) G_wprime: RistrettoPoint,
    pub(crate) G_x0: RistrettoPoint,
    pub(crate) G_x1: RistrettoPoint,
    pub(crate) G_y: OneBased<[RistrettoPoint; NUM_SUPPORTED_ATTRS]>,
    pub(crate) G_m1: RistrettoPoint,
    pub(crate) G_m2: RistrettoPoint,
    pub(crate) G_m3: RistrettoPoint,
    pub(crate) G_m4: RistrettoPoint,
    pub(crate) G_m5: RistrettoPoint,
    pub(crate) G_V: RistrettoPoint,
    pub(crate) G_z: RistrettoPoint,
}

/// Used to specialize a [`KeyPair<S>`] to support a certain number of attributes.
///
/// The only required member is `Storage`, which should be a fixed-size array of [`Scalar`], one for
/// each attribute. However, for backwards compatibility some systems support fewer attributes than
/// are actually stored, and in this case the `NUM_ATTRS` member can be set to a custom value. Note
/// that `NUM_ATTRS` must always be less than or equal to the number of elements in `Storage`.
pub trait AttrScalars {
    /// The storage (should be a fixed-size array of Scalar).
    type Storage: ArrayLike<Scalar> + Copy + Eq + Serialize + for<'a> Deserialize<'a>;

    /// The number of attributes supported in this system.
    ///
    /// Defaults to the full set stored in `Self::Storage`.
    const NUM_ATTRS: usize = Self::Storage::LEN;
}

impl AttrScalars for AuthCredential {
    // Store four scalars for backwards compatibility.
    type Storage = [Scalar; 4];
    const NUM_ATTRS: usize = NUM_AUTH_CRED_ATTRIBUTES;
}
impl AttrScalars for AuthCredentialWithPni {
    type Storage = [Scalar; 5];
}
impl AttrScalars for ProfileKeyCredential {
    // Store four scalars for backwards compatibility.
    type Storage = [Scalar; 4];
    const NUM_ATTRS: usize = NUM_PROFILE_KEY_CRED_ATTRIBUTES;
}
impl AttrScalars for ExpiringProfileKeyCredential {
    type Storage = [Scalar; 5];
}
impl AttrScalars for ReceiptCredential {
    // Store four scalars for backwards compatibility.
    type Storage = [Scalar; 4];
    const NUM_ATTRS: usize = NUM_RECEIPT_CRED_ATTRIBUTES;
}
impl AttrScalars for PniCredential {
    type Storage = [Scalar; 6];
}

#[derive(Serialize, Deserialize, PartialDefault)]
#[partial_default(bound = "S::Storage: Default")]
pub struct KeyPair<S: AttrScalars> {
    // private
    pub(crate) w: Scalar,
    pub(crate) wprime: Scalar,
    pub(crate) W: RistrettoPoint,
    pub(crate) x0: Scalar,
    pub(crate) x1: Scalar,
    pub(crate) y: OneBased<S::Storage>,

    // public
    pub(crate) C_W: RistrettoPoint,
    pub(crate) I: RistrettoPoint,
}

impl<S: AttrScalars> Clone for KeyPair<S> {
    fn clone(&self) -> Self {
        // Rely on Copy
        *self
    }
}

impl<S: AttrScalars> Copy for KeyPair<S> {}

impl<S: AttrScalars> PartialEq for KeyPair<S> {
    fn eq(&self, other: &Self) -> bool {
        self.w == other.w
            && self.wprime == other.wprime
            && self.W == other.W
            && self.x0 == other.x0
            && self.x1 == other.x1
            && self.y == other.y
            && self.C_W == other.C_W
            && self.I == other.I
    }
}
impl<S: AttrScalars> Eq for KeyPair<S> {}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub struct PublicKey {
    pub(crate) C_W: RistrettoPoint,
    pub(crate) I: RistrettoPoint,
}

/// Unused, kept only because ServerSecretParams contains a `KeyPair<AuthCredential>`.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub(crate) struct AuthCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

/// Unused, kept only because ServerSecretParams contains a `KeyPair<AuthCredentialWithPni>`.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub(crate) struct AuthCredentialWithPni {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

/// Unused, kept only because ServerSecretParams contains a `KeyPair<ProfileKeyCredential>`.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileKeyCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub struct ExpiringProfileKeyCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedExpiringProfileKeyCredentialWithSecretNonce {
    pub(crate) rprime: Scalar,
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub struct BlindedExpiringProfileKeyCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

/// Unused, kept only because ServerSecretParams contains a `KeyPair<PniCredential>`.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PniCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub struct ReceiptCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedReceiptCredentialWithSecretNonce {
    pub(crate) rprime: Scalar,
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialDefault)]
pub struct BlindedReceiptCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

pub(crate) fn convert_to_points_receipt_struct(
    receipt: receipt_struct::ReceiptStruct,
) -> Vec<RistrettoPoint> {
    let system = SystemParams::get_hardcoded();
    let m1 = receipt.calc_m1();
    let receipt_serial_scalar = encode_receipt_serial_bytes(receipt.receipt_serial_bytes);
    vec![m1 * system.G_m1, receipt_serial_scalar * system.G_m2]
}

pub(crate) fn convert_to_point_M2_receipt_serial_bytes(
    receipt_serial_bytes: ReceiptSerialBytes,
) -> RistrettoPoint {
    let system = SystemParams::get_hardcoded();
    let receipt_serial_scalar = encode_receipt_serial_bytes(receipt_serial_bytes);
    receipt_serial_scalar * system.G_m2
}

impl SystemParams {
    #[cfg(test)]
    fn generate() -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Constant_Credentials_SystemParams_Generate",
            b"",
        );
        let G_w = sho.get_point();
        let G_wprime = sho.get_point();

        let G_x0 = sho.get_point();
        let G_x1 = sho.get_point();

        let G_y1 = sho.get_point();
        let G_y2 = sho.get_point();
        let G_y3 = sho.get_point();
        let G_y4 = sho.get_point();

        let G_m1 = sho.get_point();
        let G_m2 = sho.get_point();
        let G_m3 = sho.get_point();
        let G_m4 = sho.get_point();

        let G_V = sho.get_point();
        let G_z = sho.get_point();

        // We don't ever want to use existing generator points in new ways,
        // so new points have to be added at the end.
        let G_y5 = sho.get_point();
        let G_y6 = sho.get_point();

        let G_m5 = sho.get_point();

        SystemParams {
            G_w,
            G_wprime,
            G_x0,
            G_x1,
            G_y: OneBased([G_y1, G_y2, G_y3, G_y4, G_y5, G_y6]),
            G_m1,
            G_m2,
            G_m3,
            G_m4,
            G_m5,
            G_V,
            G_z,
        }
    }

    pub fn get_hardcoded() -> SystemParams {
        *SYSTEM_PARAMS
    }

    const SYSTEM_HARDCODED: &'static [u8] = &hex!("9ae7c8e5ed779b114ae7708aa2f794670adda324987b659913122c35505b105e6ca31025d2d76be7fd34944f98f7fa0e37babb2c8b98bbbdbd3dd1bf130cca2c8a9a3bdfaaa2b6b322d46b93eca7b0d51c86a3c839e11466358258a6c10c577fc2bffd34cd99164c9a6cd29fab55d91ff9269322ec3458603cc96a0d47f704058288f62ee0acedb8aa23242121d98965a9bb2991250c11758095ece0fd2b33285286fe1fcb056103b6081744b975f550d08521568dd3d8618f25c140375a0f4024c3aa23bdfffb27fbd982208d3ecd1fd3bcb7ac0c3a14b109804fc748d7fa456cffb4934f980b6e09a248a60f44a6150ae6c13d7e3c06261d7e4eed37f39f60b04dd9d607fd357012274d3c63dbb38e7378599c9e97dfbb28842694891d5f0ddc729919b798b4131503408cc57a9c532f4427632c88f54cea53861a5bc44c61cc6037dc31c2e8d4474fb519587a448693182ad9d6d86b535957858f547b9340127da75f8074caee944ac36c0ac662d38c9b3ccce03a093fcd9644047398b86b6e83372ff14fb8bb0dea65531252ac70d58a4a0810d682a0e709c9227b30ef6c8e17c5915d527221bb00da8175cd6489aa8aa492a500f9abee5690b9dfca8855dc0bd02a7f277add240f639ac16801e81574afb4683edff63b9a01e93dbd867a04b616c706c80c756c11a3016bbfb60977f4648b5f2395a4b428b7211940813e3afde2b87aa9c2c37bf716e2578f95656df12c2fb6f5d0631f6f71e2c3193f6d");
}

impl<S: AttrScalars> KeyPair<S> {
    pub fn generate(sho: &mut Sho) -> Self {
        assert!(S::NUM_ATTRS >= 1, "at least one attribute required");
        assert!(
            S::NUM_ATTRS <= NUM_SUPPORTED_ATTRS,
            "more than {} attributes not supported",
            NUM_SUPPORTED_ATTRS
        );
        assert!(
            S::NUM_ATTRS <= S::Storage::LEN,
            "more attributes than storage",
        );

        let system = SystemParams::get_hardcoded();
        let w = sho.get_scalar();
        let W = w * system.G_w;
        let wprime = sho.get_scalar();
        let x0 = sho.get_scalar();
        let x1 = sho.get_scalar();

        let y = OneBased::<S::Storage>::create(|| sho.get_scalar());

        let C_W = (w * system.G_w) + (wprime * system.G_wprime);
        let mut I = system.G_V - (x0 * system.G_x0) - (x1 * system.G_x1);

        for (yn, G_yn) in y.iter().zip(system.G_y.iter()).take(S::NUM_ATTRS) {
            I -= yn * G_yn;
        }

        KeyPair {
            w,
            wprime,
            W,
            x0,
            x1,
            y,
            C_W,
            I,
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey {
            C_W: self.C_W,
            I: self.I,
        }
    }

    fn credential_core(
        &self,
        M: &[RistrettoPoint],
        sho: &mut Sho,
    ) -> (Scalar, RistrettoPoint, RistrettoPoint) {
        assert!(
            M.len() <= S::NUM_ATTRS,
            "more than {} attributes not supported",
            S::NUM_ATTRS
        );
        let t = sho.get_scalar();
        let U = sho.get_point();

        let mut V = self.W + (self.x0 + self.x1 * t) * U;
        for (yn, Mn) in self.y.iter().zip(M) {
            V += yn * Mn;
        }
        (t, U, V)
    }
}

impl KeyPair<ExpiringProfileKeyCredential> {
    pub fn create_blinded_expiring_profile_key_credential(
        &self,
        uid: uid_struct::UidStruct,
        public_key: profile_key_credential_request::PublicKey,
        ciphertext: profile_key_credential_request::Ciphertext,
        credential_expiration_time: Timestamp,
        sho: &mut Sho,
    ) -> BlindedExpiringProfileKeyCredentialWithSecretNonce {
        let M = [uid.M1, uid.M2];

        let (t, U, Vprime) = self.credential_core(&M, sho);

        let params = SystemParams::get_hardcoded();
        let m5 = TimestampStruct::calc_m_from(credential_expiration_time);
        let M5 = m5 * params.G_m5;
        let Vprime_with_expiration = Vprime + (self.y[5] * M5);

        let rprime = sho.get_scalar();
        let R1 = rprime * RISTRETTO_BASEPOINT_POINT;
        let R2 = rprime * public_key.Y + Vprime_with_expiration;
        let S1 = R1 + (self.y[3] * ciphertext.D1) + (self.y[4] * ciphertext.E1);
        let S2 = R2 + (self.y[3] * ciphertext.D2) + (self.y[4] * ciphertext.E2);
        BlindedExpiringProfileKeyCredentialWithSecretNonce {
            rprime,
            t,
            U,
            S1,
            S2,
        }
    }
}

impl KeyPair<ReceiptCredential> {
    pub fn create_blinded_receipt_credential(
        &self,
        public_key: receipt_credential_request::PublicKey,
        ciphertext: receipt_credential_request::Ciphertext,
        receipt_expiration_time: Timestamp,
        receipt_level: ReceiptLevel,
        sho: &mut Sho,
    ) -> BlindedReceiptCredentialWithSecretNonce {
        let params = SystemParams::get_hardcoded();
        let m1 = ReceiptStruct::calc_m1_from(receipt_expiration_time, receipt_level);
        let M = [m1 * params.G_m1];

        let (t, U, Vprime) = self.credential_core(&M, sho);
        let rprime = sho.get_scalar();
        let R1 = rprime * RISTRETTO_BASEPOINT_POINT;
        let R2 = rprime * public_key.Y + Vprime;
        let S1 = self.y[2] * ciphertext.D1 + R1;
        let S2 = self.y[2] * ciphertext.D2 + R2;
        BlindedReceiptCredentialWithSecretNonce {
            rprime,
            t,
            U,
            S1,
            S2,
        }
    }
}

impl BlindedExpiringProfileKeyCredentialWithSecretNonce {
    pub fn get_blinded_expiring_profile_key_credential(
        &self,
    ) -> BlindedExpiringProfileKeyCredential {
        BlindedExpiringProfileKeyCredential {
            t: self.t,
            U: self.U,
            S1: self.S1,
            S2: self.S2,
        }
    }
}

impl BlindedReceiptCredentialWithSecretNonce {
    pub fn get_blinded_receipt_credential(&self) -> BlindedReceiptCredential {
        BlindedReceiptCredential {
            t: self.t,
            U: self.U,
            S1: self.S1,
            S2: self.S2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;
    use crate::crypto::proofs;

    #[test]
    fn test_system() {
        let params = SystemParams::generate();
        println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());
    }

    #[test]
    fn test_mac() {
        // It doesn't really matter *which* credential we test here, we just want to generally know
        // we've set things up correctly. (Also, the credentials hardcoded here in zkgroup may
        // eventually all be superseded by implementations using zkcredential, at which point this
        // test can be deleted.)
        let mut sho = Sho::new(b"Test_Credentials", b"");
        let keypair = KeyPair::<ExpiringProfileKeyCredential>::generate(&mut sho);

        let uid_bytes = TEST_ARRAY_16;
        let redemption_time = Timestamp::from_epoch_seconds(37 * SECONDS_PER_DAY);
        let aci = libsignal_core::Aci::from_uuid_bytes(uid_bytes);
        let aci_struct = uid_struct::UidStruct::from_service_id(aci.into());
        let profile_key_struct = crate::crypto::profile_key_struct::ProfileKeyStruct::new(
            [1; PROFILE_KEY_LEN],
            uid_bytes,
        );
        let request_key_pair =
            crate::crypto::profile_key_credential_request::KeyPair::generate(&mut sho);
        let ciphertext = request_key_pair
            .encrypt(profile_key_struct, &mut sho)
            .get_ciphertext();
        let credential = keypair.create_blinded_expiring_profile_key_credential(
            aci_struct,
            request_key_pair.get_public_key(),
            ciphertext,
            redemption_time,
            &mut sho,
        );
        let proof = proofs::ExpiringProfileKeyCredentialIssuanceProof::new(
            keypair,
            request_key_pair.get_public_key(),
            ciphertext,
            credential,
            aci_struct,
            redemption_time,
            &mut sho,
        );

        let public_key = keypair.get_public_key();
        proof
            .verify(
                public_key,
                request_key_pair.get_public_key(),
                uid_bytes,
                ciphertext,
                credential.get_blinded_expiring_profile_key_credential(),
                redemption_time,
            )
            .unwrap();

        let keypair_bytes = bincode::serialize(&keypair).unwrap();
        let keypair2 = bincode::deserialize(&keypair_bytes).unwrap();
        assert!(keypair == keypair2);

        let public_key_bytes = bincode::serialize(&public_key).unwrap();
        let public_key2 = bincode::deserialize(&public_key_bytes).unwrap();
        assert!(public_key == public_key2);

        let mac_bytes = bincode::serialize(&credential).unwrap();

        println!("mac_bytes = {}", hex::encode(&mac_bytes));
        assert_eq!(
            mac_bytes,
            hex!(
                "ef47110715831160100f14d1936f4349c45b80ccaacd4edd9f949375d2d90a090888d81f8b0ed313
                808b5ff7ec1957ed4e8b3d9c195b3a5abdbdd3d972c29809100a7f8dc2354be7a1d44452cbadd87e
                4851ae05ebeb2586b856d35af765883a94473ad855df8583be2930e4e1d5756175a9091f2be1d8d0
                21280446a7611841d6b4f2eb165267a9d1d7a800f19c2077a4ef7df721b160fe200181be3c455f1c"
            )
        );
    }
}
