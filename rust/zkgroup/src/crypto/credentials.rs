//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
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

use lazy_static::lazy_static;

lazy_static! {
    static ref SYSTEM_PARAMS: SystemParams =
        bincode::deserialize::<SystemParams>(SystemParams::SYSTEM_HARDCODED).unwrap();
}

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

#[derive(Serialize, Deserialize)]
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

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) C_W: RistrettoPoint,
    pub(crate) I: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthCredentialWithPni {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

/// Unused, kept only because ServerSecretParams contains a KeyPair<ProfileKeyCredential>.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileKeyCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedExpiringProfileKeyCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

/// Unused, kept only because ServerSecretParams contains a KeyPair<PniCredential>.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PniCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedReceiptCredential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) S1: RistrettoPoint,
    pub(crate) S2: RistrettoPoint,
}

pub(crate) fn convert_to_points_uid_struct(
    uid: uid_struct::UidStruct,
    redemption_time: CoarseRedemptionTime,
) -> Vec<RistrettoPoint> {
    let system = SystemParams::get_hardcoded();
    let redemption_time_scalar = encode_redemption_time(redemption_time);
    vec![uid.M1, uid.M2, redemption_time_scalar * system.G_m3]
}

pub(crate) fn convert_to_points_aci_pni_timestamp(
    aci: uid_struct::UidStruct,
    pni: uid_struct::UidStruct,
    redemption_time: Timestamp,
) -> Vec<RistrettoPoint> {
    let system = SystemParams::get_hardcoded();
    let redemption_time_scalar = TimestampStruct::calc_m_from(redemption_time);
    vec![
        aci.M1,
        aci.M2,
        pni.M1,
        pni.M2,
        redemption_time_scalar * system.G_m5,
    ]
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

    const SYSTEM_HARDCODED: &'static [u8] = &[
        0x9a, 0xe7, 0xc8, 0xe5, 0xed, 0x77, 0x9b, 0x11, 0x4a, 0xe7, 0x70, 0x8a, 0xa2, 0xf7, 0x94,
        0x67, 0xa, 0xdd, 0xa3, 0x24, 0x98, 0x7b, 0x65, 0x99, 0x13, 0x12, 0x2c, 0x35, 0x50, 0x5b,
        0x10, 0x5e, 0x6c, 0xa3, 0x10, 0x25, 0xd2, 0xd7, 0x6b, 0xe7, 0xfd, 0x34, 0x94, 0x4f, 0x98,
        0xf7, 0xfa, 0xe, 0x37, 0xba, 0xbb, 0x2c, 0x8b, 0x98, 0xbb, 0xbd, 0xbd, 0x3d, 0xd1, 0xbf,
        0x13, 0xc, 0xca, 0x2c, 0x8a, 0x9a, 0x3b, 0xdf, 0xaa, 0xa2, 0xb6, 0xb3, 0x22, 0xd4, 0x6b,
        0x93, 0xec, 0xa7, 0xb0, 0xd5, 0x1c, 0x86, 0xa3, 0xc8, 0x39, 0xe1, 0x14, 0x66, 0x35, 0x82,
        0x58, 0xa6, 0xc1, 0xc, 0x57, 0x7f, 0xc2, 0xbf, 0xfd, 0x34, 0xcd, 0x99, 0x16, 0x4c, 0x9a,
        0x6c, 0xd2, 0x9f, 0xab, 0x55, 0xd9, 0x1f, 0xf9, 0x26, 0x93, 0x22, 0xec, 0x34, 0x58, 0x60,
        0x3c, 0xc9, 0x6a, 0xd, 0x47, 0xf7, 0x4, 0x5, 0x82, 0x88, 0xf6, 0x2e, 0xe0, 0xac, 0xed,
        0xb8, 0xaa, 0x23, 0x24, 0x21, 0x21, 0xd9, 0x89, 0x65, 0xa9, 0xbb, 0x29, 0x91, 0x25, 0xc,
        0x11, 0x75, 0x80, 0x95, 0xec, 0xe0, 0xfd, 0x2b, 0x33, 0x28, 0x52, 0x86, 0xfe, 0x1f, 0xcb,
        0x5, 0x61, 0x3, 0xb6, 0x8, 0x17, 0x44, 0xb9, 0x75, 0xf5, 0x50, 0xd0, 0x85, 0x21, 0x56,
        0x8d, 0xd3, 0xd8, 0x61, 0x8f, 0x25, 0xc1, 0x40, 0x37, 0x5a, 0xf, 0x40, 0x24, 0xc3, 0xaa,
        0x23, 0xbd, 0xff, 0xfb, 0x27, 0xfb, 0xd9, 0x82, 0x20, 0x8d, 0x3e, 0xcd, 0x1f, 0xd3, 0xbc,
        0xb7, 0xac, 0xc, 0x3a, 0x14, 0xb1, 0x9, 0x80, 0x4f, 0xc7, 0x48, 0xd7, 0xfa, 0x45, 0x6c,
        0xff, 0xb4, 0x93, 0x4f, 0x98, 0xb, 0x6e, 0x9, 0xa2, 0x48, 0xa6, 0xf, 0x44, 0xa6, 0x15, 0xa,
        0xe6, 0xc1, 0x3d, 0x7e, 0x3c, 0x6, 0x26, 0x1d, 0x7e, 0x4e, 0xed, 0x37, 0xf3, 0x9f, 0x60,
        0xb0, 0x4d, 0xd9, 0xd6, 0x7, 0xfd, 0x35, 0x70, 0x12, 0x27, 0x4d, 0x3c, 0x63, 0xdb, 0xb3,
        0x8e, 0x73, 0x78, 0x59, 0x9c, 0x9e, 0x97, 0xdf, 0xbb, 0x28, 0x84, 0x26, 0x94, 0x89, 0x1d,
        0x5f, 0xd, 0xdc, 0x72, 0x99, 0x19, 0xb7, 0x98, 0xb4, 0x13, 0x15, 0x3, 0x40, 0x8c, 0xc5,
        0x7a, 0x9c, 0x53, 0x2f, 0x44, 0x27, 0x63, 0x2c, 0x88, 0xf5, 0x4c, 0xea, 0x53, 0x86, 0x1a,
        0x5b, 0xc4, 0x4c, 0x61, 0xcc, 0x60, 0x37, 0xdc, 0x31, 0xc2, 0xe8, 0xd4, 0x47, 0x4f, 0xb5,
        0x19, 0x58, 0x7a, 0x44, 0x86, 0x93, 0x18, 0x2a, 0xd9, 0xd6, 0xd8, 0x6b, 0x53, 0x59, 0x57,
        0x85, 0x8f, 0x54, 0x7b, 0x93, 0x40, 0x12, 0x7d, 0xa7, 0x5f, 0x80, 0x74, 0xca, 0xee, 0x94,
        0x4a, 0xc3, 0x6c, 0xa, 0xc6, 0x62, 0xd3, 0x8c, 0x9b, 0x3c, 0xcc, 0xe0, 0x3a, 0x9, 0x3f,
        0xcd, 0x96, 0x44, 0x4, 0x73, 0x98, 0xb8, 0x6b, 0x6e, 0x83, 0x37, 0x2f, 0xf1, 0x4f, 0xb8,
        0xbb, 0xd, 0xea, 0x65, 0x53, 0x12, 0x52, 0xac, 0x70, 0xd5, 0x8a, 0x4a, 0x8, 0x10, 0xd6,
        0x82, 0xa0, 0xe7, 0x9, 0xc9, 0x22, 0x7b, 0x30, 0xef, 0x6c, 0x8e, 0x17, 0xc5, 0x91, 0x5d,
        0x52, 0x72, 0x21, 0xbb, 0x0, 0xda, 0x81, 0x75, 0xcd, 0x64, 0x89, 0xaa, 0x8a, 0xa4, 0x92,
        0xa5, 0x0, 0xf9, 0xab, 0xee, 0x56, 0x90, 0xb9, 0xdf, 0xca, 0x88, 0x55, 0xdc, 0xb, 0xd0,
        0x2a, 0x7f, 0x27, 0x7a, 0xdd, 0x24, 0xf, 0x63, 0x9a, 0xc1, 0x68, 0x1, 0xe8, 0x15, 0x74,
        0xaf, 0xb4, 0x68, 0x3e, 0xdf, 0xf6, 0x3b, 0x9a, 0x1, 0xe9, 0x3d, 0xbd, 0x86, 0x7a, 0x4,
        0xb6, 0x16, 0xc7, 0x6, 0xc8, 0xc, 0x75, 0x6c, 0x11, 0xa3, 0x1, 0x6b, 0xbf, 0xb6, 0x9, 0x77,
        0xf4, 0x64, 0x8b, 0x5f, 0x23, 0x95, 0xa4, 0xb4, 0x28, 0xb7, 0x21, 0x19, 0x40, 0x81, 0x3e,
        0x3a, 0xfd, 0xe2, 0xb8, 0x7a, 0xa9, 0xc2, 0xc3, 0x7b, 0xf7, 0x16, 0xe2, 0x57, 0x8f, 0x95,
        0x65, 0x6d, 0xf1, 0x2c, 0x2f, 0xb6, 0xf5, 0xd0, 0x63, 0x1f, 0x6f, 0x71, 0xe2, 0xc3, 0x19,
        0x3f, 0x6d,
    ];
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

impl KeyPair<AuthCredential> {
    pub fn create_auth_credential(
        &self,
        uid: uid_struct::UidStruct,
        redemption_time: CoarseRedemptionTime,
        sho: &mut Sho,
    ) -> AuthCredential {
        let M = convert_to_points_uid_struct(uid, redemption_time);
        let (t, U, V) = self.credential_core(&M, sho);
        AuthCredential { t, U, V }
    }
}

impl KeyPair<AuthCredentialWithPni> {
    pub fn create_auth_credential_with_pni(
        &self,
        aci: uid_struct::UidStruct,
        pni: uid_struct::UidStruct,
        redemption_time: Timestamp,
        sho: &mut Sho,
    ) -> AuthCredentialWithPni {
        let M = convert_to_points_aci_pni_timestamp(aci, pni, redemption_time);
        let (t, U, V) = self.credential_core(&M, sho);
        AuthCredentialWithPni { t, U, V }
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
    use crate::common::constants::*;
    use crate::crypto::proofs;

    use super::*;

    #[test]
    fn test_system() {
        let params = SystemParams::generate();
        println!("PARAMS = {:#x?}", bincode::serialize(&params));
        assert!(SystemParams::generate() == SystemParams::get_hardcoded());
    }

    #[test]
    fn test_mac() {
        let mut sho = Sho::new(b"Test_Credentials", b"");
        let keypair = KeyPair::<AuthCredential>::generate(&mut sho);

        let uid_bytes = TEST_ARRAY_16;
        let redemption_time = 37;
        let aci = libsignal_protocol::Aci::from_uuid_bytes(uid_bytes);
        let uid = uid_struct::UidStruct::from_service_id(aci.into());
        let credential = keypair.create_auth_credential(uid, redemption_time, &mut sho);
        let proof = proofs::AuthCredentialIssuanceProof::new(
            keypair,
            credential,
            uid,
            redemption_time,
            &mut sho,
        );

        let public_key = keypair.get_public_key();
        proof
            .verify(public_key, credential, uid, redemption_time)
            .unwrap();

        let keypair_bytes = bincode::serialize(&keypair).unwrap();
        let keypair2 = bincode::deserialize(&keypair_bytes).unwrap();
        assert!(keypair == keypair2);

        let public_key_bytes = bincode::serialize(&public_key).unwrap();
        let public_key2 = bincode::deserialize(&public_key_bytes).unwrap();
        assert!(public_key == public_key2);

        let mac_bytes = bincode::serialize(&credential).unwrap();

        println!("mac_bytes = {:#x?}", mac_bytes);
        assert!(
            mac_bytes
                == vec![
                    0xe0, 0xce, 0x21, 0xfe, 0xb7, 0xc3, 0xb8, 0x62, 0x3a, 0xe6, 0x20, 0xab, 0x3e,
                    0xe6, 0x5d, 0x94, 0xa3, 0xf3, 0x40, 0x53, 0x31, 0x63, 0xd2, 0x4c, 0x5d, 0x41,
                    0xa0, 0xd6, 0x7a, 0x40, 0xb3, 0x2, 0x8e, 0x50, 0xa2, 0x7b, 0xd4, 0xda, 0xe9,
                    0x9d, 0x60, 0x0, 0xdb, 0x97, 0x3d, 0xbc, 0xc5, 0xad, 0xe1, 0x32, 0xbc, 0x56,
                    0xb0, 0xe1, 0xac, 0x16, 0x7b, 0xb, 0x2c, 0x9, 0xe2, 0xb6, 0xc8, 0x5b, 0x68,
                    0xc8, 0x8e, 0x7d, 0xfd, 0x58, 0x97, 0x51, 0xe9, 0x8, 0x1f, 0x81, 0xb0, 0x24,
                    0xea, 0xa0, 0xaf, 0x29, 0x6, 0xed, 0xb3, 0x9, 0x32, 0xed, 0x65, 0x28, 0x2f,
                    0xa1, 0x79, 0x9e, 0x1, 0x24,
                ]
        );
    }
}
