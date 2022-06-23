//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::sho::*;
use crate::common::simple_types::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UidStruct {
    pub(crate) bytes: UidBytes,
    pub(crate) M1: RistrettoPoint,
    pub(crate) M2: RistrettoPoint,
}

pub struct PointDecodeFailure;

impl UidStruct {
    pub fn new(uid_bytes: UidBytes) -> Self {
        let mut sho = Sho::new(b"Signal_ZKGroup_20200424_UID_CalcM1", &uid_bytes);
        let M1 = sho.get_point();
        let M2 = RistrettoPoint::lizard_encode::<Sha256>(&uid_bytes);
        UidStruct {
            bytes: uid_bytes,
            M1,
            M2,
        }
    }

    pub fn from_M2(M2: RistrettoPoint) -> Result<Self, PointDecodeFailure> {
        match M2.lizard_decode::<Sha256>() {
            None => Err(PointDecodeFailure),
            Some(bytes) => Ok(Self::new(bytes)),
        }
    }

    pub fn to_bytes(&self) -> UidBytes {
        self.bytes
    }
}
