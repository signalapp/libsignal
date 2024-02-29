//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use libsignal_net::cdsi::{LookupError, LookupResponse, LookupResponseEntry, E164};
use libsignal_protocol::{Aci, Pni};
use nonzero_ext::nonzero;
use uuid::Uuid;

#[cfg(any(feature = "jni", feature = "node"))]
use crate::net::TokioAsyncContext;
use crate::support::*;
use crate::*;

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn TESTING_CdsiLookupResponseConvert() -> LookupResponse {
    const E164_BOTH: E164 = E164::new(nonzero!(18005551011u64));
    const E164_PNI: E164 = E164::new(nonzero!(18005551012u64));
    const ACI_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";
    const PNI_UUID: &str = "796abedb-ca4e-4f18-8803-1fde5b921f9f";
    const DEBUG_PERMITS_USED: i32 = 123;

    let aci = Aci::from(Uuid::parse_str(ACI_UUID).expect("is valid"));
    let pni = Pni::from(Uuid::parse_str(PNI_UUID).expect("is valid"));

    LookupResponse {
        records: vec![
            LookupResponseEntry {
                e164: E164_BOTH,
                aci: Some(aci),
                pni: Some(pni),
            },
            LookupResponseEntry {
                e164: E164_PNI,
                pni: Some(pni),
                aci: None,
            },
        ],
        debug_permits_used: DEBUG_PERMITS_USED,
    }
}

#[bridge_fn(ffi = false)]
fn TESTING_CdsiLookupErrorConvert() -> Result<(), LookupError> {
    Err(LookupError::ParseError)
}
