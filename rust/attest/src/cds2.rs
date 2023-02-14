//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::convert::From;

use hex_literal::hex;
use lazy_static::lazy_static;
use prost::Message;
use sgx_session::Result;

use crate::dcap::MREnclave;
use crate::proto::cds2;
use crate::{dcap, sgx_session};

lazy_static! {
    /// Map from MREnclave to intel SW advisories that are known to be mitigated in the
    /// build with that MREnclave value
    static ref ACCEPTABLE_SW_ADVISORIES: HashMap<MREnclave, &'static [&'static str]> = {
        HashMap::from([
            (hex!("7b75dd6e862decef9b37132d54be082441917a7790e82fe44f9cf653de03a75f"), &["INTEL-SA-00657"] as &[&str]),
            (hex!("0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57"), &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str]),
        ])
    };
}

/// SW advisories known to be mitigated by default. If an MREnclave is provided that
/// is not contained in `ACCEPTABLE_SW_ADVISORIES`, this will be used
const DEFAULT_SW_ADVISORIES: &[&str] = &[];

pub fn new_handshake(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<sgx_session::Handshake> {
    // Deserialize attestation handshake start.
    let handshake_start = cds2::ClientHandshakeStart::decode(attestation_msg)?;
    sgx_session::Handshake::new(
        mrenclave,
        &handshake_start.evidence,
        &handshake_start.endorsement,
        ACCEPTABLE_SW_ADVISORIES
            .get(mrenclave)
            .unwrap_or(&DEFAULT_SW_ADVISORIES),
        current_time,
    )
}

/// Extracts attestation metrics from a `ClientHandshakeStart` message
pub fn extract_metrics(attestation_msg: &[u8]) -> Result<HashMap<String, i64>> {
    let handshake_start = cds2::ClientHandshakeStart::decode(attestation_msg)?;
    Ok(dcap::attestation_metrics(
        &handshake_start.evidence,
        &handshake_start.endorsement,
    )?)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::testio::read_test_file;
    use std::time::{Duration, SystemTime};

    #[test]
    fn attest_cds2() {
        // Read test data files, de-hex-stringing as necessary.
        let mrenclave = hex!("39d78f17f8aa9a8e9cdaf16595947a057bac21f014d1abfd6a99b2dfd4e18d1d");

        let attestation_msg = cds2::ClientHandshakeStart {
            evidence: read_test_file("tests/data/cds2_test.evidence"),
            endorsement: read_test_file("tests/data/cds2_test.endorsements"),
            ..Default::default()
        };

        let current_time = SystemTime::UNIX_EPOCH + Duration::from_millis(1655857680000);

        assert!(new_handshake(&mrenclave, &attestation_msg.encode_to_vec(), current_time).is_ok());
    }
}
