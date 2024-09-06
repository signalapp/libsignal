//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use prost::Message;

use crate::constants::ENCLAVE_ID_CDSI_STAGING_AND_PROD;
use crate::dcap;
use crate::enclave::{Handshake, HandshakeType, Result};
use crate::proto::cds2;
use crate::util::SmallMap;

/// Map from MREnclave to intel SW advisories that are known to be mitigated in the
/// build with that MREnclave value.
const ACCEPTABLE_SW_ADVISORIES: &SmallMap<&[u8], &'static [&'static str], 1> = &SmallMap::new([(
    ENCLAVE_ID_CDSI_STAGING_AND_PROD,
    &["INTEL-SA-00615", "INTEL-SA-00657"] as &[&str],
)]);

/// SW advisories known to be mitigated by default. If an MREnclave is provided that
/// is not contained in `ACCEPTABLE_SW_ADVISORIES`, this will be used
const DEFAULT_SW_ADVISORIES: &[&str] = &[];

pub fn new_handshake(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<Handshake> {
    // Deserialize attestation handshake start.
    let handshake_start = cds2::ClientHandshakeStart::decode(attestation_msg)?;
    Ok(Handshake::for_sgx(
        mrenclave,
        &handshake_start.evidence,
        &handshake_start.endorsement,
        ACCEPTABLE_SW_ADVISORIES
            .get(&mrenclave)
            .unwrap_or(&DEFAULT_SW_ADVISORIES),
        current_time,
        HandshakeType::PreQuantum,
    )?
    .skip_raft_validation())
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
    use std::time::{Duration, SystemTime};

    use hex_literal::hex;

    use super::*;

    #[test]
    fn attest_cds2() {
        // Read test data files, de-hex-stringing as necessary.
        let mrenclave = hex!("39d78f17f8aa9a8e9cdaf16595947a057bac21f014d1abfd6a99b2dfd4e18d1d");

        let attestation_msg = cds2::ClientHandshakeStart {
            evidence: include_bytes!("../tests/data/cds2_test.evidence").to_vec(),
            endorsement: include_bytes!("../tests/data/cds2_test.endorsements").to_vec(),
            ..Default::default()
        };

        let current_time = SystemTime::UNIX_EPOCH + Duration::from_millis(1655857680000);

        assert!(new_handshake(&mrenclave, &attestation_msg.encode_to_vec(), current_time).is_ok());
    }
}
