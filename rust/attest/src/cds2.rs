//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use prost::Message;

use crate::dcap;
use crate::enclave::{Handshake, HandshakeType, Result};
use crate::proto::cds2;
use crate::util::get_sw_advisories;

pub fn new_handshake(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<Handshake> {
    new_handshake_with_advisories(
        mrenclave,
        attestation_msg,
        current_time,
        get_sw_advisories(mrenclave),
    )
}

pub fn new_handshake_with_advisories(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
    advisories: &[&str],
) -> Result<Handshake> {
    // Deserialize attestation handshake start.
    let handshake_start = cds2::ClientHandshakeStart::decode(attestation_msg)?;
    Ok(Handshake::for_sgx(
        mrenclave,
        &handshake_start.evidence,
        &handshake_start.endorsement,
        advisories,
        current_time,
        HandshakeType::PostQuantum,
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

    use super::*;

    #[test]
    fn attest_cds2() {
        // Read test data files, de-hex-stringing as necessary.
        let mrenclave = include_bytes!("../tests/data/cdsi.mrenclave");
        let attestation_msg = include_bytes!("../tests/data/cdsi.handshakestart");
        let current_time = SystemTime::UNIX_EPOCH
            + Duration::from_secs(u64::from_be_bytes(*include_bytes!(
                "../tests/data/cdsi.timestamp"
            )));
        let advisories = include_bytes!("../tests/data/cdsi.advisories")
            .split(|&b| b == b'\n')
            .map(|a| String::from_utf8(a.to_vec()).unwrap())
            .collect::<Vec<_>>();
        let advisories_arr = advisories.iter().map(|s| s.as_str()).collect::<Vec<_>>();

        assert!(
            new_handshake_with_advisories(
                &mrenclave[..],
                &attestation_msg[..],
                current_time,
                &advisories_arr
            )
            .is_ok()
        );
    }
}
