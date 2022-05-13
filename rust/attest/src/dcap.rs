//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implements SGX DCAP attestation verification.
// https://www.intel.com/content/dam/develop/external/us/en/documents/intel-sgx-support-for-third-party-attestation-801017.pdf
// https://api.portal.trustedservices.intel.com/provisioning-certification

// 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK certificate.
// 2. Verify no keys in the chain have been revoked.
// 3. Verify the Quoting Enclave is from a suitable source and is up to date.
// 4. Verify the status of the Intel® SGX TCB described in the chain.
// 5. Verify the enclave measurements in the Quote reflect an enclave identity expected.

// Azure DCAP Client dcap_provider.cpp
// sgx_ql_get_quote_config() -> sgx_ql_config_t
// and pretty much all sgx_ql_get_*

// The first value, the Provisioning Certification
// Key, is an IETF RFC 6090 [5] compliant 256 bit Elliptic
// Curve signing key, using the NIST p-256 curve.

use displaydoc::Display;
use ecdsa::signature::{Signature, Verifier};
use ecdsa::VerifyingKey;
use p256::NistP256;
use std::collections::HashMap;
use std::convert::TryFrom;

mod endorsements;
mod evidence;
mod sgx_quote;
mod sgx_report_body;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Display)]
pub enum Error {
    /// couldn't deserialize {name}: {reason}
    Deserialization {
        name: &'static str,
        reason: &'static str,
    },

    /// expected mrenclave '{expected}', was '{actual}'
    UnexpectedMrenclave { expected: String, actual: String },

    /// invalid signature: '{reason}'
    Signature { reason: String },

    /// certificate verification: '{reason}'
    CertificateVerification { reason: String },
}

///
/// NOT FOR PRODUCTION: this doesn’t actually verify remote attestation, and instead
/// simply extracts the public key from the provided evidence
///
/// In the future, verify_remote_attestation will be a drop-in replacement
///
/// Returns: Result containing a map of claims extracted from the evidence when successful,
///          or an attestation verification error when not
///
#[allow(non_snake_case)]
pub fn NOT_FOR_PRODUCTION_verify_remote_attestation(
    evidence_bytes: &[u8],
    _endorsement_bytes: &[u8],
    _expected_mrenclave: &[u8],
    _trusted_ca_cert_bytes: &[u8],
    _earliest_valid_time: std::time::SystemTime,
) -> Result<HashMap<String, Vec<u8>>> {
    let evidence = evidence::Evidence::try_from(evidence_bytes)?;

    Ok(evidence.claims)
}

/// Returns a `Result` containing a map of claims extracted from the evidence when successful,
///          or an attestation verification error when not
pub fn verify_remote_attestation(
    _evidence_bytes: &[u8],
    _endorsement_bytes: &[u8],
    _expected_mrenclave: &[u8],
    _trusted_ca_cert_bytes: &[u8],
    _timestamp: u64,
) -> Result<HashMap<String, Vec<u8>>> {
    todo!("not yet implemented")

    // verify_signature_chain()
    // verify_crl()
    // verify_enclave_source()
    // verify_tcb_status()
    // verify_enclave()
}

pub(crate) fn _check_signature(
    signature_bytes: &[u8],
    msg_bytes: &[u8],
    key_bytes: &[u8],
) -> Result<()> {
    let sig: ecdsa::Signature<NistP256> =
        ecdsa::Signature::from_bytes(signature_bytes).map_err(|e| Error::Signature {
            reason: format!("{:?}", e),
        })?;
    let key = VerifyingKey::from_sec1_bytes(key_bytes).unwrap();
    key.verify(msg_bytes, &sig).map_err(|e| Error::Signature {
        reason: format!("{:?}", e),
    })
}

fn _verify_signature_chain() {
    todo!("1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK certificate.")
}

fn _verify_crl() {
    todo!("2. Verify no keys in the chain have been revoked.")
}

fn _verify_enclave_source() {
    todo!("3. Verify the Quoting Enclave is from a suitable source and is up to date.")
}

fn _verify_tcb_status() {
    todo!("4. Verify the status of the Intel® SGX TCB described in the chain.")
}

fn _verify_enclave() {
    todo!("5. Verify the enclave measurements in the Quote reflect an enclave identity expected.")
}
