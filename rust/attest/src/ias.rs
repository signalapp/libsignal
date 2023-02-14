//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::From;
use std::error::Error;
use std::string::ToString;
use std::time::SystemTime;

use boring::error::ErrorStack;
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::rsa::Padding;
use boring::sign::Verifier;
use boring::x509::crl::X509CRL;
use boring::x509::X509;
use lazy_static::lazy_static;

use crate::dcap;
use crate::dcap::cert_chain::CertChain;
use crate::dcap::Expireable;
use crate::error::ContextError;

const IAS_ROOT_CERT_DER: &[u8] = include_bytes!("../res/ias-root.cer");
// Available from https://trustedservices.intel.com/content/CRL/SGX/AttestationReportSigningCA.crl
const IAS_ROOT_CERT_CRL_PEM: &[u8] = include_bytes!("../res/AttestationReportSigningCA.crl");

lazy_static! {
    static ref IAS_ROOT_CERT: X509 =
        X509::from_der(IAS_ROOT_CERT_DER).expect("Invalid IAS root certificate");
    static ref IAS_ROOT_CRL: X509CRL =
        X509CRL::from_pem(IAS_ROOT_CERT_CRL_PEM).expect("Invalid IAS root CRL");
}

#[derive(Debug)]
pub struct SignatureError {
    message: String,
}

impl SignatureError {
    fn new(message: impl Into<String>) -> Self {
        SignatureError {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl Error for SignatureError {}

impl From<ErrorStack> for SignatureError {
    fn from(other: ErrorStack) -> Self {
        Self::new(other.to_string())
    }
}

impl<D> From<ContextError<D>> for SignatureError {
    fn from(other: ContextError<D>) -> Self {
        Self::new(other.to_string())
    }
}

// The main entry point for the API
pub fn verify_signature(
    cert_pem: &[u8],
    body: &[u8],
    signature: &[u8],
    current_time: SystemTime,
) -> Result<(), SignatureError> {
    let cert_chain = CertChain::from_pem_data(cert_pem)?;

    let trust = dcap::from_trusted(&[&IAS_ROOT_CERT], &[&IAS_ROOT_CRL], current_time)?;
    if !cert_chain.valid_at(current_time) {
        return Err(SignatureError::new("Certificate chain has expired"));
    }
    cert_chain.validate_chain(&trust, &[])?;
    cert_chain.verify_signature(body, signature)
}

impl CertChain {
    const COMMON_NAME: &str = "Intel SGX Attestation Report Signing";
    const ORGANIZATION_NAME: &'static str = "Intel Corporation";
    const LOCALITY_NAME: &'static str = "Santa Clara";
    const STATE_NAME: &'static str = "CA";
    const COUNTRY_NAME: &'static str = "US";

    fn verify_signature(&self, body: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        let cert = self.leaf();
        Self::verify_distinguished_name(cert)?;

        let public_key = cert.public_key()?;

        let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
        verifier.set_rsa_padding(Padding::PKCS1)?;

        match verifier.verify_oneshot(signature, body) {
            Ok(true) => Ok(()),
            Ok(_) => Err(SignatureError::new("signature does not match")),
            Err(_) => Err(SignatureError::new("signature verification failed")),
        }
    }

    fn verify_distinguished_name(cert: &X509) -> Result<(), SignatureError> {
        let subject = cert.subject_name();
        for (nid, expected) in [
            (Nid::COMMONNAME, Self::COMMON_NAME),
            (Nid::ORGANIZATIONNAME, Self::ORGANIZATION_NAME),
            (Nid::LOCALITYNAME, Self::LOCALITY_NAME),
            (Nid::STATEORPROVINCENAME, Self::STATE_NAME),
            (Nid::COUNTRYNAME, Self::COUNTRY_NAME),
        ] {
            let nid_name = nid.short_name().unwrap_or("?");
            let entry = subject.entries_by_nid(nid).next().ok_or_else(|| {
                SignatureError::new(format!("Failed to extract {nid_name} entry."))
            })?;
            let data = entry.data().as_utf8()?;
            if *expected != **data {
                let message = format!(
                    "Unexpected certificate field value. Expected: '{}={}'. Actual: '{}={}'",
                    nid_name, expected, nid_name, data
                );
                return Err(SignatureError::new(message));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use boring::base64::decode_block;
    use chrono::DateTime;
    use std::time::Duration;

    use crate::util::testio::read_test_file;

    use super::*;

    #[test]
    fn happy_path() {
        verify_signature(&GOOD_PEM, &GOOD_MESSAGE, &GOOD_SIGNATURE, SystemTime::now()).unwrap();
    }

    #[test]
    fn expired_crl_should_fail_verification() {
        let future_time = DateTime::parse_from_rfc3339("2038-01-19T03:14:06Z").unwrap();
        let time: SystemTime =
            SystemTime::UNIX_EPOCH + Duration::from_millis(future_time.timestamp_millis() as u64);
        verify_signature(&GOOD_PEM, &GOOD_MESSAGE, &GOOD_SIGNATURE, time)
            .expect_err("CRL has expired");
    }

    #[test]
    fn bad_signature_test() {
        let signature = corrupt(GOOD_SIGNATURE.clone());

        verify_signature(&GOOD_PEM, &GOOD_MESSAGE, &signature, SystemTime::now())
            .expect_err("signature does not match");
    }

    #[test]
    fn bad_data_test() {
        let body = corrupt(GOOD_MESSAGE.clone());

        verify_signature(&GOOD_PEM, &body, &GOOD_SIGNATURE, SystemTime::now())
            .expect_err("signature does not match");
    }

    fn corrupt(mut subject: Vec<u8>) -> Vec<u8> {
        subject.swap(0, 1);
        subject
    }

    fn base64_to_bytes(source: &str) -> Vec<u8> {
        let mut string = source.to_string();
        string.retain(|c| !c.is_whitespace());
        decode_block(string.as_str()).unwrap()
    }

    lazy_static! {
        static ref GOOD_PEM: Vec<u8> = read_test_file("tests/data/ias-sig-cert.pem");
        static ref GOOD_SIGNATURE: Vec<u8> =
            base64_to_bytes("Hj4zz2gLX+g1T4avpcpXxmBqI5bpKKLOy4HLCTO0PwKcV+Q3fhDJVuVy0+SEgzC1TlmARKyH/DVynWu3pA9FA+4BvZxb7nLbaMG4PXdYu56sHDCzFVPsm9TPgqsVu5PbVXatZQ0oVxMkzKtPae3fy/ootXkG+4ahOU6Hwqa0Uy6+HYzL2CJZRJjHV6/iZjgTLjYsQqS0mZiaUuFoqn8RRb8/f7/9SujDSLa8dmKBqaZCtZpeHh4posLWjOhTJx07FhBRh5EV01gXFfys56h2NTc7MpmYbzt2onfH/3lDM8DfdNUJl0TfikzJyVdLWXi0MyAS2nrRhHFwVp365FYEJg==");
        static ref GOOD_MESSAGE: Vec<u8> = base64_to_bytes(
            std::str::from_utf8(&read_test_file("tests/data/ias-valid-message.txt"))
                .expect("Invalid UTF-8")
        );

    }
}
