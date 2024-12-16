//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use boring_signal::hash::MessageDigest;
use boring_signal::sign::Verifier;
use boring_signal::x509::X509;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const SIGNATURE_PREFIX_LEN: usize = 6;
const SIGNATURE_BYTES: usize = 256;
const SIGNATURE_TOTAL_LEN: usize = SIGNATURE_PREFIX_LEN + SIGNATURE_BYTES;

const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
const NONCE_SIZE: usize = 32;
const SHA256_SIZE: usize = 32;
const ALL_24_PCRS: u32 = 0x03ff_ffff;

const PCR_SIZE: usize = 32;
const PCRS_TOTAL_SIZE: usize = PCR_SIZE * 24;

#[derive(Debug, displaydoc::Display)]
pub enum Error {
    /// Invalid TPM2 signature
    InvalidSignature,
    /// Invalid TPM2 report
    InvalidReport,
    /// Invalid PCRs
    InvalidPcrs,
    /// Verification failed
    VerificationFailed,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub(crate) struct VerifiedBytes<'a>(&'a [u8]);

#[derive(Debug)]
pub struct Signature<'a>(&'a [u8]);

#[derive(Debug)]
pub struct Clock {
    #[allow(unused)]
    pub millis_since_clear: u64,
    #[allow(unused)]
    pub resets: u32,
    #[allow(unused)]
    pub restarts: u32,
    #[allow(unused)]
    pub is_safe: bool,
}

pub struct Report<'a> {
    pub key_hash: &'a [u8],
    pub nonce: &'a [u8],
    pub clock: Clock,

    pub firmware_version: u64,
    pub pcr_digest: &'a [u8],
}

impl std::fmt::Debug for Report<'_> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Report")
            .field("key_hash", &hex::encode(self.key_hash))
            .field("nonce", &hex::encode(self.nonce))
            .field("clock", &self.clock)
            .field("firmware_version", &self.firmware_version)
            .field("pcr_digest", &hex::encode(self.pcr_digest))
            .finish()
    }
}

pub(crate) type RawPcr = [u8; 32];

#[derive(Clone, Copy, Debug)]
pub struct Pcr<'a>(pub &'a RawPcr);

pub(crate) type PcrMap = [(usize, RawPcr)];

#[derive(Debug)]
pub struct Pcrs<'a>(pub [Pcr<'a>; 24]);

impl AsRef<[u8]> for VerifiedBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> Signature<'a> {
    /// Try to extract the signature from a slice
    ///
    /// `bytes` is expected to be 262 bytes long:
    /// - 6 bytes for the prefix
    /// - 256 bytes for the signature value itself
    pub fn from_slice(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_TOTAL_LEN {
            return Err(Error::InvalidSignature);
        }
        let mut view = View::new(bytes);

        let _ = view
            .read_be_u16()
            .ok()
            .filter(|value| *value == TPM_ALG_RSASSA)
            .ok_or(Error::InvalidSignature)?;

        let _ = view
            .read_be_u16()
            .ok()
            .filter(|value| *value == TPM_ALG_SHA256)
            .ok_or(Error::InvalidSignature)?;

        let _ = view
            .read_be_u16()
            .ok()
            .filter(|value| *value as usize == SIGNATURE_BYTES)
            .ok_or(Error::InvalidSignature)?;

        debug_assert_eq!(SIGNATURE_BYTES, view.data_left());

        Ok(Self(view.read_to_end()))
    }

    pub(crate) fn verify_report<'r>(
        &self,
        report_bytes: &'r [u8],
        cert: &X509,
    ) -> Result<VerifiedBytes<'r>> {
        let key = cert.public_key().expect("has public key");
        let mut verifier =
            Verifier::new(MessageDigest::sha256(), &key).expect("can build verifier");
        if verifier
            .verify_oneshot(self.0, report_bytes)
            .expect("can verify signature")
        {
            Ok(VerifiedBytes(report_bytes))
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

impl<'a> Report<'a> {
    /// Try to extract the report from a slice
    pub(crate) fn from_slice(bytes: VerifiedBytes<'a>) -> Result<Self> {
        let mut view = View::new(bytes.0);

        let _ = view
            .read_be_u32()
            .ok()
            .filter(|value| *value == TPM_GENERATED_VALUE)
            .ok_or(Error::InvalidReport)?;

        let _ = view
            .read_be_u16()
            .ok()
            .filter(|value| *value == TPM_ST_ATTEST_QUOTE)
            .ok_or(Error::InvalidReport)?;

        let _ = view
            .read_be_u16()
            .ok()
            .filter(|value| *value as usize == 2 + SHA256_SIZE)
            .ok_or(Error::InvalidReport)?;

        // Key must use SHA256
        let _ = view
            .read_be_u16()
            .ok()
            .filter(|value| *value == TPM_ALG_SHA256)
            .ok_or(Error::InvalidReport)?;

        let key_hash = view
            .read_chunk(SHA256_SIZE)
            .map_err(|_| Error::InvalidReport)?;

        let _ = view
            .read_be_u16()
            .ok()
            .filter(|value| *value as usize == NONCE_SIZE)
            .ok_or(Error::InvalidReport)?;
        let nonce = view
            .read_chunk(NONCE_SIZE)
            .map_err(|_| Error::InvalidReport)?;

        let clock = {
            let millis_since_clear = view.read_be_u64().map_err(|_| Error::InvalidReport)?;
            let resets = view.read_be_u32().map_err(|_| Error::InvalidReport)?;
            let restarts = view.read_be_u32().map_err(|_| Error::InvalidReport)?;
            let is_safe = view.read_u8().map_err(|_| Error::InvalidReport)? == 0x01;
            Clock {
                millis_since_clear,
                resets,
                restarts,
                is_safe,
            }
        };

        let firmware_version = view.read_be_u64().map_err(|_| Error::InvalidReport)?;

        // Total number of PCR selection sets
        let _ = view
            .read_be_u32()
            .ok()
            .filter(|value| *value == 1)
            .ok_or(Error::InvalidReport)?;

        // PCRs must use SHA256
        let _ = view
            .read_be_u16()
            .ok()
            .filter(|value| *value == TPM_ALG_SHA256)
            .ok_or(Error::InvalidReport)?;
        let _ = view
            .read_be_u32()
            .ok()
            .filter(|value| *value == ALL_24_PCRS)
            .ok_or(Error::InvalidReport)?;
        let _ = view
            .read_be_u16()
            .ok()
            .filter(|value| *value as usize == SHA256_SIZE)
            .ok_or(Error::InvalidReport)?;
        let pcr_digest = view
            .read_chunk(SHA256_SIZE)
            .map_err(|_| Error::InvalidReport)?;
        if view.data_left() > 0 {
            return Err(Error::InvalidReport);
        }
        Ok(Report {
            key_hash,
            nonce,
            clock,
            firmware_version,
            pcr_digest,
        })
    }

    pub(crate) fn verify_pcrs<'b>(&self, pcrs_bytes: &'b [u8]) -> Result<VerifiedBytes<'b>> {
        let digest = Sha256::digest(pcrs_bytes);

        if bool::from(self.pcr_digest.ct_eq(digest.as_slice())) {
            Ok(VerifiedBytes(pcrs_bytes))
        } else {
            Err(Error::VerificationFailed)
        }
    }

    pub(crate) fn verify_atteststion_data<'b>(
        &self,
        attestation_data: &'b [u8],
    ) -> Result<VerifiedBytes<'b>> {
        let digest = Sha256::digest(attestation_data);
        if bool::from(digest.ct_eq(self.nonce)) {
            Ok(VerifiedBytes(attestation_data))
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

impl<'a> Pcrs<'a> {
    pub(crate) fn from_slice(bytes: VerifiedBytes<'a>) -> Result<Self> {
        if bytes.0.len() != PCRS_TOTAL_SIZE {
            return Err(Error::InvalidPcrs);
        }
        // TODO: replace with array_chunks when that's stabilized.
        let vec: Vec<Pcr> = bytes
            .0
            .chunks(PCR_SIZE)
            .map(|next| Pcr(next.try_into().unwrap()))
            .collect();
        Ok(Pcrs(vec.try_into().map_err(|_| Error::InvalidPcrs)?))
    }

    pub(crate) fn validate(&self, expected_pcrs: &PcrMap) -> Result<()> {
        let mut is_match = subtle::Choice::from(1u8);
        for (i, expected) in expected_pcrs {
            is_match &= self.0[*i].0.ct_eq(expected);
        }
        if is_match.into() {
            Ok(())
        } else {
            Err(Error::InvalidPcrs)
        }
    }
}

// TODO: use byteorder crate maybe?
struct View<'a> {
    pos: usize,
    data: &'a [u8],
}

enum ReadError {
    UnexpectedEof,
    BadFormat,
}

type ReadResult<T> = std::result::Result<T, ReadError>;

impl<'a> View<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { pos: 0, data }
    }

    #[inline]
    fn data_left(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_chunk(&mut self, n: usize) -> ReadResult<&'a [u8]> {
        if self.data_left() < n {
            return Err(ReadError::UnexpectedEof);
        }
        let chunk = &self.data[self.pos..][..n];
        self.pos += n;
        Ok(chunk)
    }

    fn read_u8(&mut self) -> ReadResult<u8> {
        Ok(self.read_chunk(1)?[0])
    }

    fn read_be_u16(&mut self) -> ReadResult<u16> {
        self.read_chunk(2)?
            .try_into()
            .map_err(|_| ReadError::BadFormat)
            .map(u16::from_be_bytes)
    }

    fn read_be_u32(&mut self) -> ReadResult<u32> {
        self.read_chunk(4)?
            .try_into()
            .map_err(|_| ReadError::BadFormat)
            .map(u32::from_be_bytes)
    }

    fn read_be_u64(&mut self) -> ReadResult<u64> {
        self.read_chunk(8)?
            .try_into()
            .map_err(|_| ReadError::BadFormat)
            .map(u64::from_be_bytes)
    }

    fn read_to_end(&mut self) -> &'a [u8] {
        let chunk = &self.data[self.pos..];
        self.pos = self.data.len();
        chunk
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use hex_literal::hex;
    use test_case::test_case;

    use super::*;

    const VALID_SIGNATURE: &[u8] = include_bytes!("../../tests/data/tpm2_valid_signature.dat");
    const VALID_REPORT: &[u8] = include_bytes!("../../tests/data/tpm2_valid_report.dat");
    const VALID_PCRS: &[u8] = include_bytes!("../../tests/data/tpm2_valid_pcrs.dat");
    const VALID_CERT_PEM: &[u8] = include_bytes!("../../tests/data/tpm2snp_valid_cert.pem");

    #[test]
    fn parse_valid_signature() {
        assert_matches!(
            Signature::from_slice(VALID_SIGNATURE),
            Ok(Signature(sig_bytes)) => assert!(sig_bytes == &VALID_SIGNATURE[SIGNATURE_PREFIX_LEN..])
        );
    }

    #[test_case(1, 0x42; "bad_alg")]
    #[test_case(3, 0x42; "bad_hash")]
    #[test_case(5, 0x42; "bad_len")]
    fn parse_invalid_signature(byte_index: usize, value: u8) {
        let mut bad_signature = VALID_SIGNATURE.to_vec();
        bad_signature[byte_index] = value;
        assert_matches!(
            Signature::from_slice(&bad_signature),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn parse_signature_invalid_size() {
        assert_matches!(
            Signature::from_slice(&vec![0; SIGNATURE_TOTAL_LEN - 1]),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn parse_valid_report() {
        assert_matches!(Report::from_slice(VerifiedBytes(VALID_REPORT)), Ok(Report { firmware_version, key_hash, nonce, pcr_digest, .. }) => {
            assert_eq!(0x2020031200120003, firmware_version);
            assert_eq!(hex!("90c39c7239c45a6bbdd2344abfbd4dc923c88d274664890bc4ddf7427e51a6e9"), key_hash);
            assert_eq!(hex!("1122334455667788990011223344556677889900112233445566778899001122"), nonce);
            assert_eq!(hex!("0692355dd87c9e09e3e5a0323b238d1cccfbfcfe4a0c72ff34bfa6ee432a542b"), pcr_digest);
        });
    }

    #[test]
    fn parse_valid_pcrs() {
        assert_matches!(Pcrs::from_slice(VerifiedBytes(VALID_PCRS)), Ok(Pcrs(pcrs)) => {
            assert!(pcrs.iter().all(|pcr| pcr.0.len() == PCR_SIZE));
        });
    }

    #[test_case(PCRS_TOTAL_SIZE - 1; "too_short")]
    #[test_case(PCRS_TOTAL_SIZE + 1; "too_long")]
    fn invalid_pcrs_length(len: usize) {
        assert_matches!(
            Pcrs::from_slice(VerifiedBytes(&vec![0; len])),
            Err(Error::InvalidPcrs)
        );
        assert_matches!(
            Pcrs::from_slice(VerifiedBytes(&vec![0; len])),
            Err(Error::InvalidPcrs)
        );
    }

    #[test]
    fn verify_valid_pcrs() {
        let report = Report::from_slice(VerifiedBytes(VALID_REPORT)).expect("valid report");
        assert_matches!(report.verify_pcrs(VALID_PCRS), Ok(VerifiedBytes(_)));
    }

    #[test]
    fn verify_invalid_pcrs() {
        let report = Report::from_slice(VerifiedBytes(VALID_REPORT)).expect("valid report");
        let pcr_bytes = [0; PCRS_TOTAL_SIZE];
        assert_matches!(
            report.verify_pcrs(&pcr_bytes),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn verify_report_signature() {
        let signature = Signature::from_slice(VALID_SIGNATURE).expect("valid signature");
        let cert = X509::from_pem(VALID_CERT_PEM).expect("valid cert pem");
        assert_matches!(
            signature.verify_report(VALID_REPORT, &cert),
            Ok(VerifiedBytes(_))
        );
    }

    #[test]
    fn verify_bad_report_signature() {
        let mut sig = VALID_SIGNATURE.to_vec();
        sig[42] ^= 0xff;
        let signature = Signature::from_slice(&sig).expect("can parse signature");
        let cert = X509::from_pem(VALID_CERT_PEM).expect("valid cert pem");
        assert_matches!(
            signature.verify_report(VALID_REPORT, &cert),
            Err(Error::VerificationFailed)
        );
    }
}
