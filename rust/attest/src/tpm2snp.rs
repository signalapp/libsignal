//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::time::SystemTime;

use boring::pkey::{PKey, Public};
use boring::rsa::Rsa;
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509;
use prost::Message;

use crate::dcap::cert_chain::CertChain;
use crate::dcap::{Error as DcapError, Expireable as _};
use crate::enclave::{Claims, Error, Handshake, Result, UnvalidatedHandshake};
use crate::proto::svr2;
use crate::svr2::expected_raft_config;

use crate::constants::TPM2SNP_EXPECTED_PCRS;

const MSFT_AKCERT_ROOT_PEM: &[u8] = include_bytes!("../res/msft_akcert_root.pem");

pub fn new_handshake(enclave: &[u8], attestation_msg: &[u8], now: SystemTime) -> Result<Handshake> {
    let expected_raft_config = expected_raft_config(enclave, None)?;
    let handshake_start = svr2::ClientHandshakeStart::decode(attestation_msg)?;
    Handshake::for_tpm2snp(
        enclave,
        &handshake_start.evidence,
        &handshake_start.endorsement,
        now,
    )?
    .validate(expected_raft_config)
}

impl Handshake {
    pub(crate) fn for_tpm2snp(
        enclave: &[u8],
        evidence: &[u8],
        endorsements: &[u8],
        now: SystemTime,
    ) -> Result<UnvalidatedHandshake> {
        let evidence = svr2::AsnpEvidence::decode(evidence)?;
        let endorsements = svr2::AsnpEndorsements::decode(endorsements)?;
        let attestation_data = attest(enclave, &evidence, &endorsements, now)?;
        let claims = Claims::from_attestation_data(attestation_data)?;
        Handshake::with_claims(claims)
    }
}

fn attest(
    enclave: &[u8],
    evidence: &svr2::AsnpEvidence,
    endorsements: &svr2::AsnpEndorsements,
    now: SystemTime,
) -> Result<svr2::AttestationData> {
    let ak_cert_pk = verify_ak_cert(evidence, endorsements, now)?;
    let runtime_pk = verify_snp_report(evidence, endorsements, now)?;
    if !(ak_cert_pk.n() == runtime_pk.n() && ak_cert_pk.e() == runtime_pk.e()) {
        return Err(Error::AttestationDataError {
            reason: "RSA keys mismatch".to_string(),
        });
    }
    let expected_pcrs =
        TPM2SNP_EXPECTED_PCRS
            .get(&enclave)
            .ok_or_else(|| Error::AttestationDataError {
                reason: format!("unknown enclave {:?}", enclave),
            })?;
    let tpm2_report = verify_tpm2_quote(evidence, expected_pcrs)?;
    let attestation_data = tpm2_report.verify_atteststion_data(&evidence.attestation_data)?;
    Ok(svr2::AttestationData::decode(attestation_data.as_ref())?)
}

fn verify_ak_cert(
    evidence: &svr2::AsnpEvidence,
    endorsements: &svr2::AsnpEndorsements,
    now: SystemTime,
) -> Result<Rsa<Public>> {
    let akcert = X509::from_der(&evidence.akcert_der).expect("valid cert der");
    let chain = {
        let root = X509::from_pem(MSFT_AKCERT_ROOT_PEM).expect("Invalid MSFT root certificate");
        let intermediate = X509::from_der(&endorsements.intermediate_der).expect("valid cert der");
        CertChain::new([akcert.clone(), intermediate, root])?
    };
    let store = {
        let mut builder = X509StoreBuilder::new().expect("can make X509 store");
        builder
            .add_cert(chain.root().clone())
            .expect("can add root cert");
        builder.build()
    };
    chain.validate_chain(&store, &[])?;
    if !chain.valid_at(now) {
        return Err(Error::AttestationDataError {
            reason: "Expired certificate".to_string(),
        });
    }
    akcert
        .public_key()
        .and_then(|pk| pk.rsa())
        .map_err(|_| Error::AttestationDataError {
            reason: "Expect an RSA public key".to_string(),
        })
}

fn verify_snp_report(
    evidence: &svr2::AsnpEvidence,
    endorsements: &svr2::AsnpEndorsements,
    now: SystemTime,
) -> Result<Rsa<Public>> {
    let vcek_cert_public_key = verify_vcek_cert(endorsements, now)?;

    let report = snp::Report::new(&evidence.snp_report)?;
    report.verify(vcek_cert_public_key.clone())?;

    let runtime_data = snp::RuntimeData::new(&evidence.runtime_data)?;
    Ok(runtime_data.verify(report)?)
}

fn verify_vcek_cert(
    endorsements: &svr2::AsnpEndorsements,
    now: SystemTime,
) -> Result<PKey<Public>> {
    let vcek_cert = X509::from_der(&endorsements.vcek_der)?;
    let ask_cert = X509::from_der(&endorsements.ask_der)?;

    let root_cert = [snp::ARK_GENOA_ROOT_PEM, snp::ARK_MILAN_ROOT_PEM]
        .iter()
        .map(|pem| X509::from_pem(pem).expect("Invalid AMD root certificate"))
        .find(|root| root.issued(&ask_cert) == boring::x509::X509VerifyResult::OK)
        .ok_or_else(|| Error::AttestationDataError {
            reason: "Certificate issuer not trusted".to_string(),
        })?;

    let chain = CertChain::new([vcek_cert.clone(), ask_cert, root_cert.clone()])?;
    let trust_store = {
        let mut builder = X509StoreBuilder::new().expect("can make X509 store");
        builder.add_cert(root_cert).expect("can add root cert");
        builder.build()
    };
    chain.validate_chain(&trust_store, &[])?;
    if chain.valid_at(now) {
        Ok(vcek_cert.public_key()?)
    } else {
        Err(Error::AttestationDataError {
            reason: "Expired certificate".to_string(),
        })
    }
}

impl From<boring::error::ErrorStack> for Error {
    fn from(_err: boring::error::ErrorStack) -> Error {
        Error::AttestationDataError {
            reason: "Invalid certificate".to_string(),
        }
    }
}
mod snp {
    use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
    use boring::bn::BigNum;
    use boring::ecdsa::EcdsaSig;
    use boring::pkey::{PKey, Public};
    use boring::rsa::Rsa;
    use sha2::{Digest as _, Sha256, Sha384};
    use subtle::ConstantTimeEq as _;

    // Sizes and offsets are from the attestation_data definition:
    // https://github.com/AMDESE/sev-guest/blob/bb790bd9d65ed1e4012d7bb2b45be90c6f567e03/include/attestation.h#L45
    const SIG_PART_SIZE: usize = 48;
    const SIG_PART_CAPACITY: usize = 72;
    const REPORT_SIZE: usize = 1184;
    pub const SIGNATURE_OFFSET: usize = 0x2A0;
    const REPORT_DATA_OFFSET: usize = 0x50;
    const SHA256_SIZE: usize = 32;

    pub const ARK_GENOA_ROOT_PEM: &[u8] = include_bytes!("../res/ark_genoa.pem");
    pub const ARK_MILAN_ROOT_PEM: &[u8] = include_bytes!("../res/ark_milan.pem");

    #[allow(clippy::enum_variant_names)]
    #[derive(Debug, displaydoc::Display)]
    pub enum Error {
        /// Invalid SNP signature
        InvalidSignature,
        /// Invalid SNP report
        InvalidReport,
        /// Invalid runtime data
        InvalidRuntimeData,
        /// Invalid EC Key
        InvalidKey,
    }
    pub type Result<T> = std::result::Result<T, Error>;

    pub struct Report<'a>(&'a [u8]);
    pub struct RuntimeData<'a>(&'a [u8]);

    impl<'a> Report<'a> {
        pub fn new(bytes: &'a [u8]) -> Result<Self> {
            if bytes.len() != REPORT_SIZE {
                return Err(Error::InvalidReport);
            }

            Ok(Self(bytes))
        }

        pub fn verify(&self, public_key: PKey<Public>) -> Result<()> {
            let digest = Sha384::digest(self.data());
            let signature = self.signature();
            let ec_key = public_key.ec_key().map_err(|_| Error::InvalidKey)?;
            match signature.verify(digest.as_slice(), &ec_key) {
                Ok(true) => Ok(()),
                Ok(false) | Err(_) => Err(Error::InvalidSignature),
            }
        }

        pub fn digest(&self) -> &'a [u8] {
            &self.0[REPORT_DATA_OFFSET..][..SHA256_SIZE]
        }

        fn data(&self) -> &'a [u8] {
            &self.0[..SIGNATURE_OFFSET]
        }

        fn signature(&self) -> EcdsaSig {
            // Signature fields are stored in little endian,
            // but boring ECDSA implementation expects big endian.
            fn reversed(bytes: &[u8]) -> Vec<u8> {
                let mut bytes = bytes.to_vec();
                bytes.reverse();
                bytes
            }

            let signature_bytes = &self.0[SIGNATURE_OFFSET..];
            let r = reversed(&signature_bytes[..SIG_PART_SIZE]);
            let s = reversed(&signature_bytes[SIG_PART_CAPACITY..][..SIG_PART_SIZE]);
            let r = BigNum::from_slice(&r).expect("can extract r");
            let s = BigNum::from_slice(&s).expect("can extract s");
            EcdsaSig::from_private_components(r, s).expect("can initialize signature")
        }
    }

    impl<'a> RuntimeData<'a> {
        pub fn new(bytes: &'a [u8]) -> Result<Self> {
            // Delay any verification.
            Ok(Self(bytes))
        }

        pub fn verify(&self, report: Report) -> Result<Rsa<Public>> {
            let digest = Sha256::digest(self.0);
            if !bool::from(digest.ct_eq(report.digest())) {
                return Err(Error::InvalidRuntimeData);
            }
            self.verify_json()
        }

        fn verify_json(&self) -> Result<Rsa<Public>> {
            let doc: RuntimeDocument =
                serde_json::from_slice(self.0).map_err(|_| Error::InvalidRuntimeData)?;
            let key = doc
                .keys
                .iter()
                .find(|entry| entry.kid == "HCLAkPub" && entry.kty == "RSA")
                .ok_or(Error::InvalidRuntimeData)?;

            fn to_big_num(b64: &str) -> Result<BigNum> {
                let raw = BASE64_URL_SAFE_NO_PAD
                    .decode(b64)
                    .map_err(|_| Error::InvalidRuntimeData)?;
                BigNum::from_slice(&raw).map_err(|_| Error::InvalidRuntimeData)
            }
            let n = to_big_num(key.n)?;
            let e = to_big_num(key.e)?;
            Rsa::from_public_components(n, e).map_err(|_| Error::InvalidRuntimeData)
        }
    }

    #[derive(serde::Deserialize, Debug)]
    struct KeyEntry<'a> {
        kid: &'a str,
        e: &'a str,
        n: &'a str,
        kty: &'a str,
    }

    #[derive(serde::Deserialize, Debug)]
    struct RuntimeDocument<'a> {
        #[serde(borrow)]
        keys: Vec<KeyEntry<'a>>,
    }
}

impl From<DcapError> for Error {
    fn from(err: DcapError) -> Self {
        Error::AttestationDataError {
            reason: err.to_string(),
        }
    }
}

impl From<snp::Error> for Error {
    fn from(err: snp::Error) -> Self {
        Error::AttestationDataError {
            reason: err.to_string(),
        }
    }
}

fn verify_tpm2_quote<'a>(
    evidence: &'a svr2::AsnpEvidence,
    expected_pcrs: &tpm2::PcrMap,
) -> Result<tpm2::Report<'a>> {
    let signature = tpm2::Signature::from_slice(&evidence.sig)?;
    let report = {
        let akcert = X509::from_der(&evidence.akcert_der).expect("can parse akcert der");
        let verified = signature.verify_report(&evidence.msg, &akcert)?;
        tpm2::Report::from_slice(verified)?
    };

    let pcrs = {
        let verified = report.verify_pcrs(&evidence.pcrs)?;
        tpm2::Pcrs::from_slice(verified)?
    };
    pcrs.validate(expected_pcrs)?;

    Ok(report)
}

pub(crate) mod tpm2 {
    use boring::hash::MessageDigest;
    use boring::sign::Verifier;
    use boring::x509::X509;
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
        pub millis_since_clear: u64,
        pub resets: u32,
        pub restarts: u32,
        pub safe: u8,
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

    impl<'a> AsRef<[u8]> for VerifiedBytes<'a> {
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
                let safe = view.read_u8().map_err(|_| Error::InvalidReport)?;
                Clock {
                    millis_since_clear,
                    resets,
                    restarts,
                    safe,
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
        use super::*;
        use assert_matches::assert_matches;
        use hex_literal::hex;
        use test_case::test_case;

        const VALID_SIGNATURE: &[u8] = include_bytes!("../tests/data/tpm2_valid_signature.dat");
        const VALID_REPORT: &[u8] = include_bytes!("../tests/data/tpm2_valid_report.dat");
        const VALID_PCRS: &[u8] = include_bytes!("../tests/data/tpm2_valid_pcrs.dat");
        const VALID_CERT_PEM: &[u8] = include_bytes!("../tests/data/tpm2snp_valid_cert.pem");

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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::ENCLAVE_ID_SVR3_TPM2SNP_STAGING;
    use std::time::Duration;

    #[test]
    fn full_tpm2snp_attestation() {
        let attestation_data = include_bytes!("../tests/data/tpm2snp_attestation_msg.dat");
        let attestation = svr2::ClientHandshakeStart::decode(attestation_data.as_slice())
            .expect("valid protobuf");
        let evidence =
            svr2::AsnpEvidence::decode(attestation.evidence.as_slice()).expect("valid evidence");
        let endorsements = svr2::AsnpEndorsements::decode(attestation.endorsement.as_slice())
            .expect("valid endorsements");
        attest(
            ENCLAVE_ID_SVR3_TPM2SNP_STAGING,
            &evidence,
            &endorsements,
            SystemTime::UNIX_EPOCH + VALID_TIMESTAMP,
        )
        .expect("can attest asnp");
    }

    const VALID_TIMESTAMP: Duration = Duration::from_millis(1710875945000);
}
