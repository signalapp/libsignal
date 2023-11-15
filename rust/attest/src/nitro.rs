//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use boring::bn::BigNum;
use boring::ecdsa::EcdsaSig;
use boring::stack;
use boring::x509::store::X509StoreBuilder;
use boring::x509::{X509StoreContext, X509};
use ciborium::value::{Integer, Value};
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use std::time::SystemTime;
use subtle::ConstantTimeEq;

pub const PUBLIC_KEY_LENGTH: usize = 32;

pub type PublicKeyBytes = [u8; PUBLIC_KEY_LENGTH];

pub fn attest(
    evidence: &[u8],
    expected_pcrs: &HashMap<usize, Vec<u8>>,
    now: SystemTime,
) -> Result<PublicKeyBytes, NitroError> {
    let cose_sign1 = CoseSign1::from_bytes(evidence)?;
    let doc = cose_sign1.extract_attestation_doc(now)?;
    doc.extract_public_key(expected_pcrs)
}

#[derive(Debug, displaydoc::Display, PartialEq, Eq)]
pub enum NitroError {
    /// Invalid CBOR
    InvalidCbor,
    /// Invalid COSE_Sign1
    InvalidCoseSign1,
    /// Invalid signature
    InvalidSignature,
    /// Invalid attestation document
    InvalidAttestationDoc,
    /// Invalid certificate: {0}
    InvalidCertificate(String),
    /// Invalid PCRs
    InvalidPcrs,
    /// Invalid Public Key
    InvalidPublicKey,
}

impl std::error::Error for NitroError {}

impl From<ciborium::de::Error<std::io::Error>> for NitroError {
    fn from(_err: ciborium::de::Error<std::io::Error>) -> NitroError {
        NitroError::InvalidCbor
    }
}

impl From<boring::error::ErrorStack> for NitroError {
    fn from(err: boring::error::ErrorStack) -> NitroError {
        NitroError::InvalidCertificate(err.to_string())
    }
}

struct CoseSign1 {
    protected_header: Vec<u8>,
    // nitro has no unprotected header
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NitroError> {
        let value: Value = ciborium::from_reader(bytes)?;
        value.try_into()
    }

    pub fn extract_attestation_doc(&self, now: SystemTime) -> Result<AttestationDoc, NitroError> {
        let hash = Sha384::digest(self.to_canonical());
        let r = BigNum::from_slice(&self.signature[..48]).expect("can extract r");
        let s = BigNum::from_slice(&self.signature[48..]).expect("can extract s");
        let sig = EcdsaSig::from_private_components(r, s).expect("can initialize signature");

        let doc = AttestationDoc::from_bytes(self.payload.as_slice()).expect("can parse doc");
        let cert = doc.verified_cert(now)?;
        let key = cert
            .public_key()
            .and_then(|pub_key| pub_key.ec_key())
            .expect("has EC key");
        let is_valid = sig.verify(hash.as_slice(), &key).expect("can verify");
        if !is_valid {
            return Err(NitroError::InvalidSignature);
        }
        Ok(doc)
    }

    fn validating_new(
        protected_header: Vec<u8>,
        payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, NitroError> {
        let is_valid = {
            let mut is_valid = true;
            is_valid &= Self::is_valid_protected_header(&protected_header);
            is_valid &= (1..16384).contains(&payload.len());
            is_valid &= signature.len() == 96;
            is_valid
        };
        if !is_valid {
            return Err(NitroError::InvalidCoseSign1);
        }
        Ok(CoseSign1 {
            protected_header,
            payload,
            signature,
        })
    }

    fn is_valid_protected_header(bytes: &[u8]) -> bool {
        let signing_algorithm: Integer = Integer::from(1);
        let ecdsa_sha_384: Integer = Integer::from(-35);
        let value: Value = ciborium::from_reader(bytes).expect("valid cbor");
        match value {
            Value::Map(vec) => match &vec[..] {
                [(Value::Integer(key), Value::Integer(val))] => {
                    key == &signing_algorithm && val == &ecdsa_sha_384
                }
                _ => false,
            },
            _ => false,
        }
    }

    fn to_canonical(&self) -> Vec<u8> {
        let value = Value::Array(vec![
            Value::Text("Signature1".to_string()),
            Value::Bytes(self.protected_header.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(self.payload.clone()),
        ]);
        let mut bytes = Vec::with_capacity(self.protected_header.len() + self.payload.len());
        ciborium::into_writer(&value, &mut bytes).expect("can write bytes");
        bytes
    }
}

impl TryFrom<Value> for CoseSign1 {
    type Error = NitroError;

    // Assumes tagged CBOR encoding of COSE_Sign1
    fn try_from(value: Value) -> Result<CoseSign1, NitroError> {
        let parts: [Value; 4] = value
            .into_array()
            .ok()
            .and_then(|vs| vs.try_into().ok())
            .ok_or(NitroError::InvalidCoseSign1)?;
        match parts {
            [Value::Bytes(protected_header), Value::Map(_), Value::Bytes(payload), Value::Bytes(signature)] => {
                CoseSign1::validating_new(protected_header, payload, signature)
            }
            _ => Err(NitroError::InvalidCoseSign1),
        }
    }
}

// Values of the fields are validated as they are read from the CBOR value and are not used beyond
// that. Marking them as allowed dead code for now until it is clear we don't really even need them
// after extracting the public key.
#[allow(dead_code)]
struct AttestationDoc {
    module_id: String,
    digest: String,
    timestamp: i64,
    pcrs: Vec<(usize, Vec<u8>)>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl TryFrom<Value> for AttestationDoc {
    type Error = NitroError;

    fn try_from(value: Value) -> Result<AttestationDoc, NitroError> {
        let map = AttestationDoc::parse_as_cbor_map(value)?;
        Self::from_cbor_map(map)
    }
}

type CborMap = HashMap<String, Value>;

impl AttestationDoc {
    fn from_bytes(bytes: &[u8]) -> Result<AttestationDoc, NitroError> {
        let value: Value = ciborium::from_reader(bytes)?;
        value.try_into()
    }

    fn parse_as_cbor_map(value: Value) -> Result<CborMap, NitroError> {
        value
            .into_map()
            .map_err(|_| NitroError::InvalidAttestationDoc)?
            .into_iter()
            .map(|(k, v)| {
                let k = k
                    .into_text()
                    .map_err(|_| NitroError::InvalidAttestationDoc)?;
                Ok((k, v))
            })
            .collect()
    }

    fn from_cbor_map(mut map: CborMap) -> Result<AttestationDoc, NitroError> {
        let module_id = map
            .remove("module_id")
            .and_then(|value| value.into_text().ok())
            .filter(|s| !s.is_empty())
            .ok_or(NitroError::InvalidAttestationDoc)?;
        let digest = map
            .remove("digest")
            .and_then(|value| value.into_text().ok())
            .filter(|s| s == "SHA384")
            .ok_or(NitroError::InvalidAttestationDoc)?;
        let timestamp = map
            .remove("timestamp")
            .and_then(|value| value.into_integer().ok())
            .and_then(|integer| i64::try_from(integer).ok())
            .filter(|i| i.is_positive())
            .ok_or(NitroError::InvalidAttestationDoc)?;
        let pcrs: Vec<(usize, Vec<u8>)> = map
            .remove("pcrs")
            .and_then(|value| value.into_map().ok())
            .and_then(|pairs| {
                if !(1..=32).contains(&pairs.len()) {
                    return None;
                }
                let mut pcrs = Vec::with_capacity(pairs.len());
                for (key, value) in pairs.into_iter() {
                    let index = key
                        .into_integer()
                        .ok()
                        .and_then(|n| usize::try_from(n).ok())
                        .filter(|n| (0..32).contains(n))?;
                    let bytes = value
                        .into_bytes()
                        .ok()
                        .filter(|bs| [32, 48, 64].contains(&bs.len()))?;
                    pcrs.push((index, bytes))
                }
                Some(pcrs)
            })
            .ok_or(NitroError::InvalidAttestationDoc)?;

        fn into_valid_cert_bytes(value: Value) -> Option<Vec<u8>> {
            value
                .into_bytes()
                .ok()
                .filter(|bs| (1..=1024).contains(&bs.len()))
        }

        let certificate = map
            .remove("certificate")
            .and_then(into_valid_cert_bytes)
            .ok_or(NitroError::InvalidAttestationDoc)?;

        let cabundle = map
            .remove("cabundle")
            .and_then(|value| value.into_array().ok())
            .and_then(|vals| {
                let certs: Vec<_> = vals.into_iter().filter_map(into_valid_cert_bytes).collect();
                if certs.is_empty() {
                    return None;
                }
                Some(certs)
            })
            .ok_or(NitroError::InvalidAttestationDoc)?;

        fn into_valid_optional_bytes(
            value: Value,
            expected_length: usize,
        ) -> Result<Vec<u8>, NitroError> {
            match value.into_bytes() {
                Ok(bytes) if bytes.len() <= expected_length => Ok(bytes),
                Err(Value::Null) => Ok(vec![]),
                Ok(_) | Err(_) => Err(NitroError::InvalidAttestationDoc),
            }
        }

        let public_key = map
            .remove("public_key") // option<value>
            .map(|value| into_valid_optional_bytes(value, 1024))
            .transpose()?;

        let user_data = map
            .remove("user_data")
            .map(|value| into_valid_optional_bytes(value, 512))
            .transpose()?;

        let nonce = map
            .remove("nonce")
            .map(|value| into_valid_optional_bytes(value, 10))
            .transpose()?;

        Ok(AttestationDoc {
            module_id,
            digest,
            timestamp,
            pcrs,
            certificate,
            cabundle,
            public_key,
            user_data,
            nonce,
        })
    }

    fn verified_cert(&self, now: SystemTime) -> Result<X509, NitroError> {
        let mut context = X509StoreContext::new()?;
        let certificate = X509::from_der(&self.certificate)?;
        let mut stack = stack::Stack::<X509>::new()?;
        for der in self.cabundle.iter() {
            let cert = X509::from_der(der)?;
            stack.push(cert)?;
        }
        let stack = stack;
        let trust = {
            let root = X509::from_pem(ROOT_CERTIFICATE_PEM)?;
            let mut builder = X509StoreBuilder::new()?;
            builder.param_mut().set_time(
                now.duration_since(SystemTime::UNIX_EPOCH)
                    .expect("current time is after 1970")
                    .as_secs()
                    .try_into()
                    .expect("haven't yet overflowed time_t"),
            );
            builder.add_cert(root)?;
            builder.build()
        };
        let is_valid = context.init(&trust, &certificate, &stack, |ctx| ctx.verify_cert())?;
        if !is_valid {
            let message = context.error().to_string();
            return Err(NitroError::InvalidCertificate(message));
        }
        Ok(certificate)
    }

    fn extract_public_key(
        &self,
        expected_pcrs: &HashMap<usize, Vec<u8>>,
    ) -> Result<PublicKeyBytes, NitroError> {
        let mut is_match = true;
        for (index, pcr) in self.pcrs.iter() {
            is_match &= expected_pcrs
                .get(index)
                .map(|expected| expected.ct_eq(pcr).into())
                // if the index is missing from the expected_pcrs we do not check it
                .unwrap_or(true);
        }
        if !is_match {
            return Err(NitroError::InvalidPcrs);
        }
        self.public_key
            .clone()
            .ok_or(NitroError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| NitroError::InvalidPublicKey)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use std::time::Duration;

    #[test]
    fn test_extract_attestation_doc() {
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1684362463);
        let cose_sign1 = CoseSign1::from_bytes(VALID_DOCUMENT_BYTES_1).expect("can parse");
        cose_sign1
            .extract_attestation_doc(timestamp)
            .expect("valid signature");
    }

    #[test]
    fn test_attestation() {
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1684948138);
        let _pk = CoseSign1::from_bytes(VALID_DOCUMENT_BYTES_2)
            .expect("can parse")
            .extract_attestation_doc(timestamp)
            .expect("valid signature")
            .extract_public_key(&get_test_pcrs())
            .expect("valid pcrs");
    }

    #[test]
    fn test_expired_cert() {
        let cose_sign1 = CoseSign1::from_bytes(VALID_DOCUMENT_BYTES_1).expect("can parse");
        match cose_sign1.extract_attestation_doc(SystemTime::now()) {
            Err(err) => assert!(format!("{err:?}").contains("expired")),
            Ok(_) => panic!("Should have failed"),
        }
    }

    #[test]
    fn test_not_yet_valid_cert() {
        let cose_sign1 = CoseSign1::from_bytes(VALID_DOCUMENT_BYTES_1).expect("can parse");
        match cose_sign1.extract_attestation_doc(SystemTime::UNIX_EPOCH) {
            Err(err) => assert!(format!("{err:?}").contains("not yet valid")),
            Ok(_) => panic!("Should have failed"),
        }
    }

    #[test]
    fn test_invalid_signature() {
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1684362463);
        let mut cose_sign1 = CoseSign1::from_bytes(VALID_DOCUMENT_BYTES_1).expect("can parse");
        cose_sign1.signature[0] ^= 0xff;
        match cose_sign1.extract_attestation_doc(timestamp) {
            Err(err) => assert_eq!(NitroError::InvalidSignature, err),
            Ok(_) => panic!("Should have failed"),
        }
    }

    fn invalid_cose_sign1_test<F>(mut f: F)
    where
        F: FnMut(&mut CoseSign1),
    {
        let mut subject = CoseSign1::from_bytes(VALID_DOCUMENT_BYTES_1).expect("can parse");
        f(&mut subject);
        match CoseSign1::validating_new(
            subject.protected_header,
            subject.payload,
            subject.signature,
        ) {
            Err(err) => assert_eq!(NitroError::InvalidCoseSign1, err),
            Ok(_) => panic!("Should have failed"),
        }
    }

    #[test]
    fn test_invalid_cose_sign1_signature_len() {
        invalid_cose_sign1_test(|subject| subject.signature.push(0x00));
    }

    #[test]
    fn test_invalid_cose_sign1_empty_payload() {
        invalid_cose_sign1_test(|subject| subject.payload = vec![]);
    }

    #[test]
    fn test_invalid_cose_sign1_payload_too_large() {
        invalid_cose_sign1_test(|subject| subject.payload = [0; 16384].to_vec());
    }

    #[test]
    fn test_invalid_cose_sign1_invalid_header() {
        invalid_cose_sign1_test(|subject| subject.protected_header = vec![1, 2, 3]);
    }

    #[test]
    fn test_canonical_serialization() {
        let subject = CoseSign1::from_bytes(VALID_DOCUMENT_BYTES_1).expect("can parse");
        assert_eq!(subject.to_canonical(), VALID_DOCUMENT_BYTES_1_CANONICAL);
    }

    #[test]
    fn test_non_string_keys() {
        let value: Value = Value::Map(vec![(Value::Integer(42.into()), Value::Integer(42.into()))]);
        let err =
            AttestationDoc::parse_as_cbor_map(value).expect_err("Should have failed validation");
        assert_eq!(err, NitroError::InvalidAttestationDoc);
    }

    fn invalid_attestation_doc_test<F>(mut f: F)
    where
        F: FnMut(&mut CborMap),
    {
        let cose_sign1 = CoseSign1::from_bytes(VALID_DOCUMENT_BYTES_1).expect("valid cose_sign1");
        let value: Value =
            ciborium::from_reader(cose_sign1.payload.as_slice()).expect("valid cbor");
        let mut map = AttestationDoc::parse_as_cbor_map(value).expect("valid cbor map");
        f(&mut map);
        match AttestationDoc::from_cbor_map(map) {
            Err(err) => assert_eq!(NitroError::InvalidAttestationDoc, err),
            Ok(_) => panic!("Should have failed"),
        }
    }

    #[test]
    fn test_empty_module_id() {
        invalid_attestation_doc_test(|map| {
            *map.get_mut("module_id").unwrap() = Value::Text("".to_string());
        });
    }

    #[test]
    fn test_invalid_digest() {
        invalid_attestation_doc_test(|map| {
            *map.get_mut("digest").unwrap() = Value::Text("not sha384".to_string());
        });
    }

    #[test]
    fn test_zero_timestamp() {
        invalid_attestation_doc_test(|map| {
            *map.get_mut("timestamp").unwrap() = Value::Integer(0.into());
        });
    }

    #[test]
    fn test_empty_pcrs() {
        invalid_attestation_doc_test(|map| {
            *map.get_mut("pcrs").unwrap() = Value::Array(vec![]);
        });
    }

    #[test]
    fn test_too_many_pcrs() {
        invalid_attestation_doc_test(|map| {
            *map.get_mut("pcrs").unwrap() = Value::Array(
                (1..33)
                    // Should be a byte array, but any Value would do for length validation
                    .map(|i| Value::Integer(i.into()))
                    .collect(),
            );
        });
    }

    #[test]
    fn test_invalid_pcr_index() {
        invalid_attestation_doc_test(|map| {
            let pcrs = map.get_mut("pcrs").unwrap();
            let pcr = pcrs.as_map_mut().unwrap();
            pcr[0] = (Value::Integer(32.into()), pcr[0].1.clone());
        });
    }

    #[test]
    fn test_invalid_pcr_length() {
        invalid_attestation_doc_test(|map| {
            let pcrs = map.get_mut("pcrs").unwrap();
            let pcr = pcrs.as_map_mut().unwrap();
            pcr[0] = (pcr[0].0.clone(), Value::Bytes(b"00010203".to_vec()));
        });
    }

    #[test]
    fn test_empty_certificate() {
        invalid_attestation_doc_test(|map| {
            *map.get_mut("certificate").unwrap() = Value::Bytes(vec![]);
        });
    }

    #[test]
    fn test_certificate_too_long() {
        invalid_attestation_doc_test(|map| {
            *map.get_mut("certificate").unwrap() = Value::Bytes([0; 1025].to_vec());
        });
    }

    #[test]
    fn test_public_key_too_long() {
        invalid_attestation_doc_test(|map| {
            map.insert("public_key".to_string(), Value::Bytes([0; 1025].to_vec()));
        });
    }

    #[test]
    fn test_user_data_too_long() {
        invalid_attestation_doc_test(|map| {
            map.insert("user_data".to_string(), Value::Bytes([0; 513].to_vec()));
        });
    }

    #[test]
    fn test_nonce_too_long() {
        invalid_attestation_doc_test(|map| {
            map.insert("nonce".to_string(), Value::Bytes([0; 513].to_vec()));
        });
    }

    const VALID_DOCUMENT_BYTES_1: &[u8] = include_bytes!("../tests/data/test_cose_sign1_01.dat");
    const VALID_DOCUMENT_BYTES_1_CANONICAL: &[u8] =
        include_bytes!("../tests/data/cose_sign1_canonical.dat");
    const VALID_DOCUMENT_BYTES_2: &[u8] = include_bytes!("../tests/data/test_cose_sign1_02.dat");

    fn get_test_pcrs() -> HashMap<usize, Vec<u8>> {
        let mut map = HashMap::<usize, _>::new();
        map.insert(0, hex!("28de6557cce896cf8c580d8674fbc13c45c1a7636545ef022a01007336b8752b9a1cd9ce69df2ecacc7696a1203b45c2").to_vec());
        map.insert(1, hex!("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546").to_vec());
        map.insert(2, hex!("3bc780f5f2adc596f55c5d8b85760f1e9e585c7016957673616c0611280c4b99c8877caff00d70567a96979abe59dc0a").to_vec());
        map.insert(3, hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").to_vec());
        map.insert(4, hex!("17354aa3f163d6882a4ff746e5821c5be66f1658472feac83268cf4b7461015ea47993c07025ebb5e134cbc13b16ac97").to_vec());
        map
    }
}

// From https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// Zip hash (SHA256): 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c
const ROOT_CERTIFICATE_PEM: &[u8] = br"
-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
";
