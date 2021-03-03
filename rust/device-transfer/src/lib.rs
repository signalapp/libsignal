//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![deny(unsafe_code)]

use chrono::{Duration, Timelike, Utc};
use num_bigint_dig::traits::ModInverse;
use rand::{rngs::OsRng, Rng};
use rsa::{PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use sha2::{Digest, Sha256};
use std::fmt;
use yasna::models::{ObjectIdentifier, UTCTime};
use yasna::Tag;

#[derive(Copy, Clone, Debug)]
pub enum Error {
    KeyDecodingFailed,
    InternalError(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::KeyDecodingFailed => write!(f, "Decoding provided RSA private key failed"),
            Error::InternalError(s) => write!(f, "Internal error in device tranfer ({})", s),
        }
    }
}
fn to_yasna_biguint(v: &rsa::BigUint) -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_be(&v.to_bytes_be())
}

fn to_yasna_bigint(v: &num_bigint_dig::BigInt) -> num_bigint::BigInt {
    let enc = v.to_bytes_be();
    num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &enc.1)
}

#[allow(clippy::many_single_char_names)]
pub fn create_rsa_private_key(bits: usize) -> Result<Vec<u8>, Error> {
    let mut rng = OsRng;
    let priv_key = RSAPrivateKey::new(&mut rng, bits)
        .map_err(|_| Error::InternalError("RSA key generation failed"))?;
    let pub_key = RSAPublicKey::from(&priv_key);

    let primes = priv_key.primes();
    assert_eq!(primes.len(), 2);

    let one = rsa::BigUint::from_slice(&[1]);

    let p = &primes[0];
    let q = &primes[1];
    let e = pub_key.e();
    let n = pub_key.n();
    let d = priv_key.d();
    let d1 = d % (p - &one);
    let d2 = d % (q - &one);
    let c = q
        .mod_inverse(p)
        .ok_or(Error::InternalError("Could not produce modular inverse"))?;

    let rsa_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]);

    let encoded_key = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_i64(0); // rsa key version
            w.next().write_biguint(&to_yasna_biguint(&n));
            w.next().write_biguint(&to_yasna_biguint(&e));
            w.next().write_biguint(&to_yasna_biguint(&d));
            w.next().write_biguint(&to_yasna_biguint(&p));
            w.next().write_biguint(&to_yasna_biguint(&q));
            w.next().write_biguint(&to_yasna_biguint(&d1));
            w.next().write_biguint(&to_yasna_biguint(&d2));
            w.next().write_bigint(&to_yasna_bigint(&c));
        });
    });

    let pkcs8 = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            // pkcs8 version
            w.next().write_i64(0);
            // algorithm identifier
            w.next().write_sequence(|w| {
                w.next().write_oid(&rsa_oid);
                w.next().write_null();
            });
            w.next().write_bytes(&encoded_key);
        })
    });

    Ok(pkcs8)
}

pub fn create_self_signed_cert(
    rsa_key: &[u8],
    name: &str,
    days_to_expire: u32,
) -> Result<Vec<u8>, Error> {
    let private_key = RSAPrivateKey::from_pkcs8(rsa_key).map_err(|_| Error::KeyDecodingFailed)?;
    let public_key = RSAPublicKey::from(&private_key);

    let n = public_key.n();
    let e = public_key.e();

    let mut rng = rand::rngs::OsRng;

    // random serialize number
    let serial: Vec<u8> = (0..20).map(|_| rng.gen()).collect();

    let rsa_sha256_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 11]);
    let rsa_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]);

    let now = Utc::now()
        .with_nanosecond(0)
        .ok_or(Error::InternalError("Could not get time with cleared ns"))?;
    let not_before = UTCTime::from_datetime::<Utc>(&now);
    let not_after = UTCTime::from_datetime::<Utc>(&(now + Duration::days(days_to_expire.into())));

    let mut dn = vec![];
    dn.push((vec![2, 5, 4, 3], name.to_string()));
    dn.push((vec![2, 5, 4, 10], "Signal Messenger LLC".to_owned()));
    dn.push((vec![2, 5, 4, 11], "Device Transfer".to_owned()));

    let encoded_key = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_biguint(&to_yasna_biguint(&n));
            w.next().write_biguint(&to_yasna_biguint(&e));
        });
    });

    // TBSCertificate (see RFC 5280 section 4.1.2)
    let tbs_cert = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            // v3 (2 in wire format)
            w.next().write_tagged(Tag::context(0), |w| {
                w.write_u8(2);
            });
            // serial number
            w.next()
                .write_biguint(&num_bigint::BigUint::from_bytes_be(&serial));
            // signature algo identifier
            w.next().write_sequence(|w| {
                w.next().write_oid(&rsa_sha256_oid);
                w.next().write_null();
            });

            // issuer DN
            w.next().write_sequence(|w| {
                for (oid, value) in dn.iter() {
                    w.next().write_set(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&ObjectIdentifier::from_slice(&oid));
                            w.next().write_utf8_string(value);
                        });
                    });
                }
            });

            // Write validity
            w.next().write_sequence(|w| {
                w.next().write_utctime(&not_before);
                w.next().write_utctime(&not_after);
            });

            // subject DN (same as issuer here)
            w.next().write_sequence(|w| {
                for (oid, value) in dn.iter() {
                    w.next().write_set(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&ObjectIdentifier::from_slice(&oid));
                            w.next().write_utf8_string(value);
                        });
                    });
                }
            });

            w.next().write_sequence(|w| {
                // key algo identifier
                w.next().write_sequence(|w| {
                    w.next().write_oid(&rsa_oid);
                    w.next().write_null();
                });

                w.next()
                    .write_bitvec_bytes(&encoded_key, 8 * encoded_key.len());
            });

            // No v3 extensions
        });
    });

    let padding = rsa::PaddingScheme::PKCS1v15Sign {
        hash: Some(rsa::Hash::SHA2_256),
    };

    let tbs_cert_digest = Sha256::digest(&tbs_cert);
    let signature = private_key
        .sign_blinded(&mut rng, padding, &tbs_cert_digest)
        .expect("Signing worked");

    let signed_cert = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&tbs_cert);

            w.next().write_sequence(|w| {
                w.next().write_oid(&rsa_sha256_oid);
                w.next().write_null();
            });

            w.next().write_bitvec_bytes(&signature, 8 * signature.len());
        })
    });

    Ok(signed_cert)
}
