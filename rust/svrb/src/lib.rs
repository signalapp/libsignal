//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::Write;
use std::iter::repeat_with;
use std::num::{NonZeroU32, NonZeroUsize};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use protobuf::Message;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256, Sha512};

use crate::proto::svrb;

mod errors;
pub use errors::Error;
pub mod proto;
pub use proto::backup4::Backup4 as Backup4Proto;
pub use proto::svrb::response4::Status as V4Status;

const SECRET_BYTES: usize = 32;

pub type Secret = [u8; 32];

#[derive(Debug, PartialEq, Eq)]
pub struct EvaluationResult {
    pub value: [u8; SECRET_BYTES],
    pub tries_remaining: u32,
}

impl EvaluationResult {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(std::mem::size_of::<u32>() + SECRET_BYTES);
        bytes
            .write_all(&self.tries_remaining.to_be_bytes())
            .expect("can write to Vec");
        bytes.write_all(&self.value).expect("can write to Vec");
        bytes
    }
}

/// Perfrom array XOR: into ^= from
fn arr_xor(from: &[u8], into: &mut [u8]) {
    assert_eq!(from.len(), into.len());
    for (dst, src) in std::iter::zip(into, from) {
        *dst ^= src;
    }
}

pub struct Query4 {}

impl Query4 {
    pub fn requests() -> impl Iterator<Item = Vec<u8>> {
        std::iter::repeat(
            svrb::Request4 {
                inner: Some(svrb::request4::Inner::Query(svrb::request4::Query {
                    ..Default::default()
                })),
                ..Default::default()
            }
            .write_to_bytes()
            .expect("serialization succeeds"),
        )
    }

    pub fn finalize(responses: &[Vec<u8>]) -> Result<u32, Error> {
        assert!(!responses.is_empty());
        responses
            .iter()
            .map(|b| svrb::Response4::parse_from_bytes(b.as_ref()).map_err(|_| Error::BadData))
            .map(|rr| match rr?.inner {
                Some(svrb::response4::Inner::Query(r)) => match status_error(r.status) {
                    Ok(()) => Ok(r.tries_remaining),
                    Err(e) => Err(e),
                },
                _ => Err(Error::BadData),
            })
            // Get the min tries_remaining while short circuiting on errors.
            // Should never actually return u32::MAX, since there should be at least one
            // response, which will either be an error (returning an error overall)
            // or a value less than MAX.
            .try_fold(u32::MAX, |acc, tr| Ok(std::cmp::min(acc, tr?)))
    }
}

pub struct Remove4 {}

impl Remove4 {
    pub fn requests() -> impl Iterator<Item = Vec<u8>> {
        std::iter::repeat(
            svrb::Request4 {
                inner: Some(svrb::request4::Inner::Remove(svrb::request4::Remove {
                    ..Default::default()
                })),
                ..Default::default()
            }
            .write_to_bytes()
            .expect("serialization succeeds"),
        )
    }
}

fn random_scalar<R: Rng + CryptoRng>(r: &mut R) -> Scalar {
    let mut scalar_bytes = [0u8; 64];
    r.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
}

/// Returns a list of `n` scalars which are chosen randomly but
/// which will sum up to `s`.
fn scalars_summing_to<R: Rng + CryptoRng>(n: NonZeroUsize, s: &Scalar, rng: &mut R) -> Vec<Scalar> {
    let mut v: Vec<Scalar> = repeat_with(|| random_scalar(rng))
        .take(n.get() - 1)
        .collect();
    let sum: Scalar = v.iter().sum();
    v.push(Scalar::ZERO - sum + s);
    v
}

/// Return a list of `n` byte vectors which are chosen randomly
/// but which will XOR together to `b`.
fn bytes_xoring_to<R: Rng + CryptoRng>(n: NonZeroUsize, b: &[u8], rng: &mut R) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = repeat_with(|| {
        let mut e = vec![0; b.len()];
        rng.fill_bytes(e.as_mut_slice());
        e
    })
    .take(n.get() - 1)
    .collect();
    let mut xor: Vec<u8> = b.into();
    for vec in v.iter() {
        arr_xor(vec, &mut xor);
    }
    v.push(xor);
    v
}

trait KdfLength<const N: usize> {
    /// Key Derivation Function used throughout the rest of this code.
    fn make(info: &[u8], input1: &[u8], input2: &[u8]) -> [u8; N] {
        let mut out = [0; N];
        let concat_input: Vec<u8> = [input1, input2].concat();
        let h = hkdf::Hkdf::<Sha256>::new(None, &concat_input);
        h.expand(info, &mut out)
            .expect("all output lengths used are valid for key derivation");
        out
    }
}

enum Kdf {}

impl KdfLength<32> for Kdf {}
impl KdfLength<64> for Kdf {}

/// Return a set of (private, public) auth commitments based on the auth secret.
fn auth_commitments(
    server_ids: &[u64],
    input: &[u8; 64],
    auth_pt: &RistrettoPoint,
) -> Vec<(Scalar, RistrettoPoint)> {
    let k_auth = auth_secret(input, auth_pt);
    server_ids
        .iter()
        .map(|id| {
            Kdf::make(
                b"Signal_SVR_ServerAuthorizationKey_20240823",
                &k_auth,
                &id.to_be_bytes(),
            )
        })
        .map(|k: [u8; 64]| Scalar::hash_from_bytes::<Sha512>(&k))
        .map(|s| (s, RISTRETTO_BASEPOINT_TABLE * &s))
        .collect()
}

/// Returns the Ristretto point used for authentication.
fn auth_pt(input: &[u8; 64], k_oprf: &Scalar) -> RistrettoPoint {
    input_hash_pt(input) * k_oprf
}

/// Returns the secret used for authentication.
fn auth_secret(input: &[u8; 64], auth_pt: &RistrettoPoint) -> [u8; 32] {
    Kdf::make(
        b"Signal_SVR_MasterAuthorizationKey_20240823",
        input,
        &auth_pt.compress().to_bytes(),
    )
}

/// Return a RistrettoPoint created from our input.
fn input_hash_pt(input: &[u8; 64]) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(input)
}

fn to_ristretto_pt(b: &[u8]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(b).ok()?.decompress()
}

/// Given a set of password bytes from the client that may be in any
/// format or any length, generate a deterministic 64-byte key
/// for use in Backup/Restore operations.
fn password_to_uniform_input(passwd: &[u8]) -> [u8; 64] {
    Kdf::make(b"Signal_SVR_InputFromPassword_20240823", passwd, b"")
}

pub struct Backup4 {
    pub requests: Vec<Vec<u8>>,
    pub output: Secret,
}

impl Backup4 {
    pub fn new<R: Rng + CryptoRng>(
        server_ids: &[u64],
        password: &[u8],
        max_tries: NonZeroU32,
        rng: &mut R,
    ) -> Self {
        assert!(!server_ids.is_empty());
        let input = password_to_uniform_input(password);
        let k_oprf = random_scalar(rng);

        let mut s_enc = [0u8; 32];
        rng.fill_bytes(&mut s_enc);

        let n = NonZeroUsize::new(server_ids.len())
            .expect("server IDs nonempty as asserted in constructor");
        let oprf_keyshares = scalars_summing_to(n, &k_oprf, rng);
        let enc_keyshares = bytes_xoring_to(n, &s_enc, rng);
        let zero_keyshares = scalars_summing_to(n, &Scalar::ZERO, rng);

        let auth_pt = auth_pt(&input, &k_oprf);
        let auth_commitments = auth_commitments(server_ids, &input, &auth_pt);
        let version = rng.next_u32();
        let k_auth = auth_secret(&input, &auth_pt);
        let output = encryption_key(&s_enc, &k_auth);

        Self {
            requests: (0usize..server_ids.len())
                .map(|i| svrb::Request4 {
                    inner: Some(svrb::request4::Inner::Create(svrb::request4::Create {
                        version,
                        max_tries: max_tries.get(),
                        oprf_secretshare: oprf_keyshares[i].to_bytes().to_vec(),
                        auth_commitment: auth_commitments[i].1.compress().to_bytes().to_vec(),
                        encryption_secretshare: enc_keyshares[i].clone(),
                        zero_secretshare: zero_keyshares[i].to_bytes().to_vec(),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .map(|cr| cr.write_to_bytes().expect("serialization succeeds"))
                .collect(),
            output,
        }
    }

    pub fn into_pb(self) -> Backup4Proto {
        Backup4Proto {
            requests: self.requests,
            output: self.output.to_vec(),
            ..Default::default()
        }
    }

    pub fn from_pb(pb: Backup4Proto) -> Result<Self, Error> {
        Ok(Self {
            output: pb.output.try_into().map_err(|_| Error::BadData)?,
            requests: pb.requests,
        })
    }
}

fn encryption_key(s_enc: &[u8], k_auth: &[u8]) -> Secret {
    Kdf::make(b"Signal_SVR_EncryptionKey_20240823", s_enc, k_auth)
}

pub struct Restore1<'a> {
    server_ids: &'a [u64],
    input: [u8; 64],
    blind: Scalar,
    pub requests: Vec<Vec<u8>>,
}

pub struct Restore2<'a> {
    server_ids: &'a [u64],
    input: [u8; 64],
    auth_pt: RistrettoPoint,
    pub tries_remaining: u32,
    pub requests: Vec<Vec<u8>>,
}

fn status_error(s: protobuf::EnumOrUnknown<svrb::response4::Status>) -> Result<(), Error> {
    match s.enum_value() {
        Ok(svrb::response4::Status::OK) => Ok(()),
        Ok(s) => Err(Error::BadResponseStatus4(s)),
        Err(_) => Err(Error::BadResponse),
    }
}

fn status_errors<I: Iterator<Item = protobuf::EnumOrUnknown<svrb::response4::Status>>>(
    statuses: &mut I,
) -> Result<(), Error> {
    statuses.try_for_each(status_error)
}

impl<'a> Restore1<'a> {
    pub fn new<R: Rng + CryptoRng>(server_ids: &'a [u64], password: &[u8], rng: &mut R) -> Self {
        let blind = random_scalar(rng);
        let input = password_to_uniform_input(password);
        Restore1 {
            requests: server_ids
                .iter()
                .map(|_| svrb::Request4 {
                    inner: Some(svrb::request4::Inner::Restore1(svrb::request4::Restore1 {
                        blinded: (input_hash_pt(&input) * blind)
                            .compress()
                            .to_bytes()
                            .to_vec(),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .map(|rr| rr.write_to_bytes().expect("serialization succeeds"))
                .collect(),
            server_ids,
            blind,
            input,
        }
    }

    pub fn restore2<R: Rng + CryptoRng>(
        self,
        responses1_bytes: &[Vec<u8>],
        handshake_hashes: &[&[u8]],
        rng: &mut R,
    ) -> Result<Restore2<'a>, Error> {
        if responses1_bytes.len() != self.server_ids.len()
            || handshake_hashes.len() != self.server_ids.len()
        {
            return Err(Error::NumServers {
                servers: self.server_ids.len(),
                got: responses1_bytes.len(),
            });
        }
        let responses1 = responses1_bytes
            .iter()
            .map(|b| svrb::Response4::parse_from_bytes(b.as_ref()).map_err(|_| Error::BadResponse))
            .map(|rr| match rr?.inner {
                Some(svrb::response4::Inner::Restore1(r)) => Ok(r),
                _ => Err(Error::BadResponse),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let tries_remaining = responses1
            .iter()
            .filter(|rr| {
                matches!(
                    rr.status.enum_value(),
                    // These errors will decrement #tries, others will not.
                    // We only care about returning #tries_remaining in a case
                    // where it's decremented.
                    Ok(svrb::response4::Status::OK | svrb::response4::Status::ERROR)
                )
            })
            .map(|rr| rr.tries_remaining)
            .min();
        status_errors(&mut responses1.iter().map(|r| r.status)).map_err(
            |e| match tries_remaining {
                Some(tr) => Error::RestoreFailed(tr),
                None => e,
            },
        )?;

        let version = self
            .version_to_use(&responses1)
            .ok_or(Error::NoUsableVersion)?;
        let auths = self.auths_with_version(version, &responses1)?;
        let sum: RistrettoPoint = auths
            .iter()
            .map(|a| to_ristretto_pt(a.element.as_ref()).ok_or(Error::BadResponse))
            .reduce(|acc, a| Ok(acc? + a?))
            .expect("unwrapping reduce, which is guaranteed nonempty since auths.len() == server_ids.len()")?;
        let auth_pt = sum * self.blind.invert();
        // auth_pt should now equal the original auth_pt, which is hash_pt(input) * k_oprf.
        // Why?  Here's why:
        //   - We passed
        //       P = hash_pt(input) * b
        //     to servers
        //   - Servers computed
        //       H = hash_pt(user_id)
        //     where user_id is the same across all servers, so H is the same across them too
        //   - Servers returned
        //       P * k_i + H * z_i
        //   - We computed
        //       SUM = sum(P * k_i + H * z_i)
        //           = P * sum(k_i) + H * sum(z_i)
        //           = P * k_oprf + H * 0
        //           = P * k_oprf
        //           = hash_pt(input) * b * k_oprf
        //           = hash_pt(input) * k_oprf * b
        //           = auth_pt * b
        //   - We then divided out `b` by multiplying by `1/b`, to get the original auth_pt

        // Now, we use auth_pt to recompute auth commitments, which we send
        // back to the server, proving we have the correct value for `input`.
        let auth_commitments = auth_commitments(self.server_ids, &self.input, &auth_pt);
        let rand = random_scalar(rng);
        let proof_pt_bytes = (RISTRETTO_BASEPOINT_TABLE * &rand).compress().to_bytes();
        let blinded_pt_bytes = (input_hash_pt(&self.input) * self.blind)
            .compress()
            .to_bytes();

        Ok(Restore2 {
            requests: auth_commitments
                .iter()
                .zip(handshake_hashes)
                .map(|((sk, _pk), handshake_hash)| {
                    let hash = {
                        let mut sha512 = Sha512::new();
                        sha512.update(proof_pt_bytes.as_slice());
                        sha512.update(blinded_pt_bytes.as_slice());
                        sha512.update(handshake_hash);
                        sha512
                    };
                    let proof_scalar_base = Scalar::from_hash(hash);
                    sk * proof_scalar_base + rand
                })
                .map(|proof_scalar| svrb::Request4 {
                    inner: Some(svrb::request4::Inner::Restore2(svrb::request4::Restore2 {
                        auth_point: proof_pt_bytes.to_vec(),
                        auth_scalar: proof_scalar.as_bytes().to_vec(),
                        version,
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .map(|rr| rr.write_to_bytes().expect("serialization succeeds"))
                .collect(),
            server_ids: self.server_ids,
            input: self.input,
            auth_pt,
            tries_remaining: tries_remaining
                .expect("all responses had to be OK, so we should have this"),
        })
    }

    /// Given a set of responses, each of which have some number of Auths,
    /// return a version that is available in all responses, if such a
    /// one exists.
    fn version_to_use(&self, responses1: &[svrb::response4::Restore1]) -> Option<u32> {
        let mut versions = BTreeMap::new();
        for r1 in responses1 {
            for auth in &r1.auth {
                versions
                    .entry(auth.version)
                    .and_modify(|x| *x += 1)
                    .or_insert(1usize);
            }
        }
        versions
            .iter()
            .find(|(_v, count)| **count == self.server_ids.len())
            .map(|(v, _count)| *v)
    }

    /// Return a set of Auths, one from each response, that all have the
    /// given version, or an Error::BadResponse if they're not found.
    fn auths_with_version<'b>(
        &self,
        version: u32,
        responses1: &'b [svrb::response4::Restore1],
    ) -> Result<Vec<&'b svrb::response4::restore1::Auth>, Error> {
        let mut out = Vec::with_capacity(responses1.len());
        for r1 in responses1 {
            for auth in &r1.auth {
                if auth.version == version {
                    out.push(auth);
                    // The fact that the version was returned by `version_to_use` does
                    // NOT guarantee that this function will return success.  `version_to_use`
                    // will count multiple auths with the same version in a single response
                    // (which should never happen in practice, but is important to check for),
                    // while this function will check for that error condition due to this
                    // break statement:
                    break;
                }
            }
        }
        if out.len() != responses1.len() {
            Err(Error::NoUsableVersion)
        } else {
            Ok(out)
        }
    }
}

impl Restore2<'_> {
    pub fn restore(self, responses2_bytes: &[Vec<u8>]) -> Result<Secret, Error> {
        if responses2_bytes.len() != self.server_ids.len() {
            return Err(Error::NumServers {
                servers: self.server_ids.len(),
                got: responses2_bytes.len(),
            });
        }
        let responses2 = responses2_bytes
            .iter()
            .map(|b| svrb::Response4::parse_from_bytes(b.as_ref()).map_err(|_| Error::BadResponse))
            .map(|rr| match rr?.inner {
                Some(svrb::response4::Inner::Restore2(r)) => Ok(r),
                _ => Err(Error::BadResponse),
            })
            .collect::<Result<Vec<svrb::response4::Restore2>, _>>()?;
        status_errors(&mut responses2.iter().map(|r| r.status))
            .map_err(|_| Error::RestoreFailed(self.tries_remaining))?;

        let mut s_enc = [0u8; 32];
        for resp in responses2.iter() {
            if resp.encryption_secretshare.len() != s_enc.len() {
                return Err(Error::BadResponse);
            }
            arr_xor(&resp.encryption_secretshare, &mut s_enc);
        }
        let k_auth = auth_secret(&self.input, &self.auth_pt);
        Ok(encryption_key(&s_enc, &k_auth))
    }
}

#[cfg(test)]
mod test {
    use const_str::hex;
    use curve25519_dalek::scalar::Scalar;
    use nonzero_ext::nonzero;
    use proptest::proptest;
    use rand::TryRngCore;
    use rand::rngs::OsRng;

    use super::*;

    fn to_ristretto_scalar(b: &[u8]) -> Option<Scalar> {
        Scalar::from_canonical_bytes(b.try_into().ok()?).into_option()
    }

    #[test]
    fn scalars_summing_to_works() {
        proptest!(|(n in 1usize..10)| {
            let mut rng = OsRng.unwrap_err();
            let mut seed = [0u8; 64];
            rng.try_fill_bytes(&mut seed).unwrap();
            let want = Scalar::from_bytes_mod_order_wide(&seed);
            let out = scalars_summing_to(NonZeroUsize::new(n).unwrap(), &want, &mut rng);
            let got: Scalar = out.iter().sum();
            assert_eq!(got, want);
            assert_eq!(out.len(), n);
        });
    }

    #[test]
    fn bytes_xoring_to_works() {
        let want = vec![1u8; 32];
        proptest!(|(n in 1usize..10)|{
            let mut rng = OsRng.unwrap_err();
            let out: Vec<Vec<u8>> =
                bytes_xoring_to(NonZeroUsize::new(n).unwrap(), &want, &mut rng);
            let mut got = vec![0u8; 32];
            for vec in out.iter() {
                for (i, c) in vec.iter().enumerate() {
                    got[i] ^= c;
                }
            }
            assert_eq!(got, want);
            assert_eq!(out.len(), n);
        });
    }

    #[test]
    fn output_to_encryption() {
        assert_eq!(
            encryption_key(&[0u8; 32], &[1u8; 32]),
            hex!("fd8d53d811528ba9510759ec665dacf31b747f5a94a58f4b84f5d5f40458b9e8"),
        );
    }

    /// TestServer implements the server-side for a single-user interaction.
    struct TestServer {
        tries: u32,
        versions: BTreeMap<u32, TestServerVersion>,
        restore1_blinded: Vec<u8>,
    }

    /// TestServerVersion holds a single version's data for a single user.
    struct TestServerVersion {
        auth_commitment: RistrettoPoint,
        oprf_secretshare: Scalar,
        encryption_secretshare: [u8; 32],
        zero_secretshare: Scalar,
    }

    impl TestServerVersion {
        fn new(req: &svrb::request4::Create) -> Self {
            Self {
                auth_commitment: to_ristretto_pt(&req.auth_commitment)
                    .expect("decode auth_commitment"),
                oprf_secretshare: to_ristretto_scalar(&req.oprf_secretshare)
                    .expect("decode oprf_secretshare"),
                zero_secretshare: to_ristretto_scalar(&req.zero_secretshare)
                    .expect("decode zero_secretshare"),
                encryption_secretshare: req
                    .encryption_secretshare
                    .as_slice()
                    .try_into()
                    .expect("decode encryption_secretshare"),
            }
        }
    }

    impl TestServer {
        fn new() -> Self {
            Self {
                tries: 0,
                versions: BTreeMap::new(),
                restore1_blinded: vec![],
            }
        }

        /// Take in create request, return success/failure
        fn create(&mut self, req_bytes: &[u8]) {
            self.versions.clear();
            let req = match svrb::Request4::parse_from_bytes(req_bytes)
                .expect("decode Request4")
                .inner
            {
                Some(svrb::request4::Inner::Create(r)) => r,
                _ => {
                    panic!("not Create");
                }
            };
            self.versions
                .insert(req.version, TestServerVersion::new(&req));
            self.tries = req.max_tries;
        }

        /// Return a constant "hash" of a single user ID.
        fn hashed_user_id(&self) -> [u8; 64] {
            [1u8; 64] // SHA512(user_id)
        }

        /// Take in restore1 request, return restore1 response
        fn restore1(&mut self, req_bytes: &[u8]) -> Vec<u8> {
            let req = match svrb::Request4::parse_from_bytes(req_bytes)
                .expect("decode Request4")
                .inner
            {
                Some(svrb::request4::Inner::Restore1(r)) => r,
                _ => {
                    panic!("not Restore1");
                }
            };
            assert!(self.tries > 0);
            self.tries -= 1;
            self.restore1_blinded = req.blinded.to_vec();

            let userhash_pt = RistrettoPoint::from_uniform_bytes(&self.hashed_user_id());
            let blinded = to_ristretto_pt(&req.blinded).expect("decode blinded");

            let auths = self
                .versions
                .iter()
                .map(|(version, state)| svrb::response4::restore1::Auth {
                    version: *version,
                    element: (blinded * state.oprf_secretshare
                        + userhash_pt * state.zero_secretshare)
                        .compress()
                        .to_bytes()
                        .to_vec(),
                    ..Default::default()
                })
                .collect::<Vec<_>>();

            svrb::Response4 {
                inner: Some(svrb::response4::Inner::Restore1(
                    svrb::response4::Restore1 {
                        status: svrb::response4::Status::OK.into(),
                        tries_remaining: self.tries,
                        auth: auths,
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }
            .write_to_bytes()
            .expect("serialization succeeds")
        }

        /// Take in restore2 request, return restore2 response
        fn restore2(&self, req_bytes: &[u8], handshake_hash: &[u8]) -> Vec<u8> {
            let req = match svrb::Request4::parse_from_bytes(req_bytes)
                .expect("decode Request4")
                .inner
            {
                Some(svrb::request4::Inner::Restore2(r)) => r,
                _ => {
                    panic!("not Restore2");
                }
            };
            let state = self.versions.get(&req.version).expect("version not set");
            let auth_scalar = to_ristretto_scalar(&req.auth_scalar).expect("decode auth_scalar");
            let auth_point = to_ristretto_pt(&req.auth_point).expect("decode auth_pt");

            let scalar_hash_bytes: Vec<u8> = [
                &req.auth_point as &[_],
                &self.restore1_blinded,
                handshake_hash,
            ]
            .concat();
            let scalar_hash = Scalar::hash_from_bytes::<Sha512>(&scalar_hash_bytes);
            let lhs = RISTRETTO_BASEPOINT_TABLE * &auth_scalar;
            let rhs = state.auth_commitment * scalar_hash + auth_point;

            assert_eq!(lhs, rhs);

            svrb::Response4 {
                inner: Some(svrb::response4::Inner::Restore2(
                    svrb::response4::Restore2 {
                        status: svrb::response4::Status::OK.into(),
                        encryption_secretshare: state.encryption_secretshare.to_vec(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }
            .write_to_bytes()
            .expect("serialization succeeds")
        }
    }

    #[test]
    fn full_create_restore() {
        let mut rng = OsRng.unwrap_err();
        let server_ids = vec![1u64, 2u64, 3u64];
        let mut servers = server_ids
            .iter()
            .map(|_| TestServer::new())
            .collect::<Vec<_>>();
        let password = [2u8; 67]; // can be arbitrary length

        // Create a new backup
        let backup = Backup4::new(&server_ids, &password, nonzero!(10u32), &mut rng);
        for (server, req) in servers.iter_mut().zip(backup.requests) {
            server.create(&req);
        }
        let handshake_hashes = [&[1u8; 32][..], &[2u8; 32][..], &[3u8; 32][..]];

        // Restoring existing backup.
        let restore1 = Restore1::new(&server_ids, &password, &mut rng);
        let restore1_responses = servers
            .iter_mut()
            .zip(&restore1.requests)
            .map(|(server, req)| server.restore1(req))
            .collect::<Vec<_>>();
        let restore2 = restore1
            .restore2(&restore1_responses, &handshake_hashes, &mut rng)
            .expect("call requests2");
        let restore2_responses = servers
            .iter_mut()
            .zip(&restore2.requests)
            .zip(&handshake_hashes)
            .map(|((server, req), hh)| server.restore2(req, hh))
            .collect::<Vec<_>>();
        let got = restore2
            .restore(&restore2_responses)
            .expect("call restored");
        assert_eq!(backup.output, got);
    }
}
