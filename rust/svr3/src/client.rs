//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::iter::repeat_with;
use std::num::{NonZeroU32, NonZeroUsize};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use prost::Message;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha512};

use crate::errors::Error;
use crate::proto::svr4;

/// Make a request to remove a record from SVR4.
pub fn make_remove4_request() -> Vec<u8> {
    svr4::Request4 {
        inner: Some(svr4::request4::Inner::Remove(svr4::request4::Remove {})),
    }
    .encode_to_vec()
}

/// Returns a list of `n` scalars which are chosen randomly but
/// which will sum up to `s`.
fn scalars_summing_to<R: CryptoRngCore>(n: NonZeroUsize, s: &Scalar, rng: &mut R) -> Vec<Scalar> {
    let mut v: Vec<Scalar> = repeat_with(|| Scalar::random(rng))
        .take(n.get() - 1)
        .collect();
    let sum: Scalar = v.iter().sum();
    v.push(Scalar::ZERO - sum + s);
    v
}

/// Return a list of `n` byte vectors which are chosen randomly
/// but which will XOR together to `b`.
fn bytes_xoring_to<R: CryptoRngCore>(n: NonZeroUsize, b: &[u8], rng: &mut R) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = repeat_with(|| {
        let mut e = vec![0; b.len()];
        rng.fill_bytes(e.as_mut_slice());
        e
    })
    .take(n.get() - 1)
    .collect();
    let mut xor: Vec<u8> = b.into();
    for vec in v.iter() {
        for (i, c) in vec.iter().enumerate() {
            xor[i] ^= c;
        }
    }
    v.push(xor);
    v
}

/// Key Derivation Function used throughout the rest of this code.
fn kdf(input1: &[u8], input2: &[u8]) -> [u8; 64] {
    // TODO: implement actual KDF
    let mut h = Sha512::new();
    h.update(input1);
    h.update(input2);
    h.finalize().into()
}

/// Return a set of (private, public) auth commitments based on the auth secret.
fn auth_commitments(
    server_ids: &[u64],
    input: &[u8; 64],
    auth_pt: &RistrettoPoint,
) -> Vec<(Scalar, RistrettoPoint)> {
    let k_auth = auth_secret(input, auth_pt);
    server_ids
        .iter()
        .map(|id| kdf(&k_auth, &id.to_be_bytes()))
        .map(|k| Scalar::hash_from_bytes::<Sha512>(&k))
        .map(|s| (s, RISTRETTO_BASEPOINT_TABLE * &s))
        .collect()
}

/// Returns the Ristretto point used for authentication.
fn auth_pt(input: &[u8; 64], k_oprf: &Scalar) -> RistrettoPoint {
    input_hash_pt(input) * k_oprf
}

/// Returns the secret used for authentication.
fn auth_secret(input: &[u8; 64], auth_pt: &RistrettoPoint) -> [u8; 64] {
    kdf(input, &auth_pt.compress().to_bytes())
}

/// Return a RistrettoPoint created from our input.
fn input_hash_pt(input: &[u8; 64]) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(input)
}

fn to_ristretto_pt(b: &[u8]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(b).ok()?.decompress()
}

pub struct Backup4 {
    pub requests: Vec<Vec<u8>>,
    pub output: Output4,
}

impl Backup4 {
    pub fn new<R: CryptoRngCore>(
        server_ids: &[u64],
        input: [u8; 64],
        max_tries: NonZeroU32,
        rng: &mut R,
    ) -> Result<Self, Error> {
        assert!(!server_ids.is_empty());
        let k_oprf = Scalar::random(rng);

        let mut s_enc = [0u8; 32];
        rng.fill_bytes(&mut s_enc);

        let n = NonZeroUsize::new(server_ids.len())
            .expect("server IDs nonempty as asserted in constructor");
        let oprf_keyshares = scalars_summing_to(n, &k_oprf, rng);
        let enc_keyshares = bytes_xoring_to(n, &s_enc, rng);
        let zero_keyshares = scalars_summing_to(n, &Scalar::ZERO, rng);

        let auth_pt = auth_pt(&input, &k_oprf);
        let auth_commitments = auth_commitments(server_ids, &input, &auth_pt);
        let version = rng.next_u64();

        Ok(Self {
            requests: (0usize..server_ids.len())
                .map(|i| svr4::Request4 {
                    inner: Some(svr4::request4::Inner::Create(svr4::request4::Create {
                        version,
                        max_tries: max_tries.get(),
                        oprf_secretshare: oprf_keyshares[i].to_bytes().to_vec(),
                        auth_commitment: auth_commitments[i].1.compress().to_bytes().to_vec(),
                        encryption_secretshare: enc_keyshares[i].clone(),
                        zero_secretshare: zero_keyshares[i].to_bytes().to_vec(),
                    })),
                })
                .map(|cr| cr.encode_to_vec())
                .collect(),
            output: Output4 {
                k_auth: auth_secret(&input, &auth_pt),
                s_enc,
            },
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Output4 {
    k_auth: [u8; 64],
    s_enc: [u8; 32],
}

pub struct Restore1 {
    server_ids: Vec<u64>,
    input: [u8; 64],
    blind: Scalar,
    pub requests: Vec<Vec<u8>>,
}

pub struct Restore2 {
    server_ids: Vec<u64>,
    input: [u8; 64],
    auth_pt: RistrettoPoint,
    tries_remaining: Option<u32>,
    pub requests: Vec<Vec<u8>>,
}

fn status_error<I: Iterator<Item = i32>>(statuses: I) -> Result<(), Error> {
    match statuses
        .map(svr4::response4::Status::try_from)
        .find(|s| !matches!(s, Ok(svr4::response4::Status::Ok)))
    {
        // We found no non-OK status, everything is hunky dory.
        None => Ok(()),
        // We found a valid non-OK status, wrap it in an error.
        Some(Ok(s)) => Err(Error::BadResponseStatus4(s)),
        // We found a status we can't recognize, return a generic BadResponse error.
        _ => Err(Error::BadResponse),
    }
}

impl Restore1 {
    pub fn new<R: CryptoRngCore>(server_ids: &[u64], input: [u8; 64], rng: &mut R) -> Self {
        let blind = Scalar::random(rng);
        Restore1 {
            requests: server_ids
                .iter()
                .map(|_| svr4::Request4 {
                    inner: Some(svr4::request4::Inner::Restore1(svr4::request4::Restore1 {
                        blinded: (input_hash_pt(&input) * blind)
                            .compress()
                            .to_bytes()
                            .to_vec(),
                    })),
                })
                .map(|rr| rr.encode_to_vec())
                .collect(),
            server_ids: server_ids.to_vec(),
            blind,
            input,
        }
    }

    pub fn restore2<R: CryptoRngCore>(
        self,
        responses1_bytes: &[Vec<u8>],
        rng: &mut R,
    ) -> Result<Restore2, Error> {
        if responses1_bytes.len() != self.server_ids.len() {
            return Err(Error::NumServers {
                servers: self.server_ids.len(),
                got: responses1_bytes.len(),
            });
        }
        let responses1 = responses1_bytes
            .iter()
            .map(|b| svr4::Response4::decode(b.as_ref()).map_err(|_| Error::BadResponse))
            .map(|rr| match rr?.inner {
                Some(svr4::response4::Inner::Restore1(r)) => Ok(r),
                _ => Err(Error::BadResponse),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let tries_remaining = responses1
            .iter()
            .filter(|rr| {
                matches!(
                    rr.status(),
                    // These errors will decrement #tries, others will not.
                    // We only care about returning #tries_remaining in a case
                    // where it's decremented.
                    svr4::response4::Status::Ok | svr4::response4::Status::Error
                )
            })
            .map(|rr| rr.tries_remaining)
            .min();
        status_error(responses1.iter().map(|r| r.status)).map_err(|e| match tries_remaining {
            Some(tr) => Error::RestoreFailed(tr),
            None => e,
        })?;

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
        let auth_commitments = auth_commitments(&self.server_ids, &self.input, &auth_pt);
        let rand = Scalar::random(rng);
        let proof_pt_bytes = (RISTRETTO_BASEPOINT_TABLE * &rand).compress().to_bytes();
        let proof_scalar_base = Scalar::hash_from_bytes::<Sha512>(&proof_pt_bytes);

        Ok(Restore2 {
            requests: auth_commitments
                .iter()
                .map(|(sk, _pk)| sk * proof_scalar_base + rand)
                .map(|proof_scalar| svr4::Request4 {
                    inner: Some(svr4::request4::Inner::Restore2(svr4::request4::Restore2 {
                        auth_point: proof_pt_bytes.to_vec(),
                        auth_scalar: proof_scalar.as_bytes().to_vec(),
                        version,
                    })),
                })
                .map(|rr| rr.encode_to_vec())
                .collect(),
            server_ids: self.server_ids,
            input: self.input,
            auth_pt,
            tries_remaining,
        })
    }

    /// Given a set of responses, each of which have some number of Auths,
    /// return a version that is available in all responses, if such a
    /// one exists.
    fn version_to_use(&self, responses1: &[svr4::response4::Restore1]) -> Option<u64> {
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
    fn auths_with_version<'a>(
        &self,
        version: u64,
        responses1: &'a [svr4::response4::Restore1],
    ) -> Result<Vec<&'a svr4::response4::restore1::Auth>, Error> {
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

impl Restore2 {
    pub fn restore(self, responses2_bytes: &[Vec<u8>]) -> Result<Output4, Error> {
        if responses2_bytes.len() != self.server_ids.len() {
            return Err(Error::NumServers {
                servers: self.server_ids.len(),
                got: responses2_bytes.len(),
            });
        }
        let responses2 = responses2_bytes
            .iter()
            .map(|b| svr4::Response4::decode(b.as_ref()).map_err(|_| Error::BadResponse))
            .map(|rr| match rr?.inner {
                Some(svr4::response4::Inner::Restore2(r)) => Ok(r),
                _ => Err(Error::BadResponse),
            })
            .collect::<Result<Vec<svr4::response4::Restore2>, _>>()?;
        status_error(responses2.iter().map(|r| r.status)).map_err(|e| {
            match self.tries_remaining {
                Some(tr) => Error::RestoreFailed(tr),
                None => e,
            }
        })?;

        let mut s_enc = [0u8; 32];
        for resp in responses2.iter() {
            if resp.encryption_secretshare.len() != s_enc.len() {
                return Err(Error::BadResponse);
            }
            for (i, c) in resp.encryption_secretshare.iter().enumerate() {
                s_enc[i] ^= c;
            }
        }
        Ok(Output4 {
            s_enc,
            k_auth: auth_secret(&self.input, &self.auth_pt),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use nonzero_ext::nonzero;
    use proptest::proptest;
    use rand_core::OsRng;

    fn to_ristretto_scalar(b: &[u8]) -> Option<Scalar> {
        Scalar::from_canonical_bytes(b.try_into().ok()?).into_option()
    }

    #[test]
    fn scalars_summing_to_works() {
        proptest!(|(n in 1usize..10)| {
            let mut rng = OsRng;
            let want = Scalar::random(&mut rng);
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
            let mut rng = OsRng;
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

    /// TestServer implements the server-side for a single-user interaction.
    struct TestServer {
        tries: u32,
        versions: BTreeMap<u64, TestServerVersion>,
    }

    /// TestServerVersion holds a single version's data for a single user.
    struct TestServerVersion {
        auth_commitment: RistrettoPoint,
        oprf_secretshare: Scalar,
        encryption_secretshare: [u8; 32],
        zero_secretshare: Scalar,
    }

    impl TestServerVersion {
        fn new(req: &svr4::request4::Create) -> Self {
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
            }
        }

        /// Take in create request, return success/failure
        fn create(&mut self, req_bytes: &[u8]) {
            self.versions.clear();
            let req = match svr4::Request4::decode(req_bytes)
                .expect("decode Request4")
                .inner
            {
                Some(svr4::request4::Inner::Create(r)) => r,
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
            let req = match svr4::Request4::decode(req_bytes)
                .expect("decode Request4")
                .inner
            {
                Some(svr4::request4::Inner::Restore1(r)) => r,
                _ => {
                    panic!("not Restore1");
                }
            };
            assert!(self.tries > 0);
            self.tries -= 1;

            let userhash_pt = RistrettoPoint::from_uniform_bytes(&self.hashed_user_id());
            let blinded = to_ristretto_pt(&req.blinded).expect("decode blinded");

            let auths = self
                .versions
                .iter()
                .map(|(version, state)| svr4::response4::restore1::Auth {
                    version: *version,
                    element: (blinded * state.oprf_secretshare
                        + userhash_pt * state.zero_secretshare)
                        .compress()
                        .to_bytes()
                        .to_vec(),
                })
                .collect::<Vec<_>>();

            svr4::Response4 {
                inner: Some(svr4::response4::Inner::Restore1(
                    svr4::response4::Restore1 {
                        status: svr4::response4::Status::Ok.into(),
                        tries_remaining: self.tries,
                        auth: auths,
                    },
                )),
            }
            .encode_to_vec()
        }

        /// Take in restore2 request, return restore2 response
        fn restore2(&self, req_bytes: &[u8]) -> Vec<u8> {
            let req = match svr4::Request4::decode(req_bytes)
                .expect("decode Request4")
                .inner
            {
                Some(svr4::request4::Inner::Restore2(r)) => r,
                _ => {
                    panic!("not Restore2");
                }
            };
            let state = self.versions.get(&req.version).expect("version not set");
            let auth_scalar = to_ristretto_scalar(&req.auth_scalar).expect("decode auth_scalar");
            let auth_point = to_ristretto_pt(&req.auth_point).expect("decode auth_pt");

            let scalar_hash = Scalar::hash_from_bytes::<Sha512>(&req.auth_point);
            let lhs = RISTRETTO_BASEPOINT_TABLE * &auth_scalar;
            let rhs = state.auth_commitment * scalar_hash + auth_point;

            assert_eq!(lhs, rhs);

            svr4::Response4 {
                inner: Some(svr4::response4::Inner::Restore2(
                    svr4::response4::Restore2 {
                        status: svr4::response4::Status::Ok.into(),
                        encryption_secretshare: state.encryption_secretshare.to_vec(),
                    },
                )),
            }
            .encode_to_vec()
        }
    }

    #[test]
    fn full_create_restore() {
        let mut rng = OsRng;
        let server_ids = vec![1u64, 2u64, 3u64];
        let mut servers = server_ids
            .iter()
            .map(|_| TestServer::new())
            .collect::<Vec<_>>();
        let input = [2u8; 64];

        // Create a new backup
        let backup =
            Backup4::new(&server_ids, input, nonzero!(10u32), &mut rng).expect("create Backup4");
        for (server, req) in servers.iter_mut().zip(backup.requests) {
            server.create(&req);
        }

        // Restoring existing backup.
        let restore1 = Restore1::new(&server_ids, input, &mut rng);
        let restore1_responses = servers
            .iter_mut()
            .zip(&restore1.requests)
            .map(|(server, req)| server.restore1(req))
            .collect::<Vec<_>>();
        let restore2 = restore1
            .restore2(&restore1_responses, &mut rng)
            .expect("call requests2");
        let restore2_responses = servers
            .iter_mut()
            .zip(&restore2.requests)
            .map(|(server, req)| server.restore2(req))
            .collect::<Vec<_>>();
        let got = restore2
            .restore(&restore2_responses)
            .expect("call restored");
        assert_eq!(backup.output, got);
    }
}
