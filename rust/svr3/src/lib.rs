//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::collections::BTreeMap;
use std::io::Write;
use std::iter::repeat_with;
use std::num::{NonZeroU32, NonZeroUsize};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use prost::Message;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256, Sha512};
use signal_crypto::{Aes256GcmDecryption, Aes256GcmEncryption};

use crate::proto::svr4;

mod errors;
pub use errors::{Error, ErrorStatus};
mod proto;
pub use proto::svr4::response4::Status as V4Status;

const SECRET_BYTES: usize = 32;

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
            svr4::Request4 {
                inner: Some(svr4::request4::Inner::Query(svr4::request4::Query {})),
            }
            .encode_to_vec(),
        )
    }

    pub fn finalize(responses: &[Vec<u8>]) -> Result<u32, Error> {
        assert!(!responses.is_empty());
        responses
            .iter()
            .map(|b| svr4::Response4::decode(b.as_ref()).map_err(|_| Error::BadData))
            .map(|rr| match rr?.inner {
                Some(svr4::response4::Inner::Query(r)) => match status_error(r.status) {
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
            svr4::Request4 {
                inner: Some(svr4::request4::Inner::Remove(svr4::request4::Remove {})),
            }
            .encode_to_vec(),
        )
    }
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
    pub output: Output4,
    pub masked_secret: MaskedSecret,
}

/// Contains everything necessary to restore a secret given a password.
pub struct MaskedSecret {
    pub server_ids: Vec<u64>,
    pub masked_secret: Vec<u8>,
}

impl Backup4 {
    pub fn new<R: CryptoRngCore>(
        server_ids: &[u64],
        password: &[u8],
        secret: &[u8; 32],
        max_tries: NonZeroU32,
        rng: &mut R,
    ) -> Result<Self, Error> {
        assert!(!server_ids.is_empty());
        let input = password_to_uniform_input(password);
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
        let version = rng.next_u32();
        let output = Output4 {
            k_auth: auth_secret(&input, &auth_pt),
            s_enc,
        };

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
            masked_secret: MaskedSecret {
                server_ids: server_ids.to_vec(),
                masked_secret: output.mask_secret(secret, rng),
            },
            output,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Output4 {
    k_auth: [u8; 32],
    s_enc: [u8; 32],
}

impl Output4 {
    pub fn encryption_key(&self) -> [u8; 32] {
        Kdf::make(
            b"Signal_SVR_EncryptionKey_20240823",
            &self.s_enc,
            &self.k_auth,
        )
    }
    pub fn mask_secret<R: CryptoRngCore>(&self, secret: &[u8; 32], rng: &mut R) -> Vec<u8> {
        let mut masked_secret = vec![
                0u8;
                // masked_secret will be:  NONCE || ENCRYPTED_SECRET || TAG
                Aes256GcmEncryption::NONCE_SIZE + secret.len() + Aes256GcmEncryption::TAG_SIZE
            ];
        let nonce = {
            let nonce = &mut masked_secret[..Aes256GcmEncryption::NONCE_SIZE];
            rng.fill_bytes(nonce);
            nonce
        };
        let mut enc = Aes256GcmEncryption::new(&self.encryption_key(), nonce, b"")
            .expect("key and nonce should be valid");
        {
            let encrypted_secret =
                &mut masked_secret[Aes256GcmEncryption::NONCE_SIZE..][..secret.len()];
            encrypted_secret.copy_from_slice(secret);
            enc.encrypt(encrypted_secret);
        }
        let tag = &mut masked_secret[Aes256GcmEncryption::NONCE_SIZE + secret.len()..];
        tag.copy_from_slice(&enc.compute_tag());
        masked_secret
    }
    pub fn unmask_secret(&self, masked_secret: &[u8]) -> Result<[u8; 32], Error> {
        let mut secret = [0u8; 32];
        if masked_secret.len()
            != Aes256GcmDecryption::NONCE_SIZE + secret.len() + Aes256GcmDecryption::TAG_SIZE
        {
            return Err(Error::BadData);
        }
        let (nonce, encrypted_secret, tag) = (
            &masked_secret[..Aes256GcmDecryption::NONCE_SIZE],
            &masked_secret
                [Aes256GcmDecryption::NONCE_SIZE..Aes256GcmDecryption::NONCE_SIZE + secret.len()],
            &masked_secret[Aes256GcmDecryption::NONCE_SIZE + secret.len()..],
        );
        secret.copy_from_slice(encrypted_secret);
        let mut dec = Aes256GcmDecryption::new(&self.encryption_key(), nonce, b"")
            .expect("key and nonce shoould be valid");
        dec.decrypt(&mut secret);
        dec.verify_tag(tag).map_err(|_| Error::BadData)?;
        Ok(secret)
    }
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

fn status_error(s: i32) -> Result<(), Error> {
    match svr4::response4::Status::try_from(s) {
        Ok(svr4::response4::Status::Ok) => Ok(()),
        Ok(s) => Err(Error::BadResponseStatus4(s)),
        Err(_) => Err(Error::BadResponse),
    }
}

fn status_errors<I: Iterator<Item = i32>>(statuses: &mut I) -> Result<(), Error> {
    statuses.try_for_each(status_error)
}

impl<'a> Restore1<'a> {
    pub fn new<R: CryptoRngCore>(server_ids: &'a [u64], password: &[u8], rng: &mut R) -> Self {
        let blind = Scalar::random(rng);
        let input = password_to_uniform_input(password);
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
            server_ids,
            blind,
            input,
        }
    }

    pub fn restore2<R: CryptoRngCore>(
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
        let rand = Scalar::random(rng);
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
            tries_remaining: tries_remaining
                .expect("all responses had to be OK, so we should have this"),
        })
    }

    /// Given a set of responses, each of which have some number of Auths,
    /// return a version that is available in all responses, if such a
    /// one exists.
    fn version_to_use(&self, responses1: &[svr4::response4::Restore1]) -> Option<u32> {
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
        responses1: &'b [svr4::response4::Restore1],
    ) -> Result<Vec<&'b svr4::response4::restore1::Auth>, Error> {
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
        status_errors(&mut responses2.iter().map(|r| r.status))
            .map_err(|_| Error::RestoreFailed(self.tries_remaining))?;

        let mut s_enc = [0u8; 32];
        for resp in responses2.iter() {
            if resp.encryption_secretshare.len() != s_enc.len() {
                return Err(Error::BadResponse);
            }
            arr_xor(&resp.encryption_secretshare, &mut s_enc);
        }
        Ok(Output4 {
            s_enc,
            k_auth: auth_secret(&self.input, &self.auth_pt),
        })
    }
}

enum RotationAction {
    DoNothing,
    Commit(u32),
    Rollback(u32),
}

pub const MAX_ROTATION_STEPS: usize = 4;

/// RotationMachineState defines a simple state machine for performing
/// a client-initiated rotation.  Clients start in the InitialQuery state
/// and attempt to achieve the Done state.  The following are the
/// "happy path" state transitions, assuming no errors.  There is also
/// an implied possible state transition from any state to the Done state
/// should an error be encountered.
///    ┌────────────┐        ┌───────────┐
///  ─►│InitialQuery│───────►│FixPrevious│
///    └───┬────────┘        └─────┬─────┘
///        │                       │
///        │     ┌───────────┐     │
///        └────►│RotateStart│◄────┘
///              └──┬────────┘
///                 ▼
///              ┌────────────┐
///              │RotateCommit│
///              └──┬─────────┘
///                 ▼
///              ┌────┐
///              │Done│
///              └────┘
/// State transitions occur on the RotationMachine's `handle_responses`
/// call, which receives responses from servers and determines what to
/// do next.
enum RotationMachineState {
    /// Perform an initial `Query` call on all servers, to see if any
    /// are in a partial state due to a previous key rotation attempt.
    /// Assume that a previous rotation from version 1->2 has been
    /// attempted, with two backends.  We could be in any of the following
    /// states:
    ///
    ///   a) backendA { curr=1 new=2 }  backendB { curr=1 }       // rotation attempted on A, failed before starting B
    ///   b) backendA { curr=1 new=2 }  backendB { curr=1 new=2 } // rotation started on A and B, but never rolled forward
    ///   c) backendA { curr=2 }        backendB { curr=1 new=2 } // rotation started on A and B, committed on A
    ///   d) backendA { curr=2 }        backendB { curr=2 }       // rotation committed on A and B
    ///
    /// Note: no ordering of backends or their responses is implied or required.
    ///
    /// In state (a), the correct action is to roll back backendA, since
    /// backendB does not have the version 2 data and thus cannot be
    /// rolled forwards.  In cases (b, c), all backends
    /// have the newer version 2 data, and should be rolled forwards
    /// with Commit calls.  In case (d), all backends have a singular
    /// version, so no fixes are required and we can immediately attempt
    /// to RotateStart.
    InitialQuery,
    /// Perform the necessary fix actions determined by InitialQuery,
    /// some combination of DoNothing, Commit, and Rollback.  For servers
    /// that don't need anything done, we send a Query just so we have
    /// something to send them.
    FixPrevious(Vec<RotationAction>),
    /// Start our actual rotation, using the stored new (random) version
    /// number.  This creates new key deltas for OPRF and Encryption keys
    /// and provides them to the backing servers.
    RotateStart(u32),
    /// Commit the version we created with RotateStart, rolling all backends
    /// forward to the new version. If this succeeds, all servers will be
    /// at the new version.
    RotateCommit(u32),
    /// There's nothing more to do, either because we hit an unrecoverable
    /// error or because we've completed successfully.
    Done,
}

/// RotationMachine is a simple state machine that attempts to perform
/// a client-initiated key rotation on the underlying SVR servers.
/// See the RotationMachineState documentation for more details.
///
/// Usage:
///   let servers = ...;
///   let mut machine = RotationMachine::new(servers.ids(), ...);
///   while !machine.is_done() {
///     let requests = machine.requests();
///     let responses = servers.send(requests).await_responses();
///     machine.handle_responses(responses)?;
///   }
///
/// Important:  The order of request and response vectors matter: if
/// `server.ids()[1]` is X, then `requests[1]` is meant for server X
/// and `responses[1]` should be the response received from X.
pub struct RotationMachine<'a> {
    pub server_ids: &'a [u64],
    rng: &'a mut (dyn CryptoRngCore + Send),
    state: RotationMachineState,
}

impl<'a> RotationMachine<'a> {
    pub fn new<R: CryptoRngCore + Send>(server_ids: &'a [u64], rng: &'a mut R) -> Self {
        Self {
            server_ids,
            rng,
            state: RotationMachineState::InitialQuery,
        }
    }

    /// Returns true when the state machine is done and no more requests should be sent.
    pub fn is_done(&self) -> bool {
        matches!(self.state, RotationMachineState::Done)
    }

    /// Returns the next set of requests to send to servers.
    pub fn requests(&mut self) -> Vec<Vec<u8>> {
        match &self.state {
            RotationMachineState::InitialQuery => self.initial_query_requests(),
            RotationMachineState::FixPrevious(actions) => self.fix_previous_requests(actions),
            RotationMachineState::RotateStart(version) => self.rotate_start_requests(*version),
            RotationMachineState::RotateCommit(version) => self.rotate_commit_requests(*version),
            RotationMachineState::Done => {
                panic!("requests should not be called when done");
            }
        }
    }

    fn initial_query_requests(&mut self) -> Vec<Vec<u8>> {
        self.server_ids
            .iter()
            .map(|_| svr4::Request4 {
                inner: Some(svr4::request4::Inner::Query(svr4::request4::Query {})),
            })
            .map(|rr| rr.encode_to_vec())
            .collect::<Vec<_>>()
    }

    fn fix_previous_requests(&self, actions: &[RotationAction]) -> Vec<Vec<u8>> {
        assert!(actions.len() == self.server_ids.len());
        actions
            .iter()
            .map(|a| svr4::Request4 {
                inner: match a {
                    RotationAction::DoNothing => {
                        Some(svr4::request4::Inner::Query(svr4::request4::Query {}))
                    }
                    RotationAction::Rollback(version) => {
                        Some(svr4::request4::Inner::RotateRollback(
                            svr4::request4::RotateRollback { version: *version },
                        ))
                    }
                    RotationAction::Commit(version) => Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit { version: *version },
                    )),
                },
            })
            .map(|rr| rr.encode_to_vec())
            .collect::<Vec<_>>()
    }

    fn rotate_start_requests(&mut self, version: u32) -> Vec<Vec<u8>> {
        let n = NonZeroUsize::new(self.server_ids.len()).unwrap();
        let oprf_secretshares = scalars_summing_to(n, &Scalar::ZERO, &mut self.rng);
        let mut encryption_secretshares = bytes_xoring_to(n, &[0u8; 32], &mut self.rng);
        encryption_secretshares
            .drain(..)
            .enumerate()
            .map(|(i, enc_share)| svr4::Request4 {
                inner: Some(svr4::request4::Inner::RotateStart(
                    svr4::request4::RotateStart {
                        version,
                        oprf_secretshare_delta: oprf_secretshares[i].to_bytes().to_vec(),
                        encryption_secretshare_delta: enc_share,
                    },
                )),
            })
            .map(|rr| rr.encode_to_vec())
            .collect::<Vec<_>>()
    }

    fn rotate_commit_requests(&self, version: u32) -> Vec<Vec<u8>> {
        self.server_ids
            .iter()
            .map(|_| svr4::Request4 {
                inner: Some(svr4::request4::Inner::RotateCommit(
                    svr4::request4::RotateCommit { version },
                )),
            })
            .map(|rr| rr.encode_to_vec())
            .collect::<Vec<_>>()
    }

    /// Called with the responses received from passing `requests()` to servers.
    /// Will update state internally.  Any error will update state to `Done`.
    pub fn handle_responses(&mut self, responses: &[Vec<u8>]) -> Result<(), Error> {
        if responses.len() != self.server_ids.len() {
            return Err(Error::BadData);
        }
        let out = match self.state {
            RotationMachineState::InitialQuery => self.initial_query_responses(responses),
            RotationMachineState::FixPrevious(_) => self.fix_previous_responses(responses),
            RotationMachineState::RotateStart(version) => {
                self.rotate_start_responses(responses, version)
            }
            RotationMachineState::RotateCommit(_) => self.rotate_commit_responses(responses),
            RotationMachineState::Done => {
                panic!("responses() called when state is done");
            }
        };
        if out.is_err() {
            // If we encountered an error, we're kaput.
            self.state = RotationMachineState::Done;
        }
        out
    }

    fn initial_query_responses(&mut self, responses: &[Vec<u8>]) -> Result<(), Error> {
        let resps = responses
            .iter()
            .map(|b| svr4::Response4::decode(b.as_ref()).map_err(|_| Error::BadData))
            .map(|rr| match rr?.inner {
                Some(svr4::response4::Inner::Query(r)) => match status_error(r.status) {
                    Ok(()) => Ok(r),
                    Err(e) => Err(e),
                },
                _ => Err(Error::BadData),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let first = resps[0];
        // Utility function to check that a version is in all responses.
        let version_in_all_responses = |v: u32| -> bool {
            resps
                .iter()
                .filter(|r| r.version == v || r.new_version == v)
                .count()
                == resps.len()
        };
        // Find a version that's common across all responses.  We prefer
        // a newer version than an old one, and we rely on the fact that
        // if a version exists in ALL responses, it must exist in the FIRST
        // response, so we can just check first.new_version, then first.version.
        let canonical_version =
            if first.new_version != 0 && version_in_all_responses(first.new_version) {
                first.new_version
            } else if version_in_all_responses(first.version) {
                first.version
            } else {
                return Err(Error::BadData);
            };
        // See what we need to do to make this version canonical
        // everywhere:
        let mut action_required = false;
        let actions = resps
            .iter()
            .map(|r| {
                if r.new_version == canonical_version {
                    action_required = true;
                    RotationAction::Commit(canonical_version)
                } else if r.new_version != 0 {
                    action_required = true;
                    RotationAction::Rollback(r.new_version)
                } else {
                    RotationAction::DoNothing
                }
            })
            .collect::<Vec<_>>();
        if action_required {
            self.state = RotationMachineState::FixPrevious(actions);
        } else {
            self.state = RotationMachineState::RotateStart(self.rng.next_u32());
        }
        Ok(())
    }

    fn fix_previous_responses(&mut self, responses: &[Vec<u8>]) -> Result<(), Error> {
        responses
            .iter()
            .map(|b| svr4::Response4::decode(b.as_ref()).map_err(|_| Error::BadData))
            .try_for_each(|rr| match rr?.inner {
                Some(svr4::response4::Inner::Query(r)) => status_error(r.status),
                Some(svr4::response4::Inner::RotateCommit(r)) => status_error(r.status),
                Some(svr4::response4::Inner::RotateRollback(r)) => status_error(r.status),
                _ => Err(Error::BadResponse),
            })?;
        self.state = RotationMachineState::RotateStart(self.rng.next_u32());
        Ok(())
    }

    fn rotate_start_responses(&mut self, responses: &[Vec<u8>], version: u32) -> Result<(), Error> {
        let _resps = responses
            .iter()
            .map(|b| svr4::Response4::decode(b.as_ref()).map_err(|_| Error::BadData))
            .map(|rr| match rr?.inner {
                Some(svr4::response4::Inner::RotateStart(r)) => match status_error(r.status) {
                    Ok(()) => Ok(r),
                    Err(e) => Err(e),
                },
                _ => Err(Error::BadData),
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert!(version != 0);
        self.state = RotationMachineState::RotateCommit(version);
        Ok(())
    }

    fn rotate_commit_responses(&mut self, responses: &[Vec<u8>]) -> Result<(), Error> {
        responses
            .iter()
            .map(|b| svr4::Response4::decode(b.as_ref()).map_err(|_| Error::BadData))
            .try_for_each(|rr| match rr?.inner {
                Some(svr4::response4::Inner::RotateCommit(r)) => status_error(r.status),
                _ => Err(Error::BadResponse),
            })?;
        self.state = RotationMachineState::Done;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::scalar::Scalar;
    use hex_literal::hex;
    use nonzero_ext::nonzero;
    use proptest::proptest;
    use rand_core::{CryptoRng, OsRng, RngCore};
    use test_case::test_case;

    use super::*;

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

    #[test]
    fn output_to_encryption() {
        let o = Output4 {
            s_enc: [0u8; 32],
            k_auth: [0u8; 32],
        };
        assert_eq!(
            o.encryption_key(),
            hex!("f609185c9b5bba163a2a413ae11fd5ce6932f5ab7c47b5c0915579568741657b"),
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
                restore1_blinded: vec![],
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
            self.restore1_blinded = req.blinded.to_vec();

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
        fn restore2(&self, req_bytes: &[u8], handshake_hash: &[u8]) -> Vec<u8> {
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
        let password = [2u8; 67]; // can be arbitrary length

        // Create a new backup
        let secret = [3u8; 32];
        let backup = Backup4::new(&server_ids, &password, &secret, nonzero!(10u32), &mut rng)
            .expect("create Backup4");
        for (server, req) in servers.iter_mut().zip(backup.requests) {
            server.create(&req);
        }
        let masked_secret = backup.masked_secret;
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
        assert_eq!(
            secret,
            backup
                .output
                .unmask_secret(&masked_secret.masked_secret)
                .expect("unmask")
        );
    }

    /// Deterministic RNG for testing
    struct IncrementingRng {
        v: u64,
    }

    impl CryptoRng for IncrementingRng {}
    impl RngCore for IncrementingRng {
        #[allow(clippy::cast_possible_truncation)]
        fn next_u32(&mut self) -> u32 {
            self.v += 1;
            self.v as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.v += 1;
            self.v
        }
        #[allow(clippy::cast_possible_truncation)]
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for d in dest.iter_mut() {
                self.v += 1;
                *d = self.v as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[test_case(
        vec![
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 111,
                            new_version: 0,
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 111,
                            new_version: 0,
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateStart(
                        svr4::request4::RotateStart{
                            version: 1,
                            oprf_secretshare_delta: vec![43u8, 45, 186, 46, 151, 152, 176, 15, 92, 27, 218, 124, 96, 244, 158, 211, 155, 38, 174, 109, 24, 63, 216, 33, 6, 216, 75, 18, 75, 181, 36, 0],
                            encryption_secretshare_delta: vec![66u8, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97],
                        })),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateStart(
                        svr4::request4::RotateStart{
                          version: 1,
                          oprf_secretshare_delta: vec![194u8, 166, 59, 46, 131, 202, 97, 72, 122, 129, 29, 38, 126, 5, 64, 65, 100, 217, 81, 146, 231, 192, 39, 222, 249, 39, 180, 237, 180, 74, 219, 15],
                          encryption_secretshare_delta: vec![66u8, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97],
                        })),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateStart(svr4::response4::RotateStart{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateStart(svr4::response4::RotateStart{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{
                            version: 1,
                        })),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{
                          version: 1,
                        })),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
        ], Ok(()); "when the initial state is immediately ready for rotation"
    )]
    #[test_case(
        vec![
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 333,
                            new_version: 111,
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 111,
                            new_version: 222,
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{version: 111})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateRollback(
                        svr4::request4::RotateRollback{version: 222})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateRollback(svr4::response4::RotateRollback{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateStart(
                        svr4::request4::RotateStart{
                            version: 1,
                            oprf_secretshare_delta: vec![43u8, 45, 186, 46, 151, 152, 176, 15, 92, 27, 218, 124, 96, 244, 158, 211, 155, 38, 174, 109, 24, 63, 216, 33, 6, 216, 75, 18, 75, 181, 36, 0],
                            encryption_secretshare_delta: vec![66u8, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97],
                        })),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateStart(
                        svr4::request4::RotateStart{
                          version: 1,
                          oprf_secretshare_delta: vec![194u8, 166, 59, 46, 131, 202, 97, 72, 122, 129, 29, 38, 126, 5, 64, 65, 100, 217, 81, 146, 231, 192, 39, 222, 249, 39, 180, 237, 180, 74, 219, 15],
                          encryption_secretshare_delta: vec![66u8, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97],
                        })),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateStart(svr4::response4::RotateStart{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateStart(svr4::response4::RotateStart{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{
                            version: 1,
                        })),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{
                          version: 1,
                        })),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
        ], Ok(()); "when we need to fix the current state before starting our own rotation"
    )]
    #[test_case(
        vec![
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 333,
                            new_version: 111,
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 333,
                            new_version: 111,
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{version: 111})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{version: 111})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateRollback(svr4::response4::RotateRollback{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateStart(
                        svr4::request4::RotateStart{
                            version: 1,
                            oprf_secretshare_delta: vec![43u8, 45, 186, 46, 151, 152, 176, 15, 92, 27, 218, 124, 96, 244, 158, 211, 155, 38, 174, 109, 24, 63, 216, 33, 6, 216, 75, 18, 75, 181, 36, 0],
                            encryption_secretshare_delta: vec![66u8, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97],
                        })),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateStart(
                        svr4::request4::RotateStart{
                          version: 1,
                          oprf_secretshare_delta: vec![194u8, 166, 59, 46, 131, 202, 97, 72, 122, 129, 29, 38, 126, 5, 64, 65, 100, 217, 81, 146, 231, 192, 39, 222, 249, 39, 180, 237, 180, 74, 219, 15],
                          encryption_secretshare_delta: vec![66u8, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97],
                        })),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateStart(svr4::response4::RotateStart{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateStart(svr4::response4::RotateStart{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{
                            version: 1,
                        })),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{
                          version: 1,
                        })),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
        ], Ok(()); "when version and new_version match across all replicas"
    )]
    #[test_case(
        vec![
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 333,
                            new_version: 111,
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Missing.into(),
                            tries_remaining: 0,
                            version: 0,
                            new_version: 0,
                        })),
                    },
                ],
            ),
        ], Err(Error::BadResponseStatus4(svr4::response4::Status::Missing)); "when the initial query returns an error"
    )]
    #[test_case(
        vec![
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 333,
                            new_version: 111,
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 111,
                            new_version: 222,
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{version: 111})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateRollback(
                        svr4::request4::RotateRollback{version: 222})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::NotRotating.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateRollback(svr4::response4::RotateRollback{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
        ], Err(Error::BadResponseStatus4(svr4::response4::Status::NotRotating)); "when rotation fixing returns an error"
    )]
    #[test_case(
        vec![
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 333,
                            new_version: 111,
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 333,
                            new_version: 111,
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{version: 111})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{version: 111})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateRollback(svr4::response4::RotateRollback{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateStart(
                        svr4::request4::RotateStart{
                            version: 1,
                            oprf_secretshare_delta: vec![43u8, 45, 186, 46, 151, 152, 176, 15, 92, 27, 218, 124, 96, 244, 158, 211, 155, 38, 174, 109, 24, 63, 216, 33, 6, 216, 75, 18, 75, 181, 36, 0],
                            encryption_secretshare_delta: vec![66u8, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97],
                        })),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateStart(
                        svr4::request4::RotateStart{
                          version: 1,
                          oprf_secretshare_delta: vec![194u8, 166, 59, 46, 131, 202, 97, 72, 122, 129, 29, 38, 126, 5, 64, 65, 100, 217, 81, 146, 231, 192, 39, 222, 249, 39, 180, 237, 180, 74, 219, 15],
                          encryption_secretshare_delta: vec![66u8, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97],
                        })),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateStart(svr4::response4::RotateStart{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateStart(svr4::response4::RotateStart{
                            status: svr4::response4::Status::AlreadyRotating.into(),
                        })),
                    },
                ],
            ),
        ], Err(Error::BadResponseStatus4(svr4::response4::Status::AlreadyRotating)); "when rotation start returns an error"
    )]
    #[test_case(
        vec![
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::Query(
                        svr4::request4::Query{})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 333,
                            new_version: 111,
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::Query(svr4::response4::Query{
                            status: svr4::response4::Status::Ok.into(),
                            tries_remaining: 3,
                            version: 333,
                            new_version: 111,
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{version: 111})),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{version: 111})),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateRollback(svr4::response4::RotateRollback{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateStart(
                        svr4::request4::RotateStart{
                            version: 1,
                            oprf_secretshare_delta: vec![43u8, 45, 186, 46, 151, 152, 176, 15, 92, 27, 218, 124, 96, 244, 158, 211, 155, 38, 174, 109, 24, 63, 216, 33, 6, 216, 75, 18, 75, 181, 36, 0],
                            encryption_secretshare_delta: vec![66u8, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97],
                        })),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateStart(
                        svr4::request4::RotateStart{
                          version: 1,
                          oprf_secretshare_delta: vec![194u8, 166, 59, 46, 131, 202, 97, 72, 122, 129, 29, 38, 126, 5, 64, 65, 100, 217, 81, 146, 231, 192, 39, 222, 249, 39, 180, 237, 180, 74, 219, 15],
                          encryption_secretshare_delta: vec![66u8, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97],
                        })),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateStart(svr4::response4::RotateStart{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateStart(svr4::response4::RotateStart{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                ],
            ),
            (
                vec![
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{
                            version: 1,
                        })),
                    },
                    svr4::Request4{
                      inner: Some(svr4::request4::Inner::RotateCommit(
                        svr4::request4::RotateCommit{
                          version: 1,
                        })),
                    },
                ],
                vec![
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::Ok.into(),
                        })),
                    },
                    svr4::Response4{
                        inner: Some(svr4::response4::Inner::RotateCommit(svr4::response4::RotateCommit{
                            status: svr4::response4::Status::NotRotating.into(),
                        })),
                    },
                ],
            ),
        ], Err(Error::BadResponseStatus4(svr4::response4::Status::NotRotating)); "when rotate commit returns an error"
    )]
    /// This test runs a series of steps against the rotation machine,
    /// where at each step it checks the expected requests, then passes in
    /// the provided responses.  All but the last set of responses is
    /// expected to run without error.  The last set of responses is
    /// expected to return `result`, and after the last step the machine
    /// is expected to report `is_done()`.
    fn rotate_machine_success(
        steps: Vec<(Vec<svr4::Request4>, Vec<svr4::Response4>)>,
        result: Result<(), Error>,
    ) {
        let server_ids = [666u64, 333u64]; // these numbers shouldn't matter
        for s in steps.iter() {
            assert_eq!(s.0.len(), server_ids.len());
            assert_eq!(s.1.len(), server_ids.len());
        }

        let mut rng = IncrementingRng { v: 0 };
        let mut machine = RotationMachine::new(&server_ids, &mut rng);

        for step in 0..steps.len() {
            println!("STEP {}", step);
            assert!(!machine.is_done());
            let (expected_requests, received_responses) = &steps[step];
            // Requests should all initially be Queries
            let got_requests = machine
                .requests()
                .iter()
                .map(|b| svr4::Request4::decode(b.as_ref()).map_err(|_| Error::BadData))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            println!("REQUESTS:\n\t{:?}", got_requests);
            assert_eq!(&got_requests, expected_requests);

            println!("RESPONSES:\n\t{:?}", received_responses);
            // Respond with provided responses
            let got = machine.handle_responses(
                &received_responses
                    .iter()
                    .map(|rr| rr.encode_to_vec())
                    .collect::<Vec<_>>(),
            );
            if step == steps.len() - 1 {
                assert_eq!(got, result);
            } else {
                assert_eq!(got, Ok(()));
            }
        }
        assert!(machine.is_done());
    }
}
