//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Used to build custom _attribute-based anonymous credentials_ ("ABCs") and their associated
//! proofs.
//!
//! This crate's cryptographic abstractions are largely built around the idea of a _client,_ an
//! _issuing server,_ and a _verifying server._ The client sends a _credential request_ to the
//! issuing server, which returns a _credential_ in a _response._ The client validates the
//! credential and checks that the server has not fingerprinted it in any way, then generates a
//! _presentation_ for the credential and presents that to the verifying server when making a
//! request (to perform some operation). The verifying server validates that presentation and
//! performs that operation.
//!
//! Presentations should never be reused for multiple operations; that would allow the verifying
//! server to identify that the same user is responsible. Instead, a new presentation should be
//! generated from a cached credential for each operation.
//!
//! What's in a credential? It's essentially a MAC over several _attributes,_ such as the client's
//! account identifier. What's important is that the attributes in a credential support homomorphic
//! encryption, allowing the verifying server to validate attributes without the client revealing
//! them. A credential can even be issued over a _blinded attribute_ hidden from the issuing server,
//! matching whatever value the client has _committed_ to.
//!
//! In this model, the issuing and verifying servers share their private keys, but may otherwise be
//! independent; for Signal, the _issuing server_ is usually the main chat server (which knows who
//! the client is), and the _verifying server_ is the "storage service" where groups are managed
//! (which must not). However, it would be valid to have the same server perform both operations, as
//! long as the second connection can't be correlated with the first.
//!
//! This model is based on "[The Signal Private Group System and Anonymous Credentials Supporting
//! Efficient Verifiable Encryption][paper]", by Chase, Perrin, and Zaverucha.
//!
//! [paper]: https://eprint.iacr.org/2019/1416

#![allow(non_snake_case)]
#![warn(missing_docs)]

/// A zkcredential operation failed to verify.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub struct VerificationFailure;

/// A reasonable size of entropy to request for operations.
///
/// zkcredential uses explicit arrays of randomness rather than taking random number generators as
/// arguments because it makes it easier to write expected-output tests in the languages libsignal
/// is bridged to, which can't easily substitute a custom Rng.
pub const RANDOMNESS_LEN: usize = 32;

pub mod attributes;
pub mod credentials;
pub mod endorsements;
pub mod issuance;
pub mod presentation;
pub mod sho;

/// Helper type for implementing [`std::fmt::Debug`].
///
/// The `Debug::fmt` implementation for this type prints the wrapped value as
/// hex bytes.
pub struct PrintAsHex<T>(pub T);

impl std::fmt::Debug for PrintAsHex<&[u8]> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:0x}")?
        }
        Ok(())
    }
}

impl std::fmt::Debug for PrintAsHex<&curve25519_dalek::ristretto::CompressedRistretto> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        PrintAsHex(self.0.as_bytes().as_slice()).fmt(f)
    }
}

impl std::fmt::Debug for PrintAsHex<&[curve25519_dalek::ristretto::CompressedRistretto]> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(PrintAsHex))
            .finish()
    }
}
