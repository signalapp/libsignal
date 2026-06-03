//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Handshake trait for key agreement protocols.
//!
//! Abstracts over different key agreement protocols (PQXDH, and hypothetical
//! future variants). The trait separates key agreement from ratchet
//! initialization and session management.
//!
//! See [`crate::pqxdh`] for the current production implementation.

use rand::{CryptoRng, Rng};

use crate::Result;

/// A key agreement protocol used to establish a shared secret during
/// session initialization.
///
/// Implementors handle the cryptographic key agreement (DH computations,
/// KEM encapsulation/decapsulation, KDF). The resulting session secret is
/// consumed by the ratchet layer to initialize session state. The initiator
/// also produces a message that must be sent to the recipient for them to
/// complete the agreement.
///
/// The `initiate` method returns `(InitiatorMessage, SessionSecret)` to
/// enforce a clean boundary: the message is data for the wire, the secret
/// is data for the ratchet. These are currently protocol-specific types
/// but should eventually become opaque byte arrays.
pub(crate) trait Handshake {
    /// Parameters for the initiator (constructed from a pre-key bundle).
    type InitiatorParams;

    /// Parameters for the recipient (constructed from an incoming message).
    type RecipientParams<'a>;

    /// Data the initiator must send to the recipient for them to complete
    /// the key agreement (e.g., a KEM ciphertext for PQXDH).
    type InitiatorMessage;

    /// The shared secret derived from the handshake, consumed by the
    /// ratchet layer to initialize session state.
    type SessionSecret;

    /// Perform the initiator side of the key agreement.
    ///
    /// Returns the message to send and the session secret to keep.
    fn initiate<R: Rng + CryptoRng>(
        params: &Self::InitiatorParams,
        rng: &mut R,
    ) -> Result<(Self::InitiatorMessage, Self::SessionSecret)>;

    /// Perform the recipient side of the key agreement.
    fn accept(params: &Self::RecipientParams<'_>) -> Result<Self::SessionSecret>;
}
