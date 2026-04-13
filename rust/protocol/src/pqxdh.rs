//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! PQXDH key agreement protocol.
//!
//! This module implements the PQXDH (Post-Quantum Extended Diffie-Hellman) key
//! agreement, extracting the pure key agreement computation from ratchet
//! initialization. The output includes derived keys ready for ratchet setup;
//! the actual ratchet initialization is handled separately in the internal
//! ratchet module.
//!
//! ## Future direction
//!
//! The KDF output shape (`RootKey`, `ChainKey`, `[u8; 32]`) is currently
//! coupled to the Double Ratchet's initialization requirements. Ideally, the
//! handshake would output a single 32-byte secret and the ratchet layer would
//! derive whatever it needs from that. This requires a protocol version bump
//! and should be done alongside a future handshake protocol revision.

use libsignal_core::derive_arrays;
use rand::{CryptoRng, Rng};

use crate::handshake::Handshake;
use crate::ratchet::{ChainKey, RootKey};
use crate::{
    CiphertextMessageType, IdentityKey, IdentityKeyPair, KeyPair, PublicKey, Result,
    SignalProtocolError, kem,
};

/// The PQXDH key agreement protocol.
///
/// Implements [`Handshake`] for the Post-Quantum Extended Diffie-Hellman
/// protocol (4 EC DH + 1 ML-KEM encapsulation/decapsulation).
pub(crate) struct Pqxdh;

impl Handshake for Pqxdh {
    type InitiatorParams = InitiatorParameters;
    type RecipientParams<'a> = RecipientParameters<'a>;
    type InitiatorMessage = kem::SerializedCiphertext;
    type SessionSecret = HandshakeKeys;

    fn initiate<R: Rng + CryptoRng>(
        params: &Self::InitiatorParams,
        rng: &mut R,
    ) -> Result<(Self::InitiatorMessage, Self::SessionSecret)> {
        let result = pqxdh_initiate(params, rng)?;
        Ok((result.kyber_ciphertext, result.keys))
    }

    fn accept(params: &Self::RecipientParams<'_>) -> Result<Self::SessionSecret> {
        pqxdh_accept(params)
    }
}

/// The initial PQR (post-quantum ratchet) key derived from the handshake.
pub(crate) type InitialPQRKey = [u8; 32];

/// Keys derived from a PQXDH handshake, ready for ratchet initialization.
///
/// This bundles the KDF output in the shape the ratchet layer expects.
/// See module-level docs for why this is coupled and the plan to decouple.
pub(crate) struct HandshakeKeys {
    pub root_key: RootKey,
    pub chain_key: ChainKey,
    pub pqr_key: InitialPQRKey,
}

impl HandshakeKeys {
    /// Derive ratchet initialization keys from raw PQXDH shared secret material.
    fn derive(secret_input: &[u8]) -> Self {
        Self::derive_with_label(
            b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024",
            secret_input,
        )
    }

    fn derive_with_label(label: &[u8], secret_input: &[u8]) -> Self {
        let (root_key_bytes, chain_key_bytes, pqr_bytes) = derive_arrays(|bytes| {
            hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
                .expand(label, bytes)
                .expect("valid length")
        });

        Self {
            root_key: RootKey::new(root_key_bytes),
            chain_key: ChainKey::new(chain_key_bytes, 0),
            pqr_key: pqr_bytes,
        }
    }
}

// ── Initiator ────────────────────────────────────────────────────────

/// The output of a PQXDH key agreement from the initiator's side.
///
/// Contains the derived handshake keys and the KEM ciphertext that the
/// recipient needs to complete the agreement.
pub(crate) struct InitiatorAgreement {
    keys: HandshakeKeys,
    kyber_ciphertext: kem::SerializedCiphertext,
}

/// Parameters for the initiator side of a PQXDH key agreement.
///
/// The initiator fetches the recipient's pre-key bundle from the server
/// and uses it together with their own identity and ephemeral keys to
/// compute a shared secret.
pub struct InitiatorParameters {
    our_identity_key_pair: IdentityKeyPair,
    our_ephemeral_key_pair: KeyPair,

    their_identity_key: IdentityKey,
    their_signed_pre_key: PublicKey,
    their_one_time_pre_key: Option<PublicKey>,
    their_ratchet_key: PublicKey,
    their_kyber_pre_key: kem::PublicKey,
}

impl InitiatorParameters {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_ephemeral_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: PublicKey,
        their_ratchet_key: PublicKey,
        their_kyber_pre_key: kem::PublicKey,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_ephemeral_key_pair,
            their_identity_key,
            their_one_time_pre_key: None,
            their_signed_pre_key,
            their_ratchet_key,
            their_kyber_pre_key,
        }
    }

    pub fn set_their_one_time_pre_key(&mut self, ec_public: PublicKey) {
        self.their_one_time_pre_key = Some(ec_public);
    }

    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    pub fn our_ephemeral_key_pair(&self) -> &KeyPair {
        &self.our_ephemeral_key_pair
    }

    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_signed_pre_key(&self) -> &PublicKey {
        &self.their_signed_pre_key
    }

    #[inline]
    pub fn their_one_time_pre_key(&self) -> Option<&PublicKey> {
        self.their_one_time_pre_key.as_ref()
    }

    #[inline]
    pub fn their_kyber_pre_key(&self) -> &kem::PublicKey {
        &self.their_kyber_pre_key
    }

    #[inline]
    pub fn their_ratchet_key(&self) -> &PublicKey {
        &self.their_ratchet_key
    }
}

/// Perform the initiator side of the PQXDH key agreement.
///
/// Computes DH shared secrets and KEM encapsulation, then applies the KDF
/// to produce keys ready for ratchet initialization.
pub(crate) fn pqxdh_initiate<R: Rng + CryptoRng>(
    parameters: &InitiatorParameters,
    mut csprng: &mut R,
) -> Result<InitiatorAgreement> {
    let mut secrets = Vec::with_capacity(32 * 6);

    secrets.extend_from_slice(&[0xFFu8; 32]); // discontinuity bytes

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair
            .private_key()
            .calculate_agreement(&parameters.their_signed_pre_key)?,
    );

    let our_ephemeral_private_key = parameters.our_ephemeral_key_pair.private_key;

    secrets.extend_from_slice(
        &our_ephemeral_private_key
            .calculate_agreement(parameters.their_identity_key.public_key())?,
    );

    secrets.extend_from_slice(
        &our_ephemeral_private_key.calculate_agreement(&parameters.their_signed_pre_key)?,
    );

    if let Some(their_one_time_prekey) = &parameters.their_one_time_pre_key {
        secrets.extend_from_slice(
            &our_ephemeral_private_key.calculate_agreement(their_one_time_prekey)?,
        );
    }

    let kyber_ciphertext = {
        let (ss, ct) = parameters.their_kyber_pre_key.encapsulate(&mut csprng)?;
        secrets.extend_from_slice(ss.as_ref());
        ct
    };

    Ok(InitiatorAgreement {
        keys: HandshakeKeys::derive(&secrets),
        kyber_ciphertext,
    })
}

// ── Recipient ────────────────────────────────────────────────────────

/// Parameters for the recipient side of a PQXDH key agreement.
///
/// The recipient uses their own pre-keys together with the initiator's
/// identity and base keys (received in the pre-key message) to compute
/// the same shared secret.
pub struct RecipientParameters<'a> {
    our_identity_key_pair: IdentityKeyPair,
    our_signed_pre_key_pair: KeyPair,
    our_one_time_pre_key_pair: Option<KeyPair>,
    our_kyber_pre_key_pair: kem::KeyPair,

    their_identity_key: IdentityKey,
    their_ephemeral_key: PublicKey,
    their_kyber_ciphertext: &'a kem::SerializedCiphertext,
}

impl<'a> RecipientParameters<'a> {
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: KeyPair,
        our_one_time_pre_key_pair: Option<KeyPair>,
        our_kyber_pre_key_pair: kem::KeyPair,
        their_identity_key: IdentityKey,
        their_ephemeral_key: PublicKey,
        their_kyber_ciphertext: &'a kem::SerializedCiphertext,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_signed_pre_key_pair,
            our_one_time_pre_key_pair,
            our_kyber_pre_key_pair,
            their_identity_key,
            their_ephemeral_key,
            their_kyber_ciphertext,
        }
    }

    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    pub fn our_signed_pre_key_pair(&self) -> &KeyPair {
        &self.our_signed_pre_key_pair
    }

    #[inline]
    pub fn our_one_time_pre_key_pair(&self) -> Option<&KeyPair> {
        self.our_one_time_pre_key_pair.as_ref()
    }

    #[inline]
    pub fn our_kyber_pre_key_pair(&self) -> &kem::KeyPair {
        &self.our_kyber_pre_key_pair
    }

    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_ephemeral_key(&self) -> &PublicKey {
        &self.their_ephemeral_key
    }

    #[inline]
    pub fn their_kyber_ciphertext(&self) -> &kem::SerializedCiphertext {
        self.their_kyber_ciphertext
    }
}

/// Perform the recipient side of the PQXDH key agreement.
///
/// Computes DH shared secrets and KEM decapsulation, then applies the KDF
/// to produce keys ready for ratchet initialization.
pub(crate) fn pqxdh_accept(parameters: &RecipientParameters) -> Result<HandshakeKeys> {
    // Validate the initiator's base key before doing any computation.
    if !parameters.their_ephemeral_key.is_canonical() {
        return Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::PreKey,
            "incoming base key is invalid",
        ));
    }

    let mut secrets = Vec::with_capacity(32 * 6);

    secrets.extend_from_slice(&[0xFFu8; 32]); // discontinuity bytes

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair
            .private_key
            .calculate_agreement(parameters.their_identity_key.public_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair
            .private_key()
            .calculate_agreement(&parameters.their_ephemeral_key)?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair
            .private_key
            .calculate_agreement(&parameters.their_ephemeral_key)?,
    );

    if let Some(our_one_time_pre_key_pair) = &parameters.our_one_time_pre_key_pair {
        secrets.extend_from_slice(
            &our_one_time_pre_key_pair
                .private_key
                .calculate_agreement(&parameters.their_ephemeral_key)?,
        );
    }

    secrets.extend_from_slice(
        &parameters
            .our_kyber_pre_key_pair
            .secret_key
            .decapsulate(parameters.their_kyber_ciphertext)?,
    );

    Ok(HandshakeKeys::derive(&secrets))
}
