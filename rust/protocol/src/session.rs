//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use rand::{CryptoRng, Rng};

use crate::protocol::CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION;
use crate::ratchet::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::state::{GenericSignedPreKey, SessionState};
use crate::tahini::NewSessionLocation;
use crate::{
    CiphertextMessageType, Direction, IdentityKey, IdentityKeyStore, KeyPair, KyberPreKeyId,
    KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeySignalMessage, PreKeyStore, ProtocolAddress,
    Result, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyStore,
    ratchet,
};

pub struct PreKeysUsed {
    pub one_time_ec_pre_key_id: Option<PreKeyId>,
    pub signed_ec_pre_key_id: SignedPreKeyId,
    pub kyber_pre_key_id: Option<KyberPreKeyId>,
}

/// Expected [`IdentityKeyStore`] change when [`build_prekey_session`] succeeds.
///
/// This represents a deferred action. Assuming later operations succeed, the
/// caller should apply this to the `IdentityKeyStore` that was provided.
#[must_use]
pub struct IdentityToSave<'a> {
    pub remote_address: &'a ProtocolAddress,
    pub their_identity_key: &'a IdentityKey,
}

/// A new Bob-side session derived from an incoming PreKey envelope, *not yet
/// installed* in the [`SessionRecord`].
///
/// Returned by [`build_prekey_session`]. The caller is expected to AEAD-verify
/// the inner [`crate::SignalMessage`] against [`state`](Self::state) and only
/// commit the candidate to the record on success — see
/// [`crate::tahini::commit_received_initiation`]. This enforces the protocol
/// invariant that a session is committed only after AEAD verification.
#[must_use]
pub(crate) struct PreKeySessionCandidate {
    /// The freshly-derived session state. Mutate in place via
    /// `try_decrypt_with_session`; the post-decrypt state is what gets installed.
    pub state: SessionState,
    /// Where this session lands in the record (active vs archive_0) per the
    /// Tahini tiebreaker.
    pub placement: NewSessionLocation,
    /// Pre-keys consumed by deriving this session. Should be marked
    /// used/removed only after AEAD success.
    pub pre_keys_used: PreKeysUsed,
}

/*
These functions are on SessionBuilder in Java

However using SessionBuilder + SessionCipher at the same time causes
&mut sharing issues. And as SessionBuilder has no actual state beyond
its reference to the various data stores, instead the functions are
free standing.
 */

/// Build (but do not install) a Bob-side session from an incoming PreKey
/// envelope.
///
/// Cryptographic property: this function performs the trust check and the
/// PQXDH handshake but **does not mutate `session_record`** and **does not
/// consume any pre-keys**. The returned [`PreKeySessionCandidate`] (if any)
/// must be AEAD-verified against the inner SignalMessage before being
/// committed via [`crate::tahini::commit_received_initiation`]. This enforces
/// the protocol invariant that a session is only valid once AEAD decrypts.
///
/// The caller must confirm there is no existing session for the incoming base
/// key before calling this (a retransmitted PreKey for an existing session is
/// decrypted against that session, not rebuilt). Returns
/// `Ok((candidate, identity_to_save))` for the new session, or `Err` for trust
/// failure / malformed handshake.
pub(crate) async fn build_prekey_session<'a>(
    message: &'a PreKeySignalMessage,
    remote_address: &'a ProtocolAddress,
    local_address: &ProtocolAddress,
    session_record: &SessionRecord,
    identity_store: &dyn IdentityKeyStore,
    pre_key_store: &dyn PreKeyStore,
    signed_prekey_store: &dyn SignedPreKeyStore,
    kyber_prekey_store: &dyn KyberPreKeyStore,
) -> Result<(PreKeySessionCandidate, IdentityToSave<'a>)> {
    let their_identity_key = message.identity_key();

    if !identity_store
        .is_trusted_identity(remote_address, their_identity_key, Direction::Receiving)
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    let candidate = build_prekey_session_inner(
        message,
        remote_address,
        local_address,
        session_record,
        signed_prekey_store,
        kyber_prekey_store,
        pre_key_store,
        identity_store,
    )
    .await?;

    let identity_to_save = IdentityToSave {
        remote_address,
        their_identity_key,
    };

    Ok((candidate, identity_to_save))
}

async fn build_prekey_session_inner(
    message: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    session_record: &SessionRecord,
    signed_prekey_store: &dyn SignedPreKeyStore,
    kyber_prekey_store: &dyn KyberPreKeyStore,
    pre_key_store: &dyn PreKeyStore,
    identity_store: &dyn IdentityKeyStore,
) -> Result<PreKeySessionCandidate> {
    // The incoming PreKey message's base (ephemeral) key serves as the session ID.
    let incoming_session_id = message.base_key().serialize();

    if message.message_version() == CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION {
        // Specifically return InvalidMessage here rather than LegacyCiphertextVersion; the Signal
        // Android app treats LegacyCiphertextVersion as a structural issue rather than a retryable
        // one, and won't cause the sender and receiver to move over to a PQXDH session.
        return Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::PreKey,
            "X3DH no longer supported".to_owned(),
        ));
    }

    let our_signed_pre_key_pair = signed_prekey_store
        .get_signed_pre_key(message.signed_pre_key_id())
        .await?
        .key_pair()?;

    let our_kyber_pre_key_pair = if let Some(kyber_pre_key_id) = message.kyber_pre_key_id() {
        kyber_prekey_store
            .get_kyber_pre_key(kyber_pre_key_id)
            .await?
            .key_pair()?
    } else {
        return Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::PreKey,
            "missing pq pre-key ID".to_owned(),
        ));
    };
    let kyber_ciphertext =
        message
            .kyber_ciphertext()
            .ok_or(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "missing pq ciphertext".to_owned(),
            ))?;

    let our_one_time_pre_key_pair = if let Some(pre_key_id) = message.pre_key_id() {
        log::info!("processing PreKey message from {remote_address}");
        Some(pre_key_store.get_pre_key(pre_key_id).await?.key_pair()?)
    } else {
        log::warn!("processing PreKey message from {remote_address} which had no one-time prekey");
        None
    };

    let our_identity_key_pair = identity_store.get_identity_key_pair().await?;
    let parameters = BobSignalProtocolParameters::new(
        our_identity_key_pair,
        our_signed_pre_key_pair,
        our_one_time_pre_key_pair,
        our_kyber_pre_key_pair,
        *message.identity_key(),
        *message.base_key(),
        kyber_ciphertext,
        our_identity_key_pair.identity_key().is_same_account(
            local_address,
            message.identity_key(),
            remote_address,
        ),
    );

    // The recipient's initial ratchet key is the signed pre-key.
    let mut new_session = ratchet::initialize_bob_session(&parameters, &our_signed_pre_key_pair)?;

    new_session.set_local_registration_id(identity_store.get_local_registration_id().await?);
    new_session.set_remote_registration_id(message.registration_id());

    // Pure placement decision based on current record state. Commit happens
    // only after AEAD verification, in the caller.
    let placement = crate::tahini::decide_initiation_placement(
        session_record,
        &incoming_session_id,
        message.identity_key(),
    )?;

    let pre_keys_used = PreKeysUsed {
        one_time_ec_pre_key_id: message.pre_key_id(),
        signed_ec_pre_key_id: message.signed_pre_key_id(),
        kyber_pre_key_id: message.kyber_pre_key_id(),
    };

    Ok(PreKeySessionCandidate {
        state: new_session,
        placement,
        pre_keys_used,
    })
}

pub async fn process_prekey_bundle<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    bundle: &PreKeyBundle,
    now: SystemTime,
    mut csprng: &mut R,
) -> Result<()> {
    let their_identity_key = bundle.identity_key()?;

    if !identity_store
        .is_trusted_identity(remote_address, their_identity_key, Direction::Sending)
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    if !their_identity_key.public_key().verify_signature(
        &bundle.signed_pre_key_public()?.serialize(),
        bundle.signed_pre_key_signature()?,
    ) {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    if !their_identity_key.public_key().verify_signature(
        &bundle.kyber_pre_key_public()?.serialize(),
        bundle.kyber_pre_key_signature()?,
    ) {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    let our_base_key_pair = KeyPair::generate(&mut csprng);
    let their_signed_prekey = bundle.signed_pre_key_public()?;
    let their_kyber_prekey = bundle.kyber_pre_key_public()?;

    let their_one_time_prekey_id = bundle.pre_key_id()?;

    let our_identity_key_pair = identity_store.get_identity_key_pair().await?;

    let mut parameters = AliceSignalProtocolParameters::new(
        our_identity_key_pair,
        our_base_key_pair,
        *their_identity_key,
        their_signed_prekey,
        their_signed_prekey,
        their_kyber_prekey.clone(),
        our_identity_key_pair.identity_key().is_same_account(
            local_address,
            their_identity_key,
            remote_address,
        ),
    );
    if let Some(key) = bundle.pre_key_public()? {
        parameters.set_their_one_time_pre_key(key);
    }

    let mut session = ratchet::initialize_alice_session(&parameters, csprng)?;

    log::info!(
        "set_unacknowledged_pre_key_message for: {} with preKeyId: {}",
        remote_address,
        their_one_time_prekey_id.map_or_else(|| "<none>".to_string(), |id| id.to_string())
    );

    session.set_unacknowledged_pre_key_message(
        their_one_time_prekey_id,
        bundle.signed_pre_key_id()?,
        &our_base_key_pair.public_key,
        now,
    );
    session.set_unacknowledged_kyber_pre_key_id(bundle.kyber_pre_key_id()?);

    session.set_local_registration_id(identity_store.get_local_registration_id().await?);
    session.set_remote_registration_id(bundle.registration_id()?);

    identity_store
        .save_identity(remote_address, their_identity_key)
        .await?;

    crate::tahini::on_initiate(&mut session_record, session);

    session_store
        .store_session(remote_address, &session_record)
        .await?;

    Ok(())
}
