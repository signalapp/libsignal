//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Session management and public encrypt/decrypt API for Signal 1:1 messaging.
//!
//! This module owns two things:
//!
//! 1. **The public API** — [`message_encrypt`], [`message_decrypt`],
//!    [`message_decrypt_signal`], [`message_decrypt_prekey`]. These are the
//!    entry points used by the bridge layer and `sealed_sender`.
//!
//! 2. **Tahini session management** — the "which session do we use?" logic:
//!    trial-decryption across active and archived sessions, in-place archived
//!    session updates, tiebreak handling for simultaneous initiation, and
//!    session selection for encryption.
//!
//! All cryptographic ratchet operations are delegated to
//! [`TripleRatchet`]. This module has no knowledge of chain keys,
//! root keys, or SPQR internals.

use std::time::SystemTime;

use libsignal_core::try_scoped;
use rand::{CryptoRng, Rng};

use crate::consts::MAX_UNACKNOWLEDGED_SESSION_AGE;
use crate::state::{InvalidSessionError, SessionLocation, SessionState};
use crate::triple_ratchet::{OutgoingTripleRatchet, TripleRatchet};
use crate::{
    CiphertextMessage, CiphertextMessageType, Direction, IdentityKey, IdentityKeyStore,
    KyberPayload, KyberPreKeyStore, PreKeyBundle, PreKeySignalMessage, PreKeyStore,
    ProtocolAddress, Result, SessionNotFound, SessionRecord, SessionStore, SignalMessage,
    SignalProtocolError, SignedPreKeyStore, session, tahini,
};

#[cfg(test)]
mod tests;

// ── Public API ───────────────────────────────────────────────────────────────

/// Establish or refresh a locally-initiated session for `remote_address`
/// using the recipient's latest pre-key bundle.
pub async fn initiate_session<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    bundle: &PreKeyBundle,
    now: SystemTime,
    csprng: &mut R,
) -> Result<()> {
    session::process_prekey_bundle(
        remote_address,
        local_address,
        session_store,
        identity_store,
        bundle,
        now,
        csprng,
    )
    .await
}

/// Encrypt `ptext` for `remote_address`, loading and storing session state.
///
/// If the session is unacknowledged (a locally-initiated session that has not
/// yet received a response), wraps the [`SignalMessage`] in a
/// [`PreKeySignalMessage`] containing the original pre-key material.
pub async fn message_encrypt<R: Rng + CryptoRng>(
    ptext: &[u8],
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    now: SystemTime,
    csprng: &mut R,
) -> Result<CiphertextMessage> {
    let no_session_error = || {
        SignalProtocolError::SessionNotFound(SessionNotFound::new(
            remote_address.clone(),
            "message_encrypt",
        ))
    };
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .ok_or_else(no_session_error)?;

    let session_state = session_record
        .active_session_mut()
        .ok_or_else(no_session_error)?;

    let mut session = OutgoingTripleRatchet::from_session_state(session_state).map_err(|e| {
        log::error!("session state corrupt for {remote_address}: {e}");
        e
    })?;

    let their_identity_key = session_state
        .remote_identity_key()?
        .expect("session was valid; must have remote identity key");

    // Pre-key wrapping — session management concern.
    let message = if let Some(items) = session_state.unacknowledged_pre_key_message_items()? {
        let timestamp_as_unix_time = items
            .timestamp()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if items.timestamp() + MAX_UNACKNOWLEDGED_SESSION_AGE < now {
            log::warn!(
                "stale unacknowledged session for {remote_address} (created at {timestamp_as_unix_time})"
            );
            return Err(no_session_error());
        }

        let local_registration_id = session_state.local_registration_id();

        log::info!(
            "Building PreKeyWhisperMessage for: {} with preKeyId: {} (session created at {})",
            remote_address,
            items
                .pre_key_id()
                .map_or_else(|| "<none>".to_string(), |id| id.to_string()),
            timestamp_as_unix_time,
        );

        let kyber_payload = items
            .kyber_pre_key_id()
            .zip(items.kyber_ciphertext())
            .map(|(id, ciphertext)| KyberPayload::new(id, ciphertext.into()));
        let signal_message = session.encrypt(ptext, Some(local_address), remote_address, csprng)?;

        CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::new(
            session.session_version(),
            local_registration_id,
            items.pre_key_id(),
            items.signed_pre_key_id(),
            kyber_payload,
            *items.base_key(),
            *session.local_identity_key(),
            signal_message,
        )?)
    } else {
        let signal_message = session.encrypt(ptext, None, remote_address, csprng)?;
        CiphertextMessage::SignalMessage(signal_message)
    };

    // In clients, `is_trusted_identity` for the Sending direction checks
    // whether the session's identity key matches the stored key AND whether the
    // user has approved it (safety number changes, verification status). This
    // prevents sending to a contact whose identity has changed without user
    // acknowledgment.
    if !identity_store
        .is_trusted_identity(remote_address, &their_identity_key, Direction::Sending)
        .await?
    {
        log::warn!(
            "Identity key {} is not trusted for remote address {}",
            hex::encode(their_identity_key.public_key().public_key_bytes()),
            remote_address,
        );
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    identity_store
        .save_identity(remote_address, &their_identity_key)
        .await?;

    // Commit and save session state changes.
    session.apply_to_session_state(session_state);

    // Encryption succeeded — record the send for Tahini deadlock tracking.
    tahini::on_send(&mut session_record);

    session_store
        .store_session(remote_address, &session_record)
        .await?;
    Ok(message)
}

/// Decrypt a [`CiphertextMessage`] from `remote_address`.
///
/// Routes to [`message_decrypt_signal`] or [`message_decrypt_prekey`] based
/// on message type.
#[allow(clippy::too_many_arguments)]
pub async fn message_decrypt<R: Rng + CryptoRng>(
    ciphertext: &CiphertextMessage,
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &dyn SignedPreKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    match ciphertext {
        CiphertextMessage::SignalMessage(m) => {
            message_decrypt_signal(
                m,
                remote_address,
                local_address,
                session_store,
                identity_store,
                csprng,
            )
            .await
        }
        CiphertextMessage::PreKeySignalMessage(m) => message_decrypt_prekey(
            m,
            remote_address,
            local_address,
            session_store,
            identity_store,
            pre_key_store,
            signed_pre_key_store,
            kyber_pre_key_store,
            csprng,
        )
        .await
        .map(|r| r.plaintext),
        _ => Err(SignalProtocolError::InvalidArgument(format!(
            "message_decrypt cannot be used to decrypt {:?} messages",
            ciphertext.message_type()
        ))),
    }
}

/// Result of decrypting a [`PreKeySignalMessage`] in [`message_decrypt_prekey`].
///
/// Carries the plaintext and recovered sender identity.
///
/// With plain PQXDH the caller supplies the address, so `sender` echoes the
/// input. Under a future sender-anonymity layer these fields will identify the
/// sender recovered during session initiation.
pub struct PreKeyDecryptResult {
    pub plaintext: Vec<u8>,
    pub sender: ProtocolAddress,
    pub sender_identity_key: IdentityKey,
}

/// Decrypt a [`PreKeySignalMessage`] from `remote_address`.
///
/// If a session for the incoming base key already exists, the inner
/// [`SignalMessage`] is decrypted against that session directly. This covers
/// both retransmitted pre-key messages and messages 1+ of the initial chain,
/// which all carry the same base key. The peer's identity is always
/// trust-checked, but only saved for an active session. Messages on existing
/// archived sessions cannot replace the stored identity.
///
/// Otherwise this builds a candidate session from the pre-key material,
/// AEAD-verifies the inner [`SignalMessage`] against the candidate, and only
/// commits the session + consumes pre-keys + saves identity on AEAD success.
/// This enforces the protocol invariant that a session is committed only after
/// AEAD decrypts.
#[allow(clippy::too_many_arguments)]
pub async fn message_decrypt_prekey<R: Rng + CryptoRng>(
    ciphertext: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &dyn SignedPreKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
    csprng: &mut R,
) -> Result<PreKeyDecryptResult> {
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    // PreKey decrypt, two cases:
    //
    // 1. Existing session — a session for this base key already exists (a
    //    retransmitted pre-key message, or messages 1+ of the initial chain).
    //    The PQXDH handshake completed when that session was created, so there
    //    is no new handshake and no pre-key consumption. As on the Whisper
    //    path, trust-check the identity but only save it for an active session.
    //    An archived session must not roll back a subsequently learned identity.
    //
    // 2. Fresh — no session for this base key. Build a *candidate* session
    //    (pure: no record mutation, no prekey consumption), AEAD-verify the
    //    inner SignalMessage against it, and commit the candidate to the
    //    record ONLY on AEAD success. A session is never stored before its
    //    first message decrypts — storing earlier violates the PQXDH spec and
    //    has enabled real attacks in the past.
    // The incoming PreKey message's base (ephemeral) key serves as the session ID.
    let session_id = ciphertext.base_key().serialize();
    let result = if let Some(loc) = session_record.find_session_by_id(&session_id)? {
        // Case 1: dedup against the existing session.
        let mut state = session_record
            .get_session(loc)?
            .expect("session present at validated location");

        // The message's identity key must match the one recorded for this session. (Note that
        // this is a constant-time comparison as long as the keys have the same type: see
        // PublicKey's PartialEq.)
        if !state
            .remote_identity_key()?
            .is_some_and(|stored| *ciphertext.identity_key() == stored)
        {
            // We return this as InvalidMessage rather than any other error because there's no
            // expected recovery; barring data corruption, the peer has just decided to send us the
            // wrong identity key for no apparent reason. (Of course, it's possible it's the local
            // state that's wrong, but that's true for the eventual MAC check as well.)
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "remote identity key not consistent with previously-established session".to_owned(),
            ));
        }

        let ptext = try_decrypt_with_session(
            &mut state,
            remote_address,
            local_address,
            ciphertext.message(),
            CiphertextMessageType::Whisper,
            csprng,
        )
        .map_err(|e| {
            if matches!(
                e,
                SignalProtocolError::DuplicatedMessage(_, _)
                    | SignalProtocolError::UnrecognizedMessageVersion(_)
            ) {
                return e;
            }
            log::error!(
                "Failed to decrypt PreKey message against existing session for {}. \
                     Base key: {}. Error: {}",
                remote_address,
                hex::encode(ciphertext.base_key().serialize()),
                e,
            );
            SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "decryption failed".to_owned(),
            )
        })?;

        let their_identity_key = state
            .remote_identity_key()?
            .expect("successfully decrypted; must have a remote identity key");
        if !identity_store
            .is_trusted_identity(remote_address, &their_identity_key, Direction::Receiving)
            .await?
        {
            log::warn!(
                "Identity key {} is not trusted for remote address {}",
                hex::encode(their_identity_key.public_key().public_key_bytes()),
                remote_address,
            );
            return Err(SignalProtocolError::UntrustedIdentity(
                remote_address.clone(),
            ));
        }
        if matches!(loc, SessionLocation::Current) {
            identity_store
                .save_identity(remote_address, &their_identity_key)
                .await?;
        }

        session_record.update_session_state(loc, state)?;
        match loc {
            SessionLocation::Current => tahini::on_receive_active(&mut session_record),
            SessionLocation::Archived(_) => tahini::on_receive_inactive(&mut session_record)?,
        }
        // Any identity update is complete. An existing session consumes no pre-key and
        // records no base-key marker, so the session state is all that remains.
        session_store
            .store_session(remote_address, &session_record)
            .await?;
        PreKeyDecryptResult {
            plaintext: ptext,
            sender: remote_address.clone(),
            sender_identity_key: their_identity_key,
        }
    } else {
        // Case 2: fresh session. `build_prekey_session` runs the trust check
        // and the PQXDH handshake but does not mutate the record.
        let (mut candidate, identity_to_save) = match session::build_prekey_session(
            ciphertext,
            remote_address,
            local_address,
            &session_record,
            identity_store,
            pre_key_store,
            signed_pre_key_store,
            kyber_pre_key_store,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                log::error!(
                    "Failed to build PreKey session for {}. Base key: {}. Error: {}",
                    remote_address,
                    hex::encode(ciphertext.base_key().serialize()),
                    e,
                );
                return Err(e);
            }
        };

        // AEAD-verify against the standalone candidate state. If this fails,
        // the record is untouched and prekeys are not consumed. Malformed handshake
        // does not change our state.
        let ptext = try_decrypt_with_session(
            &mut candidate.state,
            remote_address,
            local_address,
            ciphertext.message(),
            CiphertextMessageType::PreKey,
            csprng,
        )
        .map_err(|e| {
            log::error!(
                "Failed to AEAD-verify PreKey candidate session for {}. \
                     Base key: {}. Error: {}",
                remote_address,
                hex::encode(ciphertext.base_key().serialize()),
                e,
            );
            SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "decryption failed".to_owned(),
            )
        })?;

        // AEAD succeeded — place the candidate in the in-memory record. An
        // active placement resets the deadlock state and records the receive.
        // An archived placement preserves the history; separately count the
        // successfully decrypted enclosed message as an inactive receive.
        tahini::commit_received_initiation(
            &mut session_record,
            candidate.state,
            candidate.placement,
        )?;
        if candidate.placement == tahini::NewSessionLocation::Archived {
            tahini::on_receive_inactive(&mut session_record)?;
        }

        // Mark the base key as seen and consume the one-time Kyber prekey after
        // AEAD success but before installing the session. This is a gate, not just
        // a write: it errors if this base key was already used with these pre-keys,
        // which is how a replay is detected, so it must early-exit.
        if let Some(kyber_pre_key_id) = candidate.pre_keys_used.kyber_pre_key_id {
            kyber_pre_key_store
                .mark_kyber_pre_key_used(
                    kyber_pre_key_id,
                    candidate.pre_keys_used.signed_ec_pre_key_id,
                    ciphertext.base_key(),
                )
                .await?;
        }

        // Past the gate the base key is spent, so this message can never decrypt
        // again. Attempt every remaining write and report the first failure rather
        // than early-exiting and leaving the rest of the cleanup undone.
        // Client identity callbacks may archive sessions (including this device's
        // session on iOS). Run them before the final session write so the newly
        // accepted session is installed after those side effects.
        let save_identity_result = identity_store
            .save_identity(
                identity_to_save.remote_address,
                identity_to_save.their_identity_key,
            )
            .await;

        let store_session_result = session_store
            .store_session(remote_address, &session_record)
            .await;

        let remove_pre_key_result = match candidate.pre_keys_used.one_time_ec_pre_key_id {
            Some(pre_key_id) => pre_key_store.remove_pre_key(pre_key_id).await,
            None => Ok(()),
        };

        save_identity_result?;
        store_session_result?;
        remove_pre_key_result?;

        PreKeyDecryptResult {
            plaintext: ptext,
            sender: remote_address.clone(),
            sender_identity_key: *identity_to_save.their_identity_key,
        }
    };

    Ok(result)
}

/// Decrypt a [`SignalMessage`] from `remote_address`.
///
/// Tries all sessions in the session record. Checks identity key trust
/// after decryption. Only a receive on the active session saves the identity;
/// archived sessions may decrypt delayed messages from a retired identity.
pub async fn message_decrypt_signal<R: Rng + CryptoRng>(
    ciphertext: &SignalMessage,
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .ok_or_else(|| {
            SignalProtocolError::SessionNotFound(SessionNotFound::new(
                remote_address.clone(),
                "message_decrypt_signal",
            ))
        })?;

    let result = try_decrypt_with_all_sessions(
        remote_address,
        local_address,
        &mut session_record,
        ciphertext,
        csprng,
    )?;

    let their_identity_key = result
        .their_identity_key
        .expect("successfully decrypted; must have a remote identity key");

    if !identity_store
        .is_trusted_identity(remote_address, &their_identity_key, Direction::Receiving)
        .await?
    {
        log::warn!(
            "Identity key {} is not trusted for remote address {}",
            hex::encode(their_identity_key.public_key().public_key_bytes()),
            remote_address,
        );
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    if result.decrypted_on_active {
        identity_store
            .save_identity(remote_address, &their_identity_key)
            .await?;
    }

    session_store
        .store_session(remote_address, &session_record)
        .await?;

    Ok(result.ptext)
}

// ── Session management (Tahini) ──────────────────────────────────────────────

/// Result of a successful decryption: plaintext + the remote identity key from
/// the session that decrypted. The identity key is needed for trust checks in
/// `message_decrypt_signal` and may come from any session (active or archived).
pub(crate) struct DecryptionResult {
    pub ptext: Vec<u8>,
    pub their_identity_key: Option<IdentityKey>,
    /// Whether the session was active when it decrypted the message. Capture
    /// this before receive bookkeeping, which can archive the active session.
    pub decrypted_on_active: bool,
}

/// Try to decrypt a `Whisper` `ciphertext` against every session in `record`,
/// in order.
///
/// Tries the current (active) session first, then archived sessions. On
/// success from an archived session, the session is updated **in place** —
/// Tahini never promotes archived sessions to current.
///
/// This is the `Whisper` trial-decryption path only. PreKey messages do not
/// flow through here: a PreKey envelope is matched to a specific session by base
/// key in [`message_decrypt_prekey`], which must not fall back across sessions.
pub(crate) fn try_decrypt_with_all_sessions<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    record: &mut SessionRecord,
    ciphertext: &SignalMessage,
    csprng: &mut R,
) -> Result<DecryptionResult> {
    let ciphertext_version = ciphertext.message_version() as u32;

    let log_failure = |label: &str, state: &SessionState, error: &SignalProtocolError| {
        log::warn!(
            "Failed to decrypt Whisper message with ratchet key: {} and counter: {}. \
             Session loaded for {}. {} session has base key: {} and counter: {}. {}",
            hex::encode(ciphertext.sender_ratchet_key().public_key_bytes()),
            ciphertext.counter(),
            remote_address,
            label,
            state
                .sender_ratchet_key_for_logging()
                .unwrap_or_else(|e| format!("<error: {e}>")),
            state.previous_counter(),
            error
        );
    };

    let mut errs = vec![];

    // ── Try active session ───────────────────────────────────────────────────

    if let Some(active_session) = record.active_session() {
        let mut active_session = active_session.clone();

        if active_session.session_version()? != ciphertext_version {
            let e = SignalProtocolError::UnrecognizedMessageVersion(ciphertext_version);
            log_failure("Active", &active_session, &e);
            errs.push(e);
        } else {
            match try_decrypt_with_session(
                &mut active_session,
                remote_address,
                local_address,
                ciphertext,
                CiphertextMessageType::Whisper,
                csprng,
            ) {
                Ok(ptext) => {
                    log::info!(
                        "decrypted Whisper message from {} with active session (sender ratchet key {})",
                        remote_address,
                        active_session
                            .sender_ratchet_key_for_logging()
                            .expect("successful decrypt always has a valid sender ratchet key"),
                    );
                    let their_identity_key = active_session.remote_identity_key().ok().flatten();
                    tahini::on_receive_session_state(&mut active_session);
                    // Write back: decryption advances the ratchet and consumes message keys.
                    record.set_active_session(active_session);
                    tahini::on_receive_active(record);
                    return Ok(DecryptionResult {
                        ptext,
                        their_identity_key,
                        decrypted_on_active: true,
                    });
                }
                Err(e @ SignalProtocolError::DuplicatedMessage(_, _)) => return Err(e),
                Err(e) => {
                    // Active session didn't decrypt; fall through to the archived
                    // sessions below.
                    log_failure("Active", &active_session, &e);
                    errs.push(e);
                }
            }
        }
    }

    // ── Try archived sessions (Whisper only, NO promotion) ───────────────────

    let mut decrypted_on_archived = None;

    for (idx, previous) in record.archived_sessions().enumerate() {
        let mut previous = match previous {
            Ok(previous) => previous,
            Err(e) => {
                let e: SignalProtocolError = e.into();
                log::warn!(
                    "Skipping corrupt archived session {} for {}: {}",
                    idx,
                    remote_address,
                    e
                );
                errs.push(e);
                continue;
            }
        };

        if previous.session_version()? != ciphertext_version {
            let e = SignalProtocolError::UnrecognizedMessageVersion(ciphertext_version);
            log_failure("Archived", &previous, &e);
            errs.push(e);
            continue;
        }

        match try_decrypt_with_session(
            &mut previous,
            remote_address,
            local_address,
            ciphertext,
            CiphertextMessageType::Whisper,
            csprng,
        ) {
            Ok(ptext) => {
                log::info!(
                    "decrypted Whisper message from {} with ARCHIVED session {} (sender ratchet key {})",
                    remote_address,
                    idx,
                    previous
                        .sender_ratchet_key_for_logging()
                        .expect("successful decrypt always has a valid sender ratchet key"),
                );
                let their_identity_key = previous.remote_identity_key().ok().flatten();
                decrypted_on_archived = Some((ptext, idx, previous, their_identity_key));
                break;
            }
            Err(e @ SignalProtocolError::DuplicatedMessage(_, _)) => return Err(e),
            Err(e) => {
                log_failure("Archived", &previous, &e);
                errs.push(e);
            }
        }
    }

    if let Some((ptext, idx, mut updated, their_identity_key)) = decrypted_on_archived {
        tahini::on_receive_session_state(&mut updated);
        // Tahini: update the archived session in place — no promotion.
        record.update_archived_session(idx, updated)?;
        tahini::on_receive_inactive(record)?;

        Ok(DecryptionResult {
            ptext,
            their_identity_key,
            decrypted_on_active: false,
        })
    } else {
        let previous_state_count = || record.archived_sessions().len();
        if let Some(current_state) = record.active_session() {
            log::error!(
                "No valid session for recipient: {}, active session base key {}, \
                 number of archived states: {}",
                remote_address,
                current_state
                    .sender_ratchet_key_for_logging()
                    .unwrap_or_else(|e| format!("<error: {e}>")),
                previous_state_count(),
            );
        } else {
            log::error!(
                "No valid session for recipient: {}, (no active session), \
                 number of archived states: {}",
                remote_address,
                previous_state_count(),
            );
        }
        log::error!(
            "{}",
            format_decryption_failure_log(remote_address, &errs, record, ciphertext)?
        );
        Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::Whisper,
            "decryption failed".to_owned(),
        ))
    }
}

// ── Per-session decrypt ──────────────────────────────────────────────────────

/// Attempt to decrypt `ciphertext` using the crypto state in `state`.
///
/// Constructs a [`TripleRatchet`], delegates the actual decryption,
/// and writes updated state back on success. On failure, `state` is unchanged.
pub(crate) fn try_decrypt_with_session<R: Rng + CryptoRng>(
    state: &mut SessionState,
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    ciphertext: &SignalMessage,
    original_message_type: CiphertextMessageType,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    let ciphertext_version = ciphertext.message_version() as u32;
    if state.session_version()? != ciphertext_version {
        // find_session_by_id matches on the session ID (the base key) alone, so
        // a message whose version differs from the stored session's can reach
        // here. Fail closed rather than feed mismatched-version material into the
        // ratchet.
        return Err(SignalProtocolError::UnrecognizedMessageVersion(
            ciphertext_version,
        ));
    }

    let self_session = try_scoped::<bool, InvalidSessionError>(|| {
        Ok(state.local_identity_key()?.is_same_account(
            local_address,
            &state
                .remote_identity_key()?
                .ok_or(InvalidSessionError("missing remote identity key"))?,
            remote_address,
        ))
    })
    .inspect_err(|e| log::warn!("Failed to determine self_session: {}", e))
    .unwrap_or_default();
    let mut session = TripleRatchet::from_session_state(state, self_session)?;

    let ptext = session.decrypt(
        remote_address,
        local_address,
        ciphertext,
        original_message_type,
        csprng,
    )?;

    session.apply_to_session_state(state);

    Ok(ptext)
}

// ── Logging helpers ──────────────────────────────────────────────────────────

pub(crate) fn format_decryption_failure_log(
    remote_address: &ProtocolAddress,
    mut errs: &[SignalProtocolError],
    record: &SessionRecord,
    ciphertext: &SignalMessage,
) -> Result<String> {
    fn append_session_summary(
        lines: &mut Vec<String>,
        idx: usize,
        state: std::result::Result<&SessionState, InvalidSessionError>,
        err: Option<&SignalProtocolError>,
    ) {
        let chains = state.map(|state| state.all_receiver_chain_logging_info());
        match (err, &chains) {
            (Some(err), Ok(chains)) => {
                lines.push(format!(
                    "Candidate session {} failed with '{}', had {} receiver chains",
                    idx,
                    err,
                    chains.len()
                ));
            }
            (Some(err), Err(state_err)) => {
                lines.push(format!(
                    "Candidate session {idx} failed with '{err}'; \
                     cannot get receiver chain info ({state_err})",
                ));
            }
            (None, Ok(chains)) => {
                lines.push(format!(
                    "Candidate session {} had {} receiver chains",
                    idx,
                    chains.len()
                ));
            }
            (None, Err(state_err)) => {
                lines.push(format!(
                    "Candidate session {idx}: cannot get receiver chain info ({state_err})",
                ));
            }
        }

        if let Ok(chains) = chains {
            for chain in chains {
                let chain_idx = match chain.1 {
                    Some(i) => i.to_string(),
                    None => "missing in protobuf".to_string(),
                };
                lines.push(format!(
                    "Receiver chain with sender ratchet public key {} chain key index {}",
                    hex::encode(chain.0),
                    chain_idx
                ));
            }
        }
    }

    let mut lines = vec![];
    lines.push(format!(
        "Message from {} failed to decrypt; sender ratchet public key {} message counter {}",
        remote_address,
        hex::encode(ciphertext.sender_ratchet_key().public_key_bytes()),
        ciphertext.counter()
    ));

    if let Some(current_session) = record.active_session() {
        let err = errs.first();
        if err.is_some() {
            errs = &errs[1..];
        }
        append_session_summary(&mut lines, 0, Ok(current_session), err);
    } else {
        lines.push("No current session".to_string());
    }

    for (idx, (state, err)) in record
        .archived_sessions()
        .zip(errs.iter().map(Some).chain(std::iter::repeat(None)))
        .enumerate()
    {
        let state = match state {
            Ok(ref state) => Ok(state),
            Err(err) => Err(err),
        };
        append_session_summary(&mut lines, idx + 1, state, err);
    }

    Ok(lines.join("\n"))
}
