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
//! 2. **Sesame session management** — the "which session do we use?" logic:
//!    trial-decryption across current and previous sessions, session promotion
//!    on success, and session selection for encryption.
//!
//! All cryptographic ratchet operations are delegated to
//! [`TripleRatchet`]. This module has no knowledge of chain keys,
//! root keys, or SPQR internals.

use std::time::SystemTime;

use displaydoc::Display;
use libsignal_core::try_scoped;
use rand::{CryptoRng, Rng};

use crate::consts::MAX_UNACKNOWLEDGED_SESSION_AGE;
use crate::state::{InvalidSessionError, SessionState};
use crate::triple_ratchet::{OutgoingTripleRatchet, TripleRatchet};
use crate::{
    CiphertextMessage, CiphertextMessageType, Direction, IdentityKeyStore, KyberPayload,
    KyberPreKeyStore, PreKeySignalMessage, PreKeyStore, ProtocolAddress, Result, SessionRecord,
    SessionStore, SignalMessage, SignalProtocolError, SignedPreKeyStore, session,
};

// ── Public API ───────────────────────────────────────────────────────────────

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
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;
    let session_state = session_record
        .session_state_mut()
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;

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
            return Err(SignalProtocolError::SessionNotFound(remote_address.clone()));
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
        CiphertextMessage::PreKeySignalMessage(m) => {
            message_decrypt_prekey(
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
        }
        _ => Err(SignalProtocolError::InvalidArgument(format!(
            "message_decrypt cannot be used to decrypt {:?} messages",
            ciphertext.message_type()
        ))),
    }
}

/// Decrypt a [`PreKeySignalMessage`] from `remote_address`.
///
/// Processes the pre-key material to establish a session (via
/// [`session::process_prekey`]), then decrypts the inner [`SignalMessage`].
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
) -> Result<Vec<u8>> {
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    // Make sure we log the session state if we fail to process the pre-key.
    let process_prekey_result = session::process_prekey(
        ciphertext,
        remote_address,
        local_address,
        &mut session_record,
        identity_store,
        pre_key_store,
        signed_pre_key_store,
        kyber_pre_key_store,
    )
    .await;

    let (pre_key_used, identity_to_save) = match process_prekey_result {
        Ok(result) => result,
        Err(e) => {
            let errs = [e];
            log::error!(
                "{}",
                format_decryption_failure_log(
                    remote_address,
                    &errs,
                    &session_record,
                    ciphertext.message()
                )?
            );
            let [e] = errs;
            return Err(e);
        }
    };

    let ptext = try_decrypt_from_record(
        &mut session_record,
        remote_address,
        local_address,
        ciphertext.message(),
        CiphertextMessageType::PreKey,
        csprng,
    )?;

    identity_store
        .save_identity(
            identity_to_save.remote_address,
            identity_to_save.their_identity_key,
        )
        .await?;

    if let Some(pre_key_used) = pre_key_used {
        if let Some(kyber_pre_key_id) = pre_key_used.kyber_pre_key_id {
            kyber_pre_key_store
                .mark_kyber_pre_key_used(
                    kyber_pre_key_id,
                    pre_key_used.signed_ec_pre_key_id,
                    ciphertext.base_key(),
                )
                .await?;
        }

        if let Some(pre_key_id) = pre_key_used.one_time_ec_pre_key_id {
            pre_key_store.remove_pre_key(pre_key_id).await?;
        }
    }

    session_store
        .store_session(remote_address, &session_record)
        .await?;

    Ok(ptext)
}

/// Decrypt a [`SignalMessage`] from `remote_address`.
///
/// Tries all sessions in the session record. Checks identity key trust
/// after decryption.
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
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;

    let ptext = try_decrypt_from_record(
        &mut session_record,
        remote_address,
        local_address,
        ciphertext,
        CiphertextMessageType::Whisper,
        csprng,
    )?;

    // Why are we performing this check after decryption instead of before?
    let their_identity_key = session_record
        .session_state()
        .expect("successfully decrypted; must have a current state")
        .remote_identity_key()
        .expect("successfully decrypted; must have a remote identity key")
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

    identity_store
        .save_identity(remote_address, &their_identity_key)
        .await?;

    session_store
        .store_session(remote_address, &session_record)
        .await?;

    Ok(ptext)
}

// ── Session management (Sesame) ──────────────────────────────────────────────

/// Try to decrypt `ciphertext` against every session in `record`, in order.
///
/// Tries the current session first, then previous sessions. On success from
/// a previous session, promotes that session to current (Sesame behavior).
///
/// `original_message_type` is `Whisper` for normal messages and `PreKey` for
/// the inner `SignalMessage` of a pre-key message. When it is `PreKey`, we
/// skip the fallback to previous sessions — a PreKey message establishes a
/// fresh session and should always match the current one.
pub(crate) fn try_decrypt_from_record<R: Rng + CryptoRng>(
    record: &mut SessionRecord,
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    ciphertext: &SignalMessage,
    original_message_type: CiphertextMessageType,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    debug_assert!(matches!(
        original_message_type,
        CiphertextMessageType::Whisper | CiphertextMessageType::PreKey
    ));
    let ciphertext_version = ciphertext.message_version() as u32;

    let log_failure = |label: &str, state: &SessionState, error: &SignalProtocolError| {
        log::warn!(
            "Failed to decrypt {:?} message with ratchet key: {} and counter: {}. \
             Session loaded for {}. {} session has base key: {} and counter: {}. {}",
            original_message_type,
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

    // ── Try current session ──────────────────────────────────────────────────

    if let Some(current_state) = record.session_state() {
        let mut current_state = current_state.clone();

        if current_state.session_version()? != ciphertext_version {
            let e = SignalProtocolError::UnrecognizedMessageVersion(ciphertext_version);
            log_failure("Current", &current_state, &e);
            errs.push(e);
        } else {
            match try_decrypt_with_state(
                &mut current_state,
                remote_address,
                local_address,
                ciphertext,
                original_message_type,
                CurrentOrPrevious::Current,
                csprng,
            ) {
                Ok(ptext) => {
                    log::info!(
                        "decrypted {:?} message from {} with current session state (base key {})",
                        original_message_type,
                        remote_address,
                        current_state
                            .sender_ratchet_key_for_logging()
                            .expect("successful decrypt always has a valid base key"),
                    );
                    record.set_session_state(current_state);
                    return Ok(ptext);
                }
                Err(e @ SignalProtocolError::DuplicatedMessage(_, _)) => return Err(e),
                Err(e) => {
                    log_failure("Current", &current_state, &e);
                    errs.push(e);
                    match original_message_type {
                        CiphertextMessageType::PreKey => {
                            // A PreKey message creates a session and then decrypts a Whisper message
                            // using that session. No need to check older sessions.
                            log::error!(
                                "{}",
                                format_decryption_failure_log(
                                    remote_address,
                                    &errs,
                                    record,
                                    ciphertext,
                                )?
                            );
                            // Note that we don't propagate `e` here; we always return InvalidMessage,
                            // as we would for a Whisper message that tried several sessions.
                            return Err(SignalProtocolError::InvalidMessage(
                                original_message_type,
                                "decryption failed",
                            ));
                        }
                        CiphertextMessageType::Whisper => {}
                        CiphertextMessageType::SenderKey | CiphertextMessageType::Plaintext => {
                            unreachable!("should not be using Double Ratchet for these")
                        }
                    }
                }
            }
        }
    }

    // ── Try previous sessions (Whisper only) ─────────────────────────────────

    let mut promoted = None;

    for (idx, previous) in record.previous_session_states().enumerate() {
        let mut previous = match previous {
            Ok(previous) => previous,
            Err(e) => {
                let e: SignalProtocolError = e.into();
                log::warn!(
                    "Skipping corrupt previous session {} for {}: {}",
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
            log_failure("Previous", &previous, &e);
            errs.push(e);
            continue;
        }

        match try_decrypt_with_state(
            &mut previous,
            remote_address,
            local_address,
            ciphertext,
            original_message_type,
            CurrentOrPrevious::Previous,
            csprng,
        ) {
            Ok(ptext) => {
                log::info!(
                    "decrypted {:?} message from {} with PREVIOUS session state (base key {})",
                    original_message_type,
                    remote_address,
                    previous
                        .sender_ratchet_key_for_logging()
                        .expect("successful decrypt always has a valid base key"),
                );
                promoted = Some((ptext, idx, previous));
                break;
            }
            Err(e @ SignalProtocolError::DuplicatedMessage(_, _)) => return Err(e),
            Err(e) => {
                log_failure("Previous", &previous, &e);
                errs.push(e);
            }
        }
    }

    if let Some((ptext, idx, updated)) = promoted {
        // Sesame: promote the successful previous session to current.
        // The upcoming session management update will remove this promotion.
        record.promote_old_session(idx, updated);
        Ok(ptext)
    } else {
        let previous_state_count = || record.previous_session_states().len();
        if let Some(current_state) = record.session_state() {
            log::error!(
                "No valid session for recipient: {}, current session base key {}, \
                 number of previous states: {}",
                remote_address,
                current_state
                    .sender_ratchet_key_for_logging()
                    .unwrap_or_else(|e| format!("<error: {e}>")),
                previous_state_count(),
            );
        } else {
            log::error!(
                "No valid session for recipient: {}, (no current session state), \
                 number of previous states: {}",
                remote_address,
                previous_state_count(),
            );
        }
        log::error!(
            "{}",
            format_decryption_failure_log(remote_address, &errs, record, ciphertext)?
        );
        Err(SignalProtocolError::InvalidMessage(
            original_message_type,
            "decryption failed",
        ))
    }
}

// ── Per-session decrypt ──────────────────────────────────────────────────────

/// Attempt to decrypt `ciphertext` using the crypto state in `state`.
///
/// Caller must only pass version-compatible ciphertext/session pairs.
///
/// Constructs a [`TripleRatchet`], delegates the actual decryption, and writes
/// updated state back on success. On failure, `state` is unchanged.
pub(crate) fn try_decrypt_with_state<R: Rng + CryptoRng>(
    state: &mut SessionState,
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    ciphertext: &SignalMessage,
    original_message_type: CiphertextMessageType,
    curr_or_prev_for_logging: CurrentOrPrevious,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    debug_assert_eq!(
        state.session_version()?,
        ciphertext.message_version() as u32
    );

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
        curr_or_prev_for_logging,
        csprng,
    )?;

    session.apply_to_session_state(state);
    state.clear_unacknowledged_pre_key_message();

    Ok(ptext)
}

// ── Logging helpers ──────────────────────────────────────────────────────────

pub(crate) fn format_decryption_failure_log(
    remote_address_for_logging: &ProtocolAddress,
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
        remote_address_for_logging,
        hex::encode(ciphertext.sender_ratchet_key().public_key_bytes()),
        ciphertext.counter()
    ));

    if let Some(current_session) = record.session_state() {
        let err = errs.first();
        if err.is_some() {
            errs = &errs[1..];
        }
        append_session_summary(&mut lines, 0, Ok(current_session), err);
    } else {
        lines.push("No current session".to_string());
    }

    for (idx, (state, err)) in record
        .previous_session_states()
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

#[derive(Clone, Copy, Display)]
pub(crate) enum CurrentOrPrevious {
    /// current
    Current,
    /// previous
    Previous,
}

// ── Comparison proptest ──────────────────────────────────────────────────────
//
// Verifies that the refactored encrypt/decrypt path produces identical results
// to the legacy snapshot for any message sequence.
#[cfg(test)]
mod legacy_interop_tests {
    // These tests live next to `session_management` rather than under
    // `rust/protocol/tests/` because they compare the refactored code against
    // the private `session_cipher_legacy` implementation and also assert
    // byte-level equivalence of internal persisted state. That makes them
    // implementation-regression tests for this refactor, not normal public API
    // integration tests.
    //
    // This harness is temporary. Once we are confident in the refactor, remove
    // `session_cipher_legacy` and the new-vs-legacy equivalence tests along
    // with it.
    use futures_util::FutureExt;
    use libsignal_protocol_test_support::Event;
    use proptest::prelude::*;
    use prost::Message;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::proto::storage::RecordStructure;
    use crate::ratchet::{
        AliceSignalProtocolParameters, BobSignalProtocolParameters,
        initialize_alice_session_record, initialize_bob_session_record,
    };
    use crate::{
        DecryptionErrorMessage, DeviceId, GenericSignedPreKey, IdentityKeyPair,
        InMemSignalProtocolStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord, PlaintextContent,
        PreKeyBundle, PreKeyId, PreKeyRecord, ProtocolAddress, SessionRecord,
        SessionUsabilityRequirements, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
        Timestamp, extract_decryption_error_message_from_serialized_content, process_prekey_bundle,
        session_cipher_legacy as legacy,
    };

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum MessageStatus {
        Sent,
        Dropped,
        Delivered,
    }

    #[derive(Clone)]
    struct DualLocalState {
        new_store: InMemSignalProtocolStore,
        legacy_store: InMemSignalProtocolStore,
        pre_key_count: u32,
    }

    struct DualParticipant {
        address: ProtocolAddress,
        message_queue: Vec<(CiphertextMessage, u64)>,
        state: DualLocalState,
        snapshots: Vec<DualLocalState>,
        message_send_log: Vec<MessageStatus>,
    }

    /// Build a matched (alice, bob) session pair from a seeded RNG.
    fn setup_stores(
        rng: &mut ChaCha8Rng,
    ) -> (
        InMemSignalProtocolStore,
        InMemSignalProtocolStore,
        ProtocolAddress,
        ProtocolAddress,
    ) {
        let alice_identity = IdentityKeyPair::generate(rng);
        let bob_identity = IdentityKeyPair::generate(rng);

        let alice_base_key = KeyPair::generate(rng);
        let bob_signed_pre_key = KeyPair::generate(rng);
        let bob_kyber_key = crate::kem::KeyPair::generate(crate::kem::KeyType::Kyber1024, rng);

        let alice_params = AliceSignalProtocolParameters::new(
            alice_identity,
            alice_base_key,
            *bob_identity.identity_key(),
            bob_signed_pre_key.public_key,
            bob_signed_pre_key.public_key,
            bob_kyber_key.public_key.clone(),
            false,
        );

        let alice_record =
            initialize_alice_session_record(&alice_params, rng).expect("alice session init");
        let kyber_ct: Box<[u8]> = alice_record
            .get_kyber_ciphertext()
            .expect("session valid")
            .expect("has kyber ciphertext")
            .clone()
            .into_boxed_slice();

        let bob_params = BobSignalProtocolParameters::new(
            bob_identity,
            bob_signed_pre_key,
            None,
            bob_kyber_key,
            *alice_identity.identity_key(),
            alice_base_key.public_key,
            &kyber_ct,
            false,
        );

        let bob_record = initialize_bob_session_record(&bob_params, &bob_signed_pre_key)
            .expect("bob session init");

        let alice_address = ProtocolAddress::new(
            "57721566-4901-5328-6060-651209008240".to_owned(),
            DeviceId::new(1).unwrap(),
        );
        let bob_address = ProtocolAddress::new(
            "26149721-2847-6427-8375-542683860869".to_owned(),
            DeviceId::new(1).unwrap(),
        );

        let mut alice_store = InMemSignalProtocolStore::new(alice_identity, 1).unwrap();
        let mut bob_store = InMemSignalProtocolStore::new(bob_identity, 2).unwrap();

        alice_store
            .session_store
            .store_session(&bob_address, &alice_record)
            .now_or_never()
            .unwrap()
            .unwrap();
        bob_store
            .session_store
            .store_session(&alice_address, &bob_record)
            .now_or_never()
            .unwrap()
            .unwrap();

        (alice_store, bob_store, alice_address, bob_address)
    }

    /// Create a pre-key bundle for Bob, storing new key material in his store.
    ///
    /// The `*_id` parameters must not collide with any IDs already in the
    /// store. Using a monotonically increasing generation counter (1, 2, …)
    /// is sufficient.
    fn create_bob_bundle(
        bob_store: &mut InMemSignalProtocolStore,
        pre_key_id: u32,
        signed_pre_key_id: u32,
        kyber_pre_key_id: u32,
        rng: &mut ChaCha8Rng,
    ) -> PreKeyBundle {
        let identity_key_pair = bob_store
            .get_identity_key_pair()
            .now_or_never()
            .unwrap()
            .unwrap();

        let pre_key = KeyPair::generate(rng);
        let signed_pre_key = KeyPair::generate(rng);
        let kyber_key = crate::kem::KeyPair::generate(crate::kem::KeyType::Kyber1024, rng);

        let pk_id = PreKeyId::from(pre_key_id);
        let spk_id = SignedPreKeyId::from(signed_pre_key_id);
        let kpk_id = KyberPreKeyId::from(kyber_pre_key_id);

        let spk_sig = identity_key_pair
            .private_key()
            .calculate_signature(&signed_pre_key.public_key.serialize(), rng)
            .unwrap();
        let kpk_sig = identity_key_pair
            .private_key()
            .calculate_signature(&kyber_key.public_key.serialize(), rng)
            .unwrap();

        bob_store
            .save_pre_key(pk_id, &PreKeyRecord::new(pk_id, &pre_key))
            .now_or_never()
            .unwrap()
            .unwrap();
        bob_store
            .save_signed_pre_key(
                spk_id,
                &SignedPreKeyRecord::new(
                    spk_id,
                    Timestamp::from_epoch_millis(42),
                    &signed_pre_key,
                    &spk_sig,
                ),
            )
            .now_or_never()
            .unwrap()
            .unwrap();
        bob_store
            .save_kyber_pre_key(
                kpk_id,
                &KyberPreKeyRecord::new(
                    kpk_id,
                    Timestamp::from_epoch_millis(43),
                    &kyber_key,
                    &kpk_sig,
                ),
            )
            .now_or_never()
            .unwrap()
            .unwrap();

        let reg_id = bob_store
            .get_local_registration_id()
            .now_or_never()
            .unwrap()
            .unwrap();

        PreKeyBundle::new(
            reg_id,
            DeviceId::new(1).unwrap(),
            Some((pk_id, pre_key.public_key)),
            spk_id,
            signed_pre_key.public_key,
            spk_sig.to_vec(),
            kpk_id,
            kyber_key.public_key.clone(),
            kpk_sig.to_vec(),
            *identity_key_pair.identity_key(),
        )
        .unwrap()
    }

    #[test]
    fn encrypt_preserves_corruption_error_instead_of_session_not_found() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xC0FFEE);
        let (mut alice_store, _bob_store, alice_address, bob_address) = setup_stores(&mut rng);
        let now = SystemTime::now();

        let good_record = alice_store
            .session_store
            .load_session(&bob_address)
            .now_or_never()
            .expect("sync")
            .expect("load succeeded")
            .expect("session exists");

        let serialized = good_record.serialize().expect("serialize");
        let mut record_pb = RecordStructure::decode(serialized.as_slice()).expect("decode record");
        record_pb
            .current_session
            .as_mut()
            .expect("current session")
            .remote_identity_public = vec![0xFF];

        let corrupted_record = SessionRecord::deserialize(record_pb.encode_to_vec().as_slice())
            .expect("deserialize corrupted record");

        alice_store
            .session_store
            .store_session(&bob_address, &corrupted_record)
            .now_or_never()
            .expect("sync")
            .expect("store succeeded");

        let legacy_err = legacy::legacy_message_encrypt(
            b"test",
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            now,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect_err("legacy encrypt should fail on corrupted state");
        assert!(
            matches!(
                legacy_err,
                SignalProtocolError::InvalidSessionStructure("invalid remote identity key")
            ),
            "unexpected legacy error: {legacy_err:?}"
        );

        alice_store
            .session_store
            .store_session(&bob_address, &corrupted_record)
            .now_or_never()
            .expect("sync")
            .expect("store succeeded");

        let new_err = message_encrypt(
            b"test",
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            now,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect_err("new encrypt should fail on corrupted state");
        assert!(
            matches!(
                new_err,
                SignalProtocolError::InvalidSessionStructure("invalid remote identity key")
            ),
            "unexpected new error: {new_err:?}"
        );
    }

    #[test]
    fn encrypt_ignores_corrupt_unused_receiver_chain() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xACE55);
        let (mut alice_store, _bob_store, alice_address, bob_address) = setup_stores(&mut rng);
        let now = SystemTime::now();

        let good_record = alice_store
            .session_store
            .load_session(&bob_address)
            .now_or_never()
            .expect("sync")
            .expect("load succeeded")
            .expect("session exists");

        let serialized = good_record.serialize().expect("serialize");
        let mut record_pb = RecordStructure::decode(serialized.as_slice()).expect("decode record");
        let current_session = record_pb.current_session.as_mut().expect("current session");
        assert!(
            !current_session.receiver_chains.is_empty(),
            "expected at least one receiver chain"
        );
        current_session.receiver_chains[0].sender_ratchet_key = vec![0xFF];

        let corrupted_record = SessionRecord::deserialize(record_pb.encode_to_vec().as_slice())
            .expect("deserialize corrupted record");

        alice_store
            .session_store
            .store_session(&bob_address, &corrupted_record)
            .now_or_never()
            .expect("sync")
            .expect("store succeeded");

        let mut legacy_rng = rng.clone();
        let legacy_ct = legacy::legacy_message_encrypt(
            b"test",
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            now,
            &mut legacy_rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("legacy encrypt should ignore unused receiver-chain corruption");

        alice_store
            .session_store
            .store_session(&bob_address, &corrupted_record)
            .now_or_never()
            .expect("sync")
            .expect("store succeeded");

        let new_ct = message_encrypt(
            b"test",
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            now,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("new encrypt should ignore unused receiver-chain corruption");

        let legacy_msg = match legacy_ct {
            CiphertextMessage::SignalMessage(m) => m,
            other => panic!(
                "expected SignalMessage from legacy enc, got {:?}",
                other.message_type()
            ),
        };
        let new_msg = match new_ct {
            CiphertextMessage::SignalMessage(m) => m,
            other => panic!(
                "expected SignalMessage from new enc, got {:?}",
                other.message_type()
            ),
        };

        assert_eq!(legacy_msg.serialized(), new_msg.serialized());
    }

    #[test]
    fn decrypt_skips_corrupt_previous_session_and_uses_later_valid_previous() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xBAD5EED);
        let (mut alice_store, mut bob_store, alice_address, bob_address) = setup_stores(&mut rng);
        let now = SystemTime::now();

        let delayed_plaintext = b"delayed on session A".to_vec();

        let delayed_ct = legacy::legacy_message_encrypt(
            &delayed_plaintext,
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            now,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("delayed legacy enc");

        let delayed_signal_msg = match delayed_ct {
            CiphertextMessage::SignalMessage(m) => m,
            other => panic!(
                "expected SignalMessage for delayed msg, got {:?}",
                other.message_type()
            ),
        };

        let bundle = create_bob_bundle(&mut bob_store, 1, 1, 1, &mut rng);
        process_prekey_bundle(
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bundle,
            now,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("process_prekey_bundle");

        let session_b_init = message_encrypt(
            b"session B init",
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            now,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("session B init enc");

        message_decrypt(
            &session_b_init,
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &mut bob_store.pre_key_store,
            &bob_store.signed_pre_key_store,
            &mut bob_store.kyber_pre_key_store,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("session B init dec");

        let session_b_ack = message_encrypt(
            b"session B ack",
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            now,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("session B ack enc");

        let session_b_ack_signal = match &session_b_ack {
            CiphertextMessage::SignalMessage(m) => m,
            other => panic!(
                "expected Whisper for session B ack, got {:?}",
                other.message_type()
            ),
        };
        message_decrypt_signal(
            session_b_ack_signal,
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("session B ack dec");

        let bob_record = bob_store
            .session_store
            .load_session(&alice_address)
            .now_or_never()
            .expect("sync")
            .expect("load succeeded")
            .expect("session exists");
        let serialized = bob_record.serialize().expect("serialize");
        let mut record_pb = RecordStructure::decode(serialized.as_slice()).expect("decode record");
        assert_eq!(
            record_pb.previous_sessions.len(),
            1,
            "expected one valid previous session"
        );
        record_pb.previous_sessions.insert(0, vec![0xFF]);
        let corrupted_record = SessionRecord::deserialize(record_pb.encode_to_vec().as_slice())
            .expect("deserialize mutated record");
        bob_store
            .session_store
            .store_session(&alice_address, &corrupted_record)
            .now_or_never()
            .expect("sync")
            .expect("store succeeded");

        let ptext = message_decrypt_signal(
            &delayed_signal_msg,
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("delayed msg dec via valid later previous session");

        assert_eq!(ptext, delayed_plaintext);
    }

    fn setup_two_alice_receiver_chains_on_bob(
        rng: &mut ChaCha8Rng,
    ) -> (
        InMemSignalProtocolStore,
        InMemSignalProtocolStore,
        ProtocolAddress,
        ProtocolAddress,
        SignalMessage,
    ) {
        let (mut alice_store, mut bob_store, alice_address, bob_address) = setup_stores(rng);
        let now = SystemTime::now();

        let delayed_ct = message_encrypt(
            b"delayed old",
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            now,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("delayed old enc");
        let delayed_signal_msg = match delayed_ct {
            CiphertextMessage::SignalMessage(m) => m,
            other => panic!(
                "expected delayed SignalMessage, got {:?}",
                other.message_type()
            ),
        };

        let trigger_ct = message_encrypt(
            b"trigger old chain advancement",
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            now,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("trigger enc");
        let trigger_signal_msg = match trigger_ct {
            CiphertextMessage::SignalMessage(m) => m,
            other => panic!(
                "expected trigger SignalMessage, got {:?}",
                other.message_type()
            ),
        };
        message_decrypt_signal(
            &trigger_signal_msg,
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("trigger dec");

        let bob_reply_ct = message_encrypt(
            b"bob reply new ratchet",
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            now,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("bob reply enc");
        let bob_reply_signal_msg = match bob_reply_ct {
            CiphertextMessage::SignalMessage(m) => m,
            other => panic!(
                "expected bob reply SignalMessage, got {:?}",
                other.message_type()
            ),
        };
        message_decrypt_signal(
            &bob_reply_signal_msg,
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("bob reply dec");

        let alice_new_chain_ct = message_encrypt(
            b"alice new chain",
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            now,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("alice new chain enc");
        let alice_new_chain_signal_msg = match alice_new_chain_ct {
            CiphertextMessage::SignalMessage(m) => m,
            other => panic!(
                "expected alice new chain SignalMessage, got {:?}",
                other.message_type()
            ),
        };
        message_decrypt_signal(
            &alice_new_chain_signal_msg,
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("alice new chain dec");

        (
            alice_store,
            bob_store,
            alice_address,
            bob_address,
            delayed_signal_msg,
        )
    }

    #[test]
    fn decrypt_ignores_corrupt_unmatched_receiver_chain() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xD311A9);
        let (_alice_store, mut bob_store, alice_address, bob_address, delayed_signal_msg) =
            setup_two_alice_receiver_chains_on_bob(&mut rng);

        let bob_record = bob_store
            .session_store
            .load_session(&alice_address)
            .now_or_never()
            .expect("sync")
            .expect("load succeeded")
            .expect("session exists");
        let serialized = bob_record.serialize().expect("serialize");
        let mut record_pb = RecordStructure::decode(serialized.as_slice()).expect("decode record");
        let current_session = record_pb.current_session.as_mut().expect("current session");
        assert!(
            current_session.receiver_chains.len() >= 2,
            "expected at least two receiver chains"
        );

        let matched_key = delayed_signal_msg.sender_ratchet_key().serialize().to_vec();
        let matched_idx = current_session
            .receiver_chains
            .iter()
            .position(|chain| chain.sender_ratchet_key == matched_key)
            .expect("matching receiver chain present");
        let unmatched_idx = (0..current_session.receiver_chains.len())
            .find(|idx| *idx != matched_idx)
            .expect("unmatched receiver chain present");

        current_session.receiver_chains[unmatched_idx].sender_ratchet_key = vec![0xFF];

        let corrupted_record = SessionRecord::deserialize(record_pb.encode_to_vec().as_slice())
            .expect("deserialize mutated record");
        bob_store
            .session_store
            .store_session(&alice_address, &corrupted_record)
            .now_or_never()
            .expect("sync")
            .expect("store succeeded");

        let ptext = message_decrypt_signal(
            &delayed_signal_msg,
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("decrypt should ignore unmatched corrupt receiver chain");

        assert_eq!(ptext, b"delayed old");
    }

    #[test]
    fn decrypt_fails_on_corrupt_matched_receiver_chain() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xD311AA);
        let (_alice_store, mut bob_store, alice_address, bob_address, delayed_signal_msg) =
            setup_two_alice_receiver_chains_on_bob(&mut rng);

        let bob_record = bob_store
            .session_store
            .load_session(&alice_address)
            .now_or_never()
            .expect("sync")
            .expect("load succeeded")
            .expect("session exists");
        let serialized = bob_record.serialize().expect("serialize");
        let mut record_pb = RecordStructure::decode(serialized.as_slice()).expect("decode record");
        let current_session = record_pb.current_session.as_mut().expect("current session");

        let matched_key = delayed_signal_msg.sender_ratchet_key().serialize().to_vec();
        let matched_idx = current_session
            .receiver_chains
            .iter()
            .position(|chain| chain.sender_ratchet_key == matched_key)
            .expect("matching receiver chain present");
        current_session.receiver_chains[matched_idx]
            .chain_key
            .as_mut()
            .expect("chain key present")
            .key = vec![0xFF];

        let corrupted_record = SessionRecord::deserialize(record_pb.encode_to_vec().as_slice())
            .expect("deserialize mutated record");
        bob_store
            .session_store
            .store_session(&alice_address, &corrupted_record)
            .now_or_never()
            .expect("sync")
            .expect("store succeeded");

        let err = message_decrypt_signal(
            &delayed_signal_msg,
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect_err("decrypt should fail on corrupt matched receiver chain");

        assert!(
            matches!(
                err,
                SignalProtocolError::InvalidMessage(
                    CiphertextMessageType::Whisper,
                    "decryption failed"
                )
            ),
            "unexpected error: {err:?}"
        );
    }

    // ── Dual-path simulation helpers ────────────────────────────────────
    //
    // Run every operation on both the refactored and legacy code paths,
    // asserting identical outputs (ciphertexts, plaintexts, or error
    // variants).  RNG sync follows the same clone-before-each-op pattern
    // as proptest_ciphertext_equality.

    fn assert_store_state_equivalent(
        new_store: &InMemSignalProtocolStore,
        leg_store: &InMemSignalProtocolStore,
        peer_addr: &ProtocolAddress,
        context: &str,
    ) {
        let new_session = new_store
            .session_store
            .load_session(peer_addr)
            .now_or_never()
            .expect("sync")
            .expect("new load session");
        let leg_session = leg_store
            .session_store
            .load_session(peer_addr)
            .now_or_never()
            .expect("sync")
            .expect("legacy load session");

        let new_session_bytes = new_session.map(|record| record.serialize().expect("serialize"));
        let leg_session_bytes = leg_session.map(|record| record.serialize().expect("serialize"));
        assert_eq!(
            new_session_bytes, leg_session_bytes,
            "{context}: session records diverged"
        );

        let new_identity = new_store
            .identity_store
            .get_identity(peer_addr)
            .now_or_never()
            .expect("sync")
            .expect("new load identity")
            .map(|identity| identity.serialize());
        let leg_identity = leg_store
            .identity_store
            .get_identity(peer_addr)
            .now_or_never()
            .expect("sync")
            .expect("legacy load identity")
            .map(|identity| identity.serialize());
        assert_eq!(
            new_identity, leg_identity,
            "{context}: trusted identities diverged"
        );
    }

    /// Encrypt on both paths with cloned RNG. Assert ciphertexts and sender
    /// state are byte-identical.
    fn dual_encrypt(
        plaintext: &[u8],
        recv_addr: &ProtocolAddress,
        send_addr: &ProtocolAddress,
        new_sender: &mut InMemSignalProtocolStore,
        leg_sender: &mut InMemSignalProtocolStore,
        now: SystemTime,
        rng: &mut ChaCha8Rng,
    ) -> SignalMessage {
        let mut leg_rng = rng.clone();

        let new_ct = message_encrypt(
            plaintext,
            recv_addr,
            send_addr,
            &mut new_sender.session_store,
            &mut new_sender.identity_store,
            now,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("new encrypt");

        let leg_ct = legacy::legacy_message_encrypt(
            plaintext,
            recv_addr,
            send_addr,
            &mut leg_sender.session_store,
            &mut leg_sender.identity_store,
            now,
            &mut leg_rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("legacy encrypt");

        assert_eq!(
            new_ct.serialize(),
            leg_ct.serialize(),
            "new and legacy produced different ciphertexts"
        );
        assert_eq!(
            new_ct.message_type(),
            leg_ct.message_type(),
            "new and legacy produced different ciphertext types"
        );
        assert_store_state_equivalent(new_sender, leg_sender, recv_addr, "encrypt");

        match new_ct {
            CiphertextMessage::SignalMessage(m) => m,
            other => panic!(
                "expected SignalMessage from dual_encrypt, got {:?}",
                other.message_type()
            ),
        }
    }

    /// Encrypt on both paths with cloned RNG. Assert full ciphertext
    /// equivalence, including `PreKeySignalMessage`.
    fn dual_encrypt_any(
        plaintext: &[u8],
        recv_addr: &ProtocolAddress,
        send_addr: &ProtocolAddress,
        new_sender: &mut InMemSignalProtocolStore,
        leg_sender: &mut InMemSignalProtocolStore,
        now: SystemTime,
        rng: &mut ChaCha8Rng,
    ) -> CiphertextMessage {
        let mut leg_rng = rng.clone();

        let new_ct = message_encrypt(
            plaintext,
            recv_addr,
            send_addr,
            &mut new_sender.session_store,
            &mut new_sender.identity_store,
            now,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("new encrypt");

        let leg_ct = legacy::legacy_message_encrypt(
            plaintext,
            recv_addr,
            send_addr,
            &mut leg_sender.session_store,
            &mut leg_sender.identity_store,
            now,
            &mut leg_rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("legacy encrypt");

        assert_eq!(
            new_ct.serialize(),
            leg_ct.serialize(),
            "new and legacy produced different ciphertexts"
        );
        assert_eq!(
            new_ct.message_type(),
            leg_ct.message_type(),
            "new and legacy produced different ciphertext types"
        );
        assert_store_state_equivalent(new_sender, leg_sender, recv_addr, "encrypt");
        new_ct
    }

    /// Decrypt on both paths with cloned RNG. Assert plaintexts and receiver
    /// state match.
    fn dual_decrypt(
        msg: &SignalMessage,
        sender_addr: &ProtocolAddress,
        recv_addr: &ProtocolAddress,
        new_receiver: &mut InMemSignalProtocolStore,
        leg_receiver: &mut InMemSignalProtocolStore,
        rng: &mut ChaCha8Rng,
    ) -> Vec<u8> {
        let mut leg_rng = rng.clone();

        let new_pt = message_decrypt_signal(
            msg,
            sender_addr,
            recv_addr,
            &mut new_receiver.session_store,
            &mut new_receiver.identity_store,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("new decrypt");

        let leg_pt = legacy::legacy_message_decrypt_signal(
            msg,
            sender_addr,
            &mut leg_receiver.session_store,
            &mut leg_receiver.identity_store,
            &mut leg_rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("legacy decrypt");

        assert_eq!(
            new_pt, leg_pt,
            "new and legacy produced different plaintexts"
        );
        assert_store_state_equivalent(new_receiver, leg_receiver, sender_addr, "decrypt");
        new_pt
    }

    /// Decrypt any ciphertext on both paths with cloned RNG. Assert
    /// plaintexts and receiver-side state match.
    fn dual_decrypt_any(
        msg: &CiphertextMessage,
        sender_addr: &ProtocolAddress,
        receiver_addr: &ProtocolAddress,
        new_receiver: &mut InMemSignalProtocolStore,
        leg_receiver: &mut InMemSignalProtocolStore,
        rng: &mut ChaCha8Rng,
    ) -> Vec<u8> {
        let mut leg_rng = rng.clone();

        let new_pt = message_decrypt(
            msg,
            sender_addr,
            receiver_addr,
            &mut new_receiver.session_store,
            &mut new_receiver.identity_store,
            &mut new_receiver.pre_key_store,
            &new_receiver.signed_pre_key_store,
            &mut new_receiver.kyber_pre_key_store,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("new decrypt");

        let leg_pt = legacy::legacy_message_decrypt(
            msg,
            sender_addr,
            receiver_addr,
            &mut leg_receiver.session_store,
            &mut leg_receiver.identity_store,
            &mut leg_receiver.pre_key_store,
            &leg_receiver.signed_pre_key_store,
            &mut leg_receiver.kyber_pre_key_store,
            &mut leg_rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("legacy decrypt");

        assert_eq!(
            new_pt, leg_pt,
            "new and legacy produced different plaintexts"
        );
        assert_store_state_equivalent(new_receiver, leg_receiver, sender_addr, "decrypt");
        new_pt
    }

    fn dual_decrypt_any_result(
        msg: &CiphertextMessage,
        sender_addr: &ProtocolAddress,
        receiver_addr: &ProtocolAddress,
        new_receiver: &mut InMemSignalProtocolStore,
        leg_receiver: &mut InMemSignalProtocolStore,
        rng: &mut ChaCha8Rng,
    ) -> Result<Vec<u8>> {
        let mut leg_rng = rng.clone();

        let new_result = message_decrypt(
            msg,
            sender_addr,
            receiver_addr,
            &mut new_receiver.session_store,
            &mut new_receiver.identity_store,
            &mut new_receiver.pre_key_store,
            &new_receiver.signed_pre_key_store,
            &mut new_receiver.kyber_pre_key_store,
            rng,
        )
        .now_or_never()
        .expect("sync");

        let leg_result = legacy::legacy_message_decrypt(
            msg,
            sender_addr,
            receiver_addr,
            &mut leg_receiver.session_store,
            &mut leg_receiver.identity_store,
            &mut leg_receiver.pre_key_store,
            &leg_receiver.signed_pre_key_store,
            &mut leg_receiver.kyber_pre_key_store,
            &mut leg_rng,
        )
        .now_or_never()
        .expect("sync");

        match (new_result, leg_result) {
            (Ok(new_pt), Ok(leg_pt)) => {
                assert_eq!(
                    new_pt, leg_pt,
                    "new and legacy produced different plaintexts"
                );
                assert_store_state_equivalent(new_receiver, leg_receiver, sender_addr, "decrypt");
                Ok(new_pt)
            }
            (Err(new_err), Err(leg_err)) => {
                assert_eq!(
                    std::mem::discriminant(&new_err),
                    std::mem::discriminant(&leg_err),
                    "error variants differ: new={new_err:?}, legacy={leg_err:?}"
                );
                assert_store_state_equivalent(new_receiver, leg_receiver, sender_addr, "decrypt");
                Err(new_err)
            }
            (new_result, leg_result) => panic!(
                "new and legacy disagreed on decrypt result: new={new_result:?}, legacy={leg_result:?}"
            ),
        }
    }

    /// Decrypt on both paths, assert both fail with the same error variant.
    fn dual_decrypt_expect_err(
        msg: &SignalMessage,
        sender_addr: &ProtocolAddress,
        recv_addr: &ProtocolAddress,
        new_receiver: &mut InMemSignalProtocolStore,
        leg_receiver: &mut InMemSignalProtocolStore,
        rng: &mut ChaCha8Rng,
    ) -> SignalProtocolError {
        let mut leg_rng = rng.clone();

        let new_err = message_decrypt_signal(
            msg,
            sender_addr,
            recv_addr,
            &mut new_receiver.session_store,
            &mut new_receiver.identity_store,
            rng,
        )
        .now_or_never()
        .expect("sync")
        .expect_err("expected new decrypt to fail");

        let leg_err = legacy::legacy_message_decrypt_signal(
            msg,
            sender_addr,
            &mut leg_receiver.session_store,
            &mut leg_receiver.identity_store,
            &mut leg_rng,
        )
        .now_or_never()
        .expect("sync")
        .expect_err("expected legacy decrypt to fail");

        assert_eq!(
            std::mem::discriminant(&new_err),
            std::mem::discriminant(&leg_err),
            "error variants differ: new={new_err:?}, legacy={leg_err:?}"
        );
        new_err
    }

    // ── DualSession convenience wrapper ─────────────────────────────────

    /// Paired new+legacy session state for readable scenario tests.
    struct DualSession {
        na: InMemSignalProtocolStore,
        nb: InMemSignalProtocolStore,
        la: InMemSignalProtocolStore,
        lb: InMemSignalProtocolStore,
        alice: ProtocolAddress,
        bob: ProtocolAddress,
        rng: ChaCha8Rng,
        now: SystemTime,
    }

    impl DualSession {
        fn new(seed: u64) -> Self {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let (na, nb, alice, bob) = setup_stores(&mut rng);
            let (la, lb) = (na.clone(), nb.clone());
            Self {
                na,
                nb,
                la,
                lb,
                alice,
                bob,
                rng,
                now: SystemTime::now(),
            }
        }

        fn alice_sends(&mut self, plaintext: &[u8]) -> SignalMessage {
            dual_encrypt(
                plaintext,
                &self.bob,
                &self.alice,
                &mut self.na,
                &mut self.la,
                self.now,
                &mut self.rng,
            )
        }

        fn bob_sends(&mut self, plaintext: &[u8]) -> SignalMessage {
            dual_encrypt(
                plaintext,
                &self.alice,
                &self.bob,
                &mut self.nb,
                &mut self.lb,
                self.now,
                &mut self.rng,
            )
        }

        fn bob_receives(&mut self, msg: &SignalMessage) -> Vec<u8> {
            dual_decrypt(
                msg,
                &self.alice,
                &self.bob,
                &mut self.nb,
                &mut self.lb,
                &mut self.rng,
            )
        }

        fn alice_receives(&mut self, msg: &SignalMessage) -> Vec<u8> {
            dual_decrypt(
                msg,
                &self.bob,
                &self.alice,
                &mut self.na,
                &mut self.la,
                &mut self.rng,
            )
        }

        fn bob_receives_err(&mut self, msg: &SignalMessage) -> SignalProtocolError {
            dual_decrypt_expect_err(
                msg,
                &self.alice,
                &self.bob,
                &mut self.nb,
                &mut self.lb,
                &mut self.rng,
            )
        }

        #[allow(dead_code)]
        fn alice_receives_err(&mut self, msg: &SignalMessage) -> SignalProtocolError {
            dual_decrypt_expect_err(
                msg,
                &self.bob,
                &self.alice,
                &mut self.na,
                &mut self.la,
                &mut self.rng,
            )
        }
    }

    impl DualParticipant {
        fn new(
            _name: &'static str,
            address: ProtocolAddress,
            rng: &mut (impl rand::Rng + rand::CryptoRng),
        ) -> Self {
            let identity = IdentityKeyPair::generate(rng);
            let store = InMemSignalProtocolStore::new(identity, rng.random()).unwrap();
            Self {
                address,
                message_queue: Vec::new(),
                state: DualLocalState {
                    new_store: store.clone(),
                    legacy_store: store,
                    pre_key_count: 0,
                },
                snapshots: Vec::new(),
                message_send_log: Vec::new(),
            }
        }

        fn address(&self) -> &ProtocolAddress {
            &self.address
        }

        fn has_pending_incoming_messages(&self) -> bool {
            !self.message_queue.is_empty()
        }

        fn assert_equivalent_with(&self, them: &Self, context: &str) {
            assert_store_state_equivalent(
                &self.state.new_store,
                &self.state.legacy_store,
                &them.address,
                context,
            );
        }

        async fn process_pre_key(
            &mut self,
            them: &mut Self,
            use_one_time_pre_key: bool,
            rng: &mut ChaCha8Rng,
        ) {
            let their_signed_pre_key_pair = KeyPair::generate(rng);
            let their_signed_pre_key_public = their_signed_pre_key_pair.public_key.serialize();
            let identity_key_pair = them.state.new_store.get_identity_key_pair().await.unwrap();
            let their_signed_pre_key_signature = identity_key_pair
                .private_key()
                .calculate_signature(&their_signed_pre_key_public, rng)
                .unwrap();

            them.state.pre_key_count += 1;
            let signed_pre_key_id: SignedPreKeyId = them.state.pre_key_count.into();
            let signed_pre_key_record = SignedPreKeyRecord::new(
                signed_pre_key_id,
                Timestamp::from_epoch_millis(42),
                &their_signed_pre_key_pair,
                &their_signed_pre_key_signature,
            );
            them.state
                .new_store
                .save_signed_pre_key(signed_pre_key_id, &signed_pre_key_record)
                .await
                .unwrap();
            them.state
                .legacy_store
                .save_signed_pre_key(signed_pre_key_id, &signed_pre_key_record)
                .await
                .unwrap();

            them.state.pre_key_count += 1;
            let pre_key_id: PreKeyId = them.state.pre_key_count.into();
            let pre_key_info = if use_one_time_pre_key {
                let one_time_pre_key = KeyPair::generate(rng);
                let pre_key_record = PreKeyRecord::new(pre_key_id, &one_time_pre_key);
                them.state
                    .new_store
                    .save_pre_key(pre_key_id, &pre_key_record)
                    .await
                    .unwrap();
                them.state
                    .legacy_store
                    .save_pre_key(pre_key_id, &pre_key_record)
                    .await
                    .unwrap();
                Some((pre_key_id, one_time_pre_key.public_key))
            } else {
                None
            };

            let their_kyber_pre_key_pair =
                crate::kem::KeyPair::generate(crate::kem::KeyType::Kyber1024, rng);
            let their_kyber_pre_key_public = their_kyber_pre_key_pair.public_key.serialize();
            let their_kyber_pre_key_signature = identity_key_pair
                .private_key()
                .calculate_signature(&their_kyber_pre_key_public, rng)
                .unwrap();

            them.state.pre_key_count += 1;
            let kyber_pre_key_id: KyberPreKeyId = them.state.pre_key_count.into();
            let kyber_pre_key_record = KyberPreKeyRecord::new(
                kyber_pre_key_id,
                Timestamp::from_epoch_millis(42),
                &their_kyber_pre_key_pair,
                &their_kyber_pre_key_signature,
            );
            them.state
                .new_store
                .save_kyber_pre_key(kyber_pre_key_id, &kyber_pre_key_record)
                .await
                .unwrap();
            them.state
                .legacy_store
                .save_kyber_pre_key(kyber_pre_key_id, &kyber_pre_key_record)
                .await
                .unwrap();

            let their_pre_key_bundle = PreKeyBundle::new(
                them.state
                    .new_store
                    .get_local_registration_id()
                    .await
                    .unwrap(),
                DeviceId::new(1).unwrap(),
                pre_key_info,
                signed_pre_key_id,
                their_signed_pre_key_pair.public_key,
                their_signed_pre_key_signature.into_vec(),
                kyber_pre_key_id,
                their_kyber_pre_key_pair.public_key,
                their_kyber_pre_key_signature.into_vec(),
                *identity_key_pair.identity_key(),
            )
            .unwrap();

            let mut legacy_rng = rng.clone();
            process_prekey_bundle(
                &them.address,
                &self.address,
                &mut self.state.new_store.session_store,
                &mut self.state.new_store.identity_store,
                &their_pre_key_bundle,
                SystemTime::UNIX_EPOCH,
                rng,
            )
            .await
            .unwrap();
            process_prekey_bundle(
                &them.address,
                &self.address,
                &mut self.state.legacy_store.session_store,
                &mut self.state.legacy_store.identity_store,
                &their_pre_key_bundle,
                SystemTime::UNIX_EPOCH,
                &mut legacy_rng,
            )
            .await
            .unwrap();

            self.assert_equivalent_with(them, "process_pre_key/self");
            them.assert_equivalent_with(self, "process_pre_key/them");
            assert!(
                self.state
                    .new_store
                    .load_session(&them.address)
                    .await
                    .unwrap()
                    .expect("just created")
                    .has_usable_sender_chain(
                        SystemTime::UNIX_EPOCH,
                        SessionUsabilityRequirements::all(),
                    )
                    .unwrap()
            );
        }

        async fn send_message(&mut self, them: &mut Self, rng: &mut ChaCha8Rng) {
            self.send_message_with_id(them, self.message_send_log.len().try_into().unwrap(), rng)
                .await;
            self.message_send_log.push(MessageStatus::Sent);
        }

        async fn send_message_with_id(&mut self, them: &mut Self, id: u64, rng: &mut ChaCha8Rng) {
            let has_usable_sender_chain = self
                .state
                .new_store
                .load_session(&them.address)
                .await
                .unwrap()
                .and_then(|session| {
                    session
                        .has_usable_sender_chain(
                            SystemTime::UNIX_EPOCH,
                            SessionUsabilityRequirements::all(),
                        )
                        .ok()
                })
                .unwrap_or(false);

            if !has_usable_sender_chain {
                self.process_pre_key(them, rng.random_bool(0.75), rng).await;
            }

            let buffer = id.to_le_bytes();
            let outgoing_message = dual_encrypt_any(
                &buffer,
                &them.address,
                &self.address,
                &mut self.state.new_store,
                &mut self.state.legacy_store,
                SystemTime::UNIX_EPOCH,
                rng,
            );

            let incoming_message = match outgoing_message.message_type() {
                CiphertextMessageType::PreKey => CiphertextMessage::PreKeySignalMessage(
                    PreKeySignalMessage::try_from(outgoing_message.serialize()).unwrap(),
                ),
                CiphertextMessageType::Whisper => CiphertextMessage::SignalMessage(
                    SignalMessage::try_from(outgoing_message.serialize()).unwrap(),
                ),
                other_type => panic!("unexpected type {other_type:?}"),
            };

            them.message_queue.push((incoming_message, id));
            self.assert_equivalent_with(them, "send");
        }

        async fn receive_messages(&mut self, them: &mut Self, rng: &mut ChaCha8Rng) {
            for (incoming_message, expected) in self.message_queue.split_off(0) {
                match incoming_message {
                    CiphertextMessage::SignalMessage(_)
                    | CiphertextMessage::PreKeySignalMessage(_) => {
                        match dual_decrypt_any_result(
                            &incoming_message,
                            &them.address,
                            &self.address,
                            &mut self.state.new_store,
                            &mut self.state.legacy_store,
                            rng,
                        ) {
                            Ok(decrypted) => {
                                assert_eq!(expected.to_le_bytes(), &decrypted[..]);
                                them.ack(expected);
                            }
                            Err(_) => {
                                let error_msg = DecryptionErrorMessage::for_original(
                                    incoming_message.serialize(),
                                    incoming_message.message_type(),
                                    Timestamp::from_epoch_millis(expected),
                                    1,
                                )
                                .expect("can encode DEM");
                                them.message_queue.push((
                                    CiphertextMessage::PlaintextContent(error_msg.into()),
                                    u64::MAX,
                                ));
                            }
                        }
                    }
                    CiphertextMessage::SenderKeyMessage(_) => unreachable!(),
                    CiphertextMessage::PlaintextContent(content) => {
                        self.handle_decryption_error(them, content, rng).await;
                    }
                }
            }
            self.assert_equivalent_with(them, "receive");
            them.assert_equivalent_with(self, "receive/peer");
        }

        fn drop_message(&mut self, them: &mut Self) {
            match self.message_queue.pop() {
                None | Some((CiphertextMessage::PlaintextContent(_), _)) => {}
                Some((_, id)) => them.nack(id),
            }
        }

        fn shuffle_messages(&mut self, rng: &mut impl rand::Rng) {
            use rand::seq::SliceRandom as _;
            self.message_queue.shuffle(rng);
        }

        async fn handle_decryption_error(
            &mut self,
            them: &mut Self,
            content: PlaintextContent,
            rng: &mut ChaCha8Rng,
        ) {
            let dem = extract_decryption_error_message_from_serialized_content(content.body())
                .expect("all PlaintextContent is DEM");
            assert_eq!(dem.device_id(), 1);

            let id = dem.timestamp().epoch_millis();
            let Some(status) = self.message_send_log.get(usize::try_from(id).unwrap()) else {
                panic!(
                    "failed to decrypt an unsent message {id} ({} total sent)",
                    self.message_send_log.len()
                )
            };
            match status {
                MessageStatus::Sent => {}
                MessageStatus::Dropped => {
                    panic!("got a decryption error for dropped message {id}");
                }
                MessageStatus::Delivered => {
                    panic!("got a decryption error for successfully delivered message {id}");
                }
            }

            let ratchet_key = dem
                .ratchet_key()
                .expect("all DEMs for 1:1 messages have ratchet keys");
            if self
                .state
                .new_store
                .load_session(&them.address)
                .await
                .unwrap()
                .is_some_and(|session| {
                    session
                        .current_ratchet_key_matches(ratchet_key)
                        .expect("structurally valid session")
                })
            {
                self.archive_session(&them.address).await;
            }

            self.send_message_with_id(them, id, rng).await;
        }

        async fn archive_session(&mut self, their_address: &ProtocolAddress) {
            for store in [&mut self.state.new_store, &mut self.state.legacy_store] {
                if let Some(mut session) = store.load_session(their_address).await.unwrap() {
                    session.archive_current_state().unwrap();
                    store.store_session(their_address, &session).await.unwrap();
                }
            }
        }

        fn snapshot_state(&mut self) {
            self.snapshots.push(self.state.clone());
        }

        fn restore_from_snapshot_if_exists(&mut self, i: u8) {
            let i = usize::from(i);
            if i < self.snapshots.len() {
                self.state = self.snapshots.remove(i);
            }
        }

        fn ack(&mut self, id: u64) {
            self.update_status(id, MessageStatus::Delivered);
        }

        fn nack(&mut self, id: u64) {
            self.update_status(id, MessageStatus::Dropped);
        }

        fn update_status(&mut self, id: u64, updated_status: MessageStatus) {
            let Some(status) = self.message_send_log.get_mut(usize::try_from(id).unwrap()) else {
                panic!(
                    "tried to update unsent message {id} ({} total sent)",
                    self.message_send_log.len()
                )
            };
            match status {
                MessageStatus::Sent => *status = updated_status,
                MessageStatus::Dropped => panic!("updated dropped message {id}"),
                MessageStatus::Delivered => panic!("updated delivered message {id}"),
            }
        }

        async fn run_event(&mut self, them: &mut Self, event: Event, rng: &mut ChaCha8Rng) {
            match event {
                Event::Archive => self.archive_session(them.address()).await,
                Event::Snapshot => self.snapshot_state(),
                Event::Restore { index } => self.restore_from_snapshot_if_exists(index),
                Event::Receive => self.receive_messages(them, rng).await,
                Event::Drop => self.drop_message(them),
                Event::Shuffle => self.shuffle_messages(rng),
                Event::Send { count_times_eight } => {
                    for _ in 0..(count_times_eight / 8) {
                        self.send_message(them, rng).await;
                    }
                }
            }
            self.assert_equivalent_with(them, "event");
            them.assert_equivalent_with(self, "event/peer");
        }
    }

    // ── Scenario tests ──────────────────────────────────────────────────

    /// Ordinary skipped-key handling remains interoperable when messages are
    /// delivered with gaps, later arrive out of order, and both directions
    /// continue sending before the session fully catches up.
    #[test]
    fn scenario_interleaved_delivery_with_gaps_and_recovery() {
        let mut s = DualSession::new(0xBEEF_0001);

        // Alice sends a burst to Bob. Bob receives only the first and third,
        // leaving a gap that must be recovered later from stored skipped keys.
        let a_msgs: Vec<_> = (0u8..4)
            .map(|i| (s.alice_sends(&[b'A', i]), vec![b'A', i]))
            .collect();
        assert_eq!(s.bob_receives(&a_msgs[0].0), a_msgs[0].1, "alice msg 0");
        assert_eq!(s.bob_receives(&a_msgs[2].0), a_msgs[2].1, "alice msg 2");

        // Before Alice's burst is fully drained, Bob sends his own burst.
        // Alice receives only the later message first, exercising the same
        // skipped-key path in the opposite direction.
        let b_msgs: Vec<_> = (0u8..3)
            .map(|i| (s.bob_sends(&[b'B', i]), vec![b'B', i]))
            .collect();
        assert_eq!(s.alice_receives(&b_msgs[2].0), b_msgs[2].1, "bob msg 2");

        // The missing earlier messages now arrive and must still decrypt.
        assert_eq!(s.bob_receives(&a_msgs[1].0), a_msgs[1].1, "alice msg 1");
        assert_eq!(s.bob_receives(&a_msgs[3].0), a_msgs[3].1, "alice msg 3");
        assert_eq!(s.alice_receives(&b_msgs[0].0), b_msgs[0].1, "bob msg 0");
        assert_eq!(s.alice_receives(&b_msgs[1].0), b_msgs[1].1, "bob msg 1");

        // After recovering the gaps, both directions should continue in steady
        // state without any special handling.
        let alice_followup = s.alice_sends(b"alice steady");
        assert_eq!(s.bob_receives(&alice_followup), b"alice steady");
        let bob_followup = s.bob_sends(b"bob steady");
        assert_eq!(s.alice_receives(&bob_followup), b"bob steady");
    }

    /// Skip past MAX_FORWARD_JUMPS — both paths must reject with the same
    /// error.  Encrypts on just the new path for performance (25k+ messages);
    /// both receivers start from identical untouched state.
    #[test]
    fn scenario_chain_jump_over_limit() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xBEEF_0005);
        let (mut na, mut nb, alice, bob) = setup_stores(&mut rng);
        let mut lb = nb.clone();
        let now = SystemTime::now();

        let count = crate::consts::MAX_FORWARD_JUMPS + 2;
        let mut last = None;
        for _ in 0..count {
            let ct = message_encrypt(
                b"x",
                &bob,
                &alice,
                &mut na.session_store,
                &mut na.identity_store,
                now,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("encrypt");
            last = Some(match ct {
                CiphertextMessage::SignalMessage(m) => m,
                _ => panic!("not SignalMessage"),
            });
        }
        let msg = last.unwrap();

        // Bob has received nothing — new and legacy stores are identical.
        let mut leg_rng = rng.clone();
        let new_err = message_decrypt_signal(
            &msg,
            &alice,
            &bob,
            &mut nb.session_store,
            &mut nb.identity_store,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect_err("should exceed jump limit");

        let leg_err = legacy::legacy_message_decrypt_signal(
            &msg,
            &alice,
            &mut lb.session_store,
            &mut lb.identity_store,
            &mut leg_rng,
        )
        .now_or_never()
        .expect("sync")
        .expect_err("should exceed jump limit");

        assert_eq!(
            std::mem::discriminant(&new_err),
            std::mem::discriminant(&leg_err),
            "error variants differ: new={new_err:?}, legacy={leg_err:?}"
        );
        assert!(
            matches!(new_err, SignalProtocolError::InvalidMessage(..)),
            "expected InvalidMessage, got {new_err:?}"
        );
    }

    /// The initial unacknowledged send must be bit-identical as a
    /// `PreKeySignalMessage`, and both sides must end up with identical
    /// session state after the ack round-trip.
    #[test]
    fn scenario_prekey_session_establishment_equivalence() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xBEEF_0008);
        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let bob_identity = IdentityKeyPair::generate(&mut rng);
        let alice = ProtocolAddress::new(
            "9d0652a3-dcc3-4d11-975f-74d61598733f".to_owned(),
            DeviceId::new(1).unwrap(),
        );
        let bob = ProtocolAddress::new(
            "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(),
            DeviceId::new(1).unwrap(),
        );
        let now = SystemTime::now();

        let alice_base = InMemSignalProtocolStore::new(alice_identity, 1).expect("alice store");
        let mut bob_base = InMemSignalProtocolStore::new(bob_identity, 2).expect("bob store");
        let bundle = create_bob_bundle(&mut bob_base, 1, 1, 1, &mut rng);

        let (mut alice_new, mut alice_legacy) = (alice_base.clone(), alice_base.clone());
        let (mut bob_new, mut bob_legacy) = (bob_base.clone(), bob_base.clone());

        let mut legacy_rng = rng.clone();
        process_prekey_bundle(
            &bob,
            &alice,
            &mut alice_new.session_store,
            &mut alice_new.identity_store,
            &bundle,
            now,
            &mut rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("new process_prekey_bundle");
        process_prekey_bundle(
            &bob,
            &alice,
            &mut alice_legacy.session_store,
            &mut alice_legacy.identity_store,
            &bundle,
            now,
            &mut legacy_rng,
        )
        .now_or_never()
        .expect("sync")
        .expect("legacy process_prekey_bundle");
        assert_store_state_equivalent(&alice_new, &alice_legacy, &bob, "post-bundle");

        let init = dual_encrypt_any(
            b"session init",
            &bob,
            &alice,
            &mut alice_new,
            &mut alice_legacy,
            now,
            &mut rng,
        );
        assert!(
            matches!(init, CiphertextMessage::PreKeySignalMessage(_)),
            "expected first message after bundle processing to be PreKey"
        );

        assert_eq!(
            dual_decrypt_any(&init, &alice, &bob, &mut bob_new, &mut bob_legacy, &mut rng),
            b"session init"
        );

        let ack = dual_encrypt_any(
            b"session ack",
            &alice,
            &bob,
            &mut bob_new,
            &mut bob_legacy,
            now,
            &mut rng,
        );
        assert!(
            matches!(ack, CiphertextMessage::SignalMessage(_)),
            "expected ack to be a SignalMessage"
        );
        assert_eq!(
            dual_decrypt_any(
                &ack,
                &bob,
                &alice,
                &mut alice_new,
                &mut alice_legacy,
                &mut rng
            ),
            b"session ack"
        );

        let followup = dual_encrypt_any(
            b"steady state",
            &bob,
            &alice,
            &mut alice_new,
            &mut alice_legacy,
            now,
            &mut rng,
        );
        assert!(
            matches!(followup, CiphertextMessage::SignalMessage(_)),
            "expected acknowledged session to emit SignalMessage"
        );
        assert_eq!(
            dual_decrypt_any(
                &followup,
                &alice,
                &bob,
                &mut bob_new,
                &mut bob_legacy,
                &mut rng
            ),
            b"steady state"
        );
    }

    /// Flip a byte in the MAC — both paths must reject identically, and
    /// the original message must still decrypt afterward.
    #[test]
    fn scenario_corrupted_ciphertext() {
        let mut s = DualSession::new(0xBEEF_0006);

        // Warm up the session with a round-trip
        let msg = s.alice_sends(b"hello");
        assert_eq!(s.bob_receives(&msg), b"hello");
        let msg = s.bob_sends(b"hi");
        assert_eq!(s.alice_receives(&msg), b"hi");

        // Alice sends a message; corrupt the last byte (in the MAC)
        let msg = s.alice_sends(b"secret");
        let mut corrupted_bytes = msg.serialized().to_vec();
        let len = corrupted_bytes.len();
        corrupted_bytes[len - 1] ^= 0xFF;
        let corrupted =
            SignalMessage::try_from(corrupted_bytes.as_slice()).expect("parse corrupted message");

        let err = s.bob_receives_err(&corrupted);
        assert!(
            matches!(
                err,
                SignalProtocolError::InvalidMessage(CiphertextMessageType::Whisper, _)
            ),
            "expected InvalidMessage(Whisper, _), got {err:?}"
        );

        // The original (uncorrupted) message still decrypts — failed MAC
        // check does not persist state changes.
        assert_eq!(s.bob_receives(&msg), b"secret");
    }

    /// Replay an already-decrypted message — both paths must detect the
    /// duplicate.
    #[test]
    fn scenario_replay_message() {
        let mut s = DualSession::new(0xBEEF_0007);

        let msg = s.alice_sends(b"once");
        assert_eq!(s.bob_receives(&msg), b"once");

        // Same ciphertext again — should be detected as duplicate
        let err = s.bob_receives_err(&msg);
        assert!(
            matches!(err, SignalProtocolError::DuplicatedMessage(..)),
            "expected DuplicatedMessage, got {err:?}"
        );
    }

    proptest! {
        /// Reuse the existing session-reset event model from `test-support`,
        /// but execute every encrypt/decrypt on both new and legacy codepaths.
        #[test]
        fn proptest_event_model_matches_legacy(
            actions in prop::collection::vec(
                (prop::bool::ANY, proptest_arbitrary_interop::arb::<Event>()),
                0..40,
            ),
        ) {
            let mut rng = ChaCha8Rng::seed_from_u64(0);
            let mut alice = DualParticipant::new(
                "alice",
                ProtocolAddress::new("9d0652a3-dcc3-4d11-975f-74d61598733f".to_owned(), DeviceId::new(1).unwrap()),
                &mut rng,
            );
            let mut bob = DualParticipant::new(
                "bob",
                ProtocolAddress::new("796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(), DeviceId::new(1).unwrap()),
                &mut rng,
            );

            for (who, event) in actions {
                let (me, them) = if who {
                    (&mut alice, &mut bob)
                } else {
                    (&mut bob, &mut alice)
                };
                me.run_event(them, event, &mut rng)
                    .now_or_never()
                    .expect("sync");
            }

            while alice.has_pending_incoming_messages() || bob.has_pending_incoming_messages() {
                alice
                    .receive_messages(&mut bob, &mut rng)
                    .now_or_never()
                    .expect("sync");
                bob.receive_messages(&mut alice, &mut rng)
                    .now_or_never()
                    .expect("sync");
            }

            for _ in 0..8 {
                alice
                    .send_message(&mut bob, &mut rng)
                    .now_or_never()
                    .expect("sync");
                bob.receive_messages(&mut alice, &mut rng)
                    .now_or_never()
                    .expect("sync");
                bob.send_message(&mut alice, &mut rng)
                    .now_or_never()
                    .expect("sync");
                alice
                    .receive_messages(&mut bob, &mut rng)
                    .now_or_never()
                    .expect("sync");
            }

            alice.assert_equivalent_with(&bob, "final/alice");
            bob.assert_equivalent_with(&alice, "final/bob");
        }
    }

    proptest! {
        /// New code can take over a session whose state was last written by
        /// legacy code.
        ///
        /// Runs `legacy_actions` using legacy enc+dec on both sides, then
        /// switches both sides to new enc+dec for `new_actions`. The session
        /// state — chain keys, ratchet state, SPQR state — was written by the
        /// legacy decrypt path; new code must read and advance it correctly.
        #[test]
        fn proptest_legacy_handover_to_new(
            seed in 0u64..u64::MAX,
            legacy_actions in prop::collection::vec(
                (prop::bool::ANY, prop::collection::vec(any::<u8>(), 0..=64)),
                1..=10,
            ),
            new_actions in prop::collection::vec(
                (prop::bool::ANY, prop::collection::vec(any::<u8>(), 0..=64)),
                1..=10,
            ),
        ) {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let (mut alice_store, mut bob_store, alice_address, bob_address) =
                setup_stores(&mut rng);
            let now = std::time::SystemTime::now();

            // Phase 1: legacy enc + legacy dec advance the session state.
            for (alice_sends, plaintext) in &legacy_actions {
                let (sender, receiver, recv_addr, send_addr) = if *alice_sends {
                    (&mut alice_store, &mut bob_store, &bob_address, &alice_address)
                } else {
                    (&mut bob_store, &mut alice_store, &alice_address, &bob_address)
                };

                let ct = legacy::legacy_message_encrypt(
                    plaintext,
                    recv_addr,
                    send_addr,
                    &mut sender.session_store,
                    &mut sender.identity_store,
                    now,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("legacy enc");

                let signal_msg = match &ct {
                    CiphertextMessage::SignalMessage(m) => m,
                    other => panic!(
                        "expected SignalMessage in legacy phase, got {:?}",
                        other.message_type()
                    ),
                };

                let ptext = legacy::legacy_message_decrypt_signal(
                    signal_msg,
                    send_addr,
                    &mut receiver.session_store,
                    &mut receiver.identity_store,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("legacy dec");

                prop_assert_eq!(ptext, plaintext.clone(), "legacy phase: wrong plaintext");
            }

            // Phase 2: new code takes over the session state left by legacy.
            for (alice_sends, plaintext) in &new_actions {
                let (sender, receiver, recv_addr, send_addr) = if *alice_sends {
                    (&mut alice_store, &mut bob_store, &bob_address, &alice_address)
                } else {
                    (&mut bob_store, &mut alice_store, &alice_address, &bob_address)
                };

                let ct = message_encrypt(
                    plaintext,
                    recv_addr,
                    send_addr,
                    &mut sender.session_store,
                    &mut sender.identity_store,
                    now,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("new enc");

                let signal_msg = match &ct {
                    CiphertextMessage::SignalMessage(m) => m,
                    other => panic!(
                        "expected SignalMessage in new phase, got {:?}",
                        other.message_type()
                    ),
                };

                let ptext = message_decrypt_signal(
                    signal_msg,
                    send_addr,
                    recv_addr,
                    &mut receiver.session_store,
                    &mut receiver.identity_store,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("new dec");

                prop_assert_eq!(ptext, plaintext.clone(), "new phase: wrong plaintext");
            }
        }

        /// A message encrypted by legacy code on a previous session is correctly
        /// decrypted by new code after a session transition.
        ///
        /// Scenario:
        ///   1. `pre_actions` exchanges on session A using legacy enc+dec.
        ///   2. Alice encrypts a delayed Whisper on session A using legacy enc
        ///      (not yet delivered to Bob).
        ///   3. Alice processes a new pre-key bundle from Bob → session B
        ///      (session A is archived in Alice's previous_sessions).
        ///   4. Alice and Bob establish session B on both sides and exchange
        ///      `post_actions` using new enc+dec. Bob's session A' is archived to
        ///      his previous_sessions when he receives Alice's first session-B
        ///      PreKeySignalMessage.
        ///   5. The delayed message from step 2 is delivered to Bob via new
        ///      message_decrypt_signal. try_decrypt_from_record must fail on
        ///      the current session B' and succeed on the previous session A',
        ///      exercising promote_old_session.
        #[test]
        fn proptest_delayed_message_via_previous_session(
            seed in 0u64..u64::MAX,
            pre_actions in prop::collection::vec(
                (prop::bool::ANY, prop::collection::vec(any::<u8>(), 0..=6)),
                0..=6,
            ),
            post_actions in prop::collection::vec(
                (prop::bool::ANY, prop::collection::vec(any::<u8>(), 0..=64)),
                0..=6,
            ),
            delayed_plaintext in prop::collection::vec(any::<u8>(), 1..=64),
        ) {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let (mut alice_store, mut bob_store, alice_address, bob_address) =
                setup_stores(&mut rng);
            let now = std::time::SystemTime::now();

            // ── Phase 1: legacy enc+dec on session A ─────────────────────────

            for (alice_sends, plaintext) in &pre_actions {
                let (sender, receiver, recv_addr, send_addr) = if *alice_sends {
                    (&mut alice_store, &mut bob_store, &bob_address, &alice_address)
                } else {
                    (&mut bob_store, &mut alice_store, &alice_address, &bob_address)
                };

                let ct = legacy::legacy_message_encrypt(
                    plaintext,
                    recv_addr,
                    send_addr,
                    &mut sender.session_store,
                    &mut sender.identity_store,
                    now,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("pre legacy enc");

                let signal_msg = match &ct {
                    CiphertextMessage::SignalMessage(m) => m,
                    other => panic!(
                        "expected SignalMessage in pre phase, got {:?}",
                        other.message_type()
                    ),
                };

                let ptext = legacy::legacy_message_decrypt_signal(
                    signal_msg,
                    send_addr,
                    &mut receiver.session_store,
                    &mut receiver.identity_store,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("pre legacy dec");

                prop_assert_eq!(ptext, plaintext.clone(), "pre phase: wrong plaintext");
            }

            // ── Encrypt delayed message (not yet delivered) ──────────────────

            // This Whisper is encrypted by Alice on session A's current chain.
            // Bob's session A' is at the same chain index, so it can decrypt
            // it later.
            let delayed_ct = legacy::legacy_message_encrypt(
                &delayed_plaintext,
                &bob_address,
                &alice_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                now,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("delayed legacy enc");

            let delayed_signal_msg = match delayed_ct {
                CiphertextMessage::SignalMessage(m) => m,
                other => panic!(
                    "expected SignalMessage for delayed msg, got {:?}",
                    other.message_type()
                ),
            };

            // ── Session transition: A → B ─────────────────────────────────────

            // Alice processes a new pre-key bundle from Bob. This calls
            // promote_state, archiving session A to Alice's previous_sessions.
            let bundle = create_bob_bundle(&mut bob_store, 1, 1, 1, &mut rng);
            process_prekey_bundle(
                &bob_address,
                &alice_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bundle,
                now,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("process_prekey_bundle");

            // Alice sends her first message on session B (a PreKeySignalMessage
            // since B is unacknowledged). When Bob decrypts it, process_prekey
            // fires and archives his session A' to previous_sessions.
            let session_b_init = message_encrypt(
                b"session B init",
                &bob_address,
                &alice_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                now,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("session B init enc");

            message_decrypt(
                &session_b_init,
                &alice_address,
                &bob_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &mut bob_store.pre_key_store,
                &bob_store.signed_pre_key_store,
                &mut bob_store.kyber_pre_key_store,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("session B init dec");
            // Bob now has: current = session B', previous_sessions = [session A']

            // Bob acknowledges session B on Alice's side. Without this, Alice
            // would keep wrapping messages as PreKeySignalMessage, and each
            // would trigger another process_prekey on Bob's side, nesting
            // sessions further. After this round-trip both sides send Whispers.
            let session_b_ack = message_encrypt(
                b"session B ack",
                &alice_address,
                &bob_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                now,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("session B ack enc");

            let session_b_ack_signal = match &session_b_ack {
                CiphertextMessage::SignalMessage(m) => m,
                other => panic!(
                    "expected Whisper for session B ack, got {:?}",
                    other.message_type()
                ),
            };
            message_decrypt_signal(
                session_b_ack_signal,
                &bob_address,
                &alice_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("session B ack dec");
            // Alice's session B is now acknowledged; all her sends are Whispers.

            // ── Phase 2: new enc+dec on session B ────────────────────────────

            for (alice_sends, plaintext) in &post_actions {
                let (sender, receiver, recv_addr, send_addr) = if *alice_sends {
                    (&mut alice_store, &mut bob_store, &bob_address, &alice_address)
                } else {
                    (&mut bob_store, &mut alice_store, &alice_address, &bob_address)
                };

                let ct = message_encrypt(
                    plaintext,
                    recv_addr,
                    send_addr,
                    &mut sender.session_store,
                    &mut sender.identity_store,
                    now,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("post new enc");

                let signal_msg = match &ct {
                    CiphertextMessage::SignalMessage(m) => m,
                    other => panic!(
                        "expected SignalMessage in post phase, got {:?}",
                        other.message_type()
                    ),
                };

                let ptext = message_decrypt_signal(
                    signal_msg,
                    send_addr,
                    recv_addr,
                    &mut receiver.session_store,
                    &mut receiver.identity_store,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("post new dec");

                prop_assert_eq!(ptext, plaintext.clone(), "post phase: wrong plaintext");
            }

            // ── Deliver delayed message ───────────────────────────────────────

            // Bob's current session is B'. The delayed message was encrypted
            // under session A. try_decrypt_from_record must:
            //   1. Try session B' → fail (wrong ratchet key / counter).
            //   2. Try session A' from previous_sessions → succeed.
            //   3. Call promote_old_session, making A' the current session.
            let ptext = message_decrypt_signal(
                &delayed_signal_msg,
                &alice_address,
                &bob_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &mut rng,
            )
            .now_or_never()
            .expect("sync")
            .expect("delayed msg dec via previous session");

            prop_assert_eq!(
                ptext,
                delayed_plaintext.clone(),
                "delayed message: wrong plaintext"
            );
        }

        /// New encrypt and legacy encrypt produce byte-identical ciphertexts
        /// when given the same RNG state.
        ///
        /// Runs two parallel session pairs from the same initial state.
        /// Before each encrypt, the RNG is cloned so that both the new and
        /// legacy paths start from the same randomness.  If the RNG
        /// consumption is identical (one `spqr::send` call per encrypt,
        /// one `KeyPair::generate` per DH ratchet step on decrypt), the
        /// ciphertexts must be equal.  The receiver sessions are advanced
        /// with the same split so that subsequent iterations stay in sync.
        #[test]
        fn proptest_ciphertext_equality(
            seed in 0u64..u64::MAX,
            actions in prop::collection::vec(
                (prop::bool::ANY, prop::collection::vec(any::<u8>(), 0..=64)),
                1..=20,
            ),
        ) {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let (mut alice_new, mut bob_new, alice_address, bob_address) =
                setup_stores(&mut rng);
            // Clone the freshly-initialized stores so both paths start from
            // identical state.
            let (mut alice_legacy, mut bob_legacy) = (alice_new.clone(), bob_new.clone());
            let now = SystemTime::now();

            for (alice_sends, plaintext) in &actions {
                // Borrow the right stores for sender/receiver on each path.
                let (
                    (sender_new, receiver_new),
                    (sender_legacy, receiver_legacy),
                    sender_addr,
                    receiver_addr,
                ) = if *alice_sends {
                    (
                        (&mut alice_new, &mut bob_new),
                        (&mut alice_legacy, &mut bob_legacy),
                        &alice_address,
                        &bob_address,
                    )
                } else {
                    (
                        (&mut bob_new, &mut alice_new),
                        (&mut bob_legacy, &mut alice_legacy),
                        &bob_address,
                        &alice_address,
                    )
                };

                // Both encrypt calls start from the same RNG position.
                let mut enc_rng = rng.clone();

                let new_ct = message_encrypt(
                    plaintext,
                    receiver_addr,
                    sender_addr,
                    &mut sender_new.session_store,
                    &mut sender_new.identity_store,
                    now,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("new encrypt succeeded");

                let legacy_ct = legacy::legacy_message_encrypt(
                    plaintext,
                    receiver_addr,
                    sender_addr,
                    &mut sender_legacy.session_store,
                    &mut sender_legacy.identity_store,
                    now,
                    &mut enc_rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("legacy encrypt succeeded");

                let new_msg = match &new_ct {
                    CiphertextMessage::SignalMessage(m) => m,
                    other => panic!(
                        "expected SignalMessage from new enc, got {:?}",
                        other.message_type()
                    ),
                };
                let legacy_msg = match &legacy_ct {
                    CiphertextMessage::SignalMessage(m) => m,
                    other => panic!(
                        "expected SignalMessage from legacy enc, got {:?}",
                        other.message_type()
                    ),
                };

                prop_assert_eq!(
                    new_msg.serialized(),
                    legacy_msg.serialized(),
                    "new and legacy produced different ciphertexts from the same RNG state"
                );

                // Advance both receiver sessions with the same RNG split so
                // their states stay in sync for the next iteration.
                let mut dec_rng = rng.clone();

                let _ = message_decrypt_signal(
                    new_msg,
                    sender_addr,
                    receiver_addr,
                    &mut receiver_new.session_store,
                    &mut receiver_new.identity_store,
                    &mut rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("new decrypt succeeded");

                let _ = legacy::legacy_message_decrypt_signal(
                    legacy_msg,
                    sender_addr,
                    &mut receiver_legacy.session_store,
                    &mut receiver_legacy.identity_store,
                    &mut dec_rng,
                )
                .now_or_never()
                .expect("sync")
                .expect("legacy decrypt succeeded");
            }
        }
    }
}
