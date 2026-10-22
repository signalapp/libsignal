//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Tahini session management — pure state-machine policy.
//!
//! This module owns the Tahini protocol's policy decisions for the per-device
//! [`SessionRecord`]: when to archive, when to break a deadlock, how to resolve
//! tiebreakers on simultaneous initiation, when to mark a locally-initiated
//! session as acknowledged, and how direction tracking flips between sends and
//! receives.
//!
//! ## Boundary
//!
//! Functions here are **pure**: synchronous, no `async`, no store traits. They
//! operate over an in-memory [`SessionRecord`] (or [`SessionState`]) and return
//! decisions to the caller. Anything that talks to a `dyn *Store` lives in
//! [`crate::session_management`].
//!
//! ## Verbs
//!
//! Callers invoke a verb that names the protocol event:
//!
//! - [`on_send`] — about to encrypt a message.
//! - [`on_receive_active`] — successfully decrypted on the active session.
//! - [`on_receive_inactive`] — successfully decrypted on an archived session
//!   (also fires the deadlock breaker if the threshold is exceeded).
//! - [`on_receive_session_state`] — per-state bookkeeping on any successful
//!   decrypt: once the peer responds, clears the unacknowledged pre-key (so we
//!   stop wrapping outgoing messages) and promotes `LocalNew` → `LocalAcked`.
//! - [`on_archive`] — per-state bookkeeping when a session is retired into the
//!   archive: clears the unacknowledged pre-key so its secret material does not
//!   linger past the point we know it will not be used again.
//! - [`on_initiate`] — locally-initiated session built from a peer's pre-key
//!   bundle is about to be installed.
//! - [`decide_initiation_placement`] / [`commit_received_initiation`] —
//!   peer-initiated session built from an incoming PreKey message: first ask
//!   where it should land (pure, read-only), then install it at that slot
//!   (stamps origin `Remote`).

use crate::state::{InvalidSessionError, SessionState};
use crate::{IdentityKey, SessionRecord};

// ── Policy constants ─────────────────────────────────────────────────────────

/// Maximum number of Send ↔ ReceiveInactive direction changes before the
/// deadlock detector archives the active session and forces re-establishment.
pub(crate) const MAX_DIR_CHANGES: u32 = 5;

// ── Types ────────────────────────────────────────────────────────────────────

/// How a session was established, from the local device's perspective.
///
/// `Legacy` indicates a pre-Tahini session (proto default). Tahini policy keys
/// "known by peer" off the pending pre-key rather than this field, so a Legacy
/// session behaves like `Remote` once acknowledged, or like `LocalNew` while it
/// still carries an unacknowledged pre-key.
pub(crate) use crate::proto::storage::session_structure::Origin as SessionOrigin;
/// The most recent action taken on a device record.
///
/// Used by Tahini's deadlock detector to track direction changes.
pub(crate) use crate::proto::storage::tahini_session_management_state::LastAct;

/// Where a newly-installed peer-initiated session landed in the device record.
///
/// Produced by [`decide_initiation_placement`] and consumed by
/// [`commit_received_initiation`], so the caller can route the inner
/// SignalMessage decryption against the correct session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewSessionLocation {
    Active,
    Archived,
}

// ── Send path ────────────────────────────────────────────────────────────────

/// Update direction-change state in advance of an encrypt.
///
/// If the previous action was a receive on an inactive session, this counts as
/// a direction change. The actual deadlock-breaking archive happens on the
/// receive path; send only updates the counter and the action marker.
pub(crate) fn on_send(record: &mut SessionRecord) {
    if record.last_act() == LastAct::ReceiveInactive {
        record.increment_direction_change_ctr();
    }
    record.set_last_act(LastAct::Send);
}

// ── Receive path ─────────────────────────────────────────────────────────────

/// Mark a successful decrypt on the active session.
pub(crate) fn on_receive_active(record: &mut SessionRecord) {
    record.set_last_act(LastAct::ReceiveActive);
}

/// Mark a successful decrypt on an archived (inactive) session.
///
/// If the prior action was a send, increments the direction-change counter.
/// If the counter then exceeds [`MAX_DIR_CHANGES`], archives the active
/// session and resets the counter (deadlock break).
pub(crate) fn on_receive_inactive(
    record: &mut SessionRecord,
) -> Result<(), crate::SignalProtocolError> {
    if record.last_act() == LastAct::Send {
        record.increment_direction_change_ctr();
    }
    record.set_last_act(LastAct::ReceiveInactive);

    if record.direction_change_ctr() > MAX_DIR_CHANGES {
        log::info!(
            "Tahini deadlock detected (direction_change_ctr={}), \
             archiving active session on receive",
            record.direction_change_ctr()
        );
        record.archive_current_state()?;
        record.reset_direction_change_ctr();
    }

    Ok(())
}

/// Per-state bookkeeping after any successful decrypt, regardless of which
/// session decrypted.
///
/// A successful decrypt means the peer has responded. If this session was not
/// yet known to the peer (it still carries an unacknowledged pre-key), it is
/// now acknowledged: drop the pre-key payload so we stop wrapping outgoing
/// messages as pre-key messages, and record the transition in the origin for
/// diagnostics. Complements the record-level [`on_receive_active`] /
/// [`on_receive_inactive`] helpers.
pub(crate) fn on_receive_session_state(state: &mut SessionState) {
    if !state.is_known_by_peer() {
        debug_assert!(
            matches!(
                state.origin(),
                SessionOrigin::LocalNew | SessionOrigin::Legacy
            ),
            "is_known_by_peer is false but origin is {:?}",
            state.origin()
        );
        state.clear_unacknowledged_pre_key_message();
        if state.origin() == SessionOrigin::LocalNew {
            state.set_origin(SessionOrigin::LocalAcked);
        }
    }
}

/// Per-state bookkeeping when a session is being archived.
///
/// Clears the unacknowledged pre-key payload. Archived sessions are never sent
/// on and are never promoted back to active, so the pre-key material will not
/// be used again — and because it holds cryptographic secrets, it must be
/// deleted as soon as we know it can be deleted safely.
pub(crate) fn on_archive(state: &mut SessionState) {
    state.clear_unacknowledged_pre_key_message();
}

// ── Session establishment ────────────────────────────────────────────────────

/// Install a locally-initiated session as the active session.
///
/// Stamps origin `LocalNew`, archives any prior active session, installs
/// `new_session` as active, and clears the deadlock-detector history for the
/// fresh session: the direction-change counter goes to zero and `last_act` is
/// cleared to [`LastAct::Unset`].
pub(crate) fn on_initiate(record: &mut SessionRecord, mut new_session: SessionState) {
    new_session.set_origin(SessionOrigin::LocalNew);
    record.replace_active_session(new_session);
    record.reset_direction_change_ctr();
    record.set_last_act(LastAct::Unset);
}

/// Decide where a peer-initiated session built from an incoming PreKey
/// message should land in the device record.
///
/// Pure: reads `record` and returns a placement decision. Does not mutate.
///
/// - If there is no active session, the active session is already known by
///   the peer, or the incoming identity differs from the active session's peer
///   identity, the new session goes [`Active`](NewSessionLocation::Active).
///   Identity replacement takes precedence over the SID tiebreaker: a session
///   targeting the retired identity may no longer be usable by the peer.
/// - If the active session is not yet known by the peer (an unacknowledged
///   locally-initiated session — `LocalNew`, or a migrated pre-Tahini session
///   still carrying a pending pre-key), and the identities match, this is a
///   simultaneous initiation: compare session IDs lexicographically. The higher
///   SID wins the active slot; the loser is destined for the archive.
///
/// Deduplication is handled separately by the caller (a session with this ID
/// may already exist, in which case the caller skips placement entirely).
pub(crate) fn decide_initiation_placement(
    record: &SessionRecord,
    incoming_session_id: &[u8],
    incoming_identity: &IdentityKey,
) -> Result<NewSessionLocation, InvalidSessionError> {
    Ok(match record.active_session() {
        None => NewSessionLocation::Active,
        Some(active) => {
            // The caller handles deduplication before reaching here, so the incoming
            // session ID must differ from the active session's. Session IDs are
            // public, so a plain (non-constant-time) comparison is fine.
            debug_assert_ne!(
                incoming_session_id,
                active.session_id(),
                "incoming session ID matches active session; dedup should have caught this"
            );
            if active.is_known_by_peer()
                || active.remote_identity_key()? != Some(*incoming_identity)
                || incoming_session_id > active.session_id()
            {
                NewSessionLocation::Active
            } else {
                NewSessionLocation::Archived
            }
        }
    })
}

/// Install a peer-initiated session at the previously-decided slot, after
/// AEAD has verified.
///
/// Stamps origin `Remote`, writes `new_session` into the slot indicated by
/// `placement`, and applies post-decrypt bookkeeping:
/// - On `Active`: the active session is replaced, so its deadlock history is
///   reset — direction-change counter to zero and `last_act = ReceiveActive`
///   (the winning initiation was received on the now-active session).
/// - On `Archived` (tiebreaker loser): the active session is unchanged, so the
///   deadlock history is left untouched by placement. The caller must then
///   invoke [`on_receive_inactive`] for the successfully decrypted enclosed
///   message; that receive can increment the counter and fire the breaker.
pub(crate) fn commit_received_initiation(
    record: &mut SessionRecord,
    mut new_session: SessionState,
    placement: NewSessionLocation,
) -> Result<(), crate::SignalProtocolError> {
    new_session.set_origin(SessionOrigin::Remote);
    match placement {
        NewSessionLocation::Active => {
            record.replace_active_session(new_session);
            record.reset_direction_change_ctr();
            on_receive_active(record);
            Ok(())
        }
        NewSessionLocation::Archived => {
            record.archive_session(new_session);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use test_case::test_case;

    use super::*;
    use crate::proto::storage::SessionStructure;

    #[test]
    fn send_on_recv_inactive_increments_changes() {
        let mut record = SessionRecord::new_fresh();
        record.set_last_act(LastAct::ReceiveInactive);
        assert_eq!(record.direction_change_ctr(), 0);
        on_send(&mut record);
        assert_eq!(record.direction_change_ctr(), 1);
        assert_eq!(record.last_act(), LastAct::Send);
    }

    #[test_case(LastAct::Send)]
    #[test_case(LastAct::ReceiveInactive)]
    #[test_case(LastAct::ReceiveActive)]
    fn recv_active_no_increment(prev: LastAct) {
        let mut record = SessionRecord::new_fresh();
        record.set_last_act(prev);
        on_receive_active(&mut record);
        assert_eq!(record.direction_change_ctr(), 0);
        assert_eq!(record.last_act(), LastAct::ReceiveActive);
    }

    #[test]
    fn recv_inactive_on_send_detects_deadlock() {
        let mut record =
            SessionRecord::new(SessionState::from_session_structure(SessionStructure {
                ..Default::default()
            }));
        for _i in 0..=MAX_DIR_CHANGES {
            record.increment_direction_change_ctr();
        }
        record.set_last_act(LastAct::ReceiveActive);
        assert!(record.active_session().is_some());
        on_receive_inactive(&mut record).unwrap();
        assert_eq!(record.direction_change_ctr(), 0);
        assert_eq!(record.last_act(), LastAct::ReceiveInactive);
        // The deadlock break archived the active session: it's gone from the
        // active slot and now sits as the single archived session.
        assert!(record.active_session().is_none());
        assert_eq!(record.archived_sessions().count(), 1);
    }

    #[test]
    fn initiate_resets_dir_ctr() {
        let mut record = SessionRecord::new_fresh();
        record.increment_direction_change_ctr();
        on_initiate(
            &mut record,
            SessionState::from_session_structure(SessionStructure {
                ..Default::default()
            }),
        );
        assert_eq!(record.direction_change_ctr(), 0);
    }

    #[test]
    fn initiate_clears_last_act_so_first_send_has_no_phantom_change() {
        // A freshly initiated session inherits no direction-change history:
        // `on_initiate` clears `last_act` to `Unset`, so the first send does not
        // read a stale `ReceiveInactive` (left by the archived-session receive that
        // preceded re-establishment) and count a phantom direction change against
        // the brand-new session.
        let mut record = SessionRecord::new_fresh();
        record.set_last_act(LastAct::ReceiveInactive);
        record.increment_direction_change_ctr();

        on_initiate(
            &mut record,
            SessionState::from_session_structure(SessionStructure {
                ..Default::default()
            }),
        );
        assert_eq!(record.direction_change_ctr(), 0);
        assert_eq!(record.last_act(), LastAct::Unset);

        // The first send on the fresh session must not count a direction change.
        on_send(&mut record);
        assert_eq!(record.direction_change_ctr(), 0);
        assert_eq!(record.last_act(), LastAct::Send);
    }

    #[test]
    fn commit_archived_leaves_deadlock_state_untouched() {
        // Placement alone must not advance the counter or fire the breaker.
        // The caller subsequently records the decrypted enclosed message as
        // an inactive receive; full receive tests cover that separate step.
        let mut record =
            SessionRecord::new(SessionState::from_session_structure(SessionStructure {
                alice_base_key: vec![0x05, 0xff],
                ..Default::default()
            }));
        record.set_last_act(LastAct::Send);
        for _ in 0..MAX_DIR_CHANGES {
            record.increment_direction_change_ctr();
        }
        assert_eq!(record.direction_change_ctr(), MAX_DIR_CHANGES);
        let active_before = record.active_session().map(|s| s.session_id().to_vec());

        // The loser: a lower session id that lost the tiebreak in the caller.
        let loser = SessionState::from_session_structure(SessionStructure {
            alice_base_key: vec![0x05, 0x01],
            ..Default::default()
        });
        commit_received_initiation(&mut record, loser, NewSessionLocation::Archived).unwrap();

        // Counter and marker unchanged; the active session was NOT archived by a
        // spurious break; only the loser sits in the archive.
        assert_eq!(record.direction_change_ctr(), MAX_DIR_CHANGES);
        assert_eq!(record.last_act(), LastAct::Send);
        assert_eq!(
            record.active_session().map(|s| s.session_id().to_vec()),
            active_before
        );
        assert_eq!(record.archived_sessions().count(), 1);
    }

    #[test]
    fn decide_initiation_no_active_session() {
        // With no active session, an incoming initiation always takes the active
        // slot — there is nothing to tiebreak against.
        let record = SessionRecord::new_fresh();
        assert!(record.active_session().is_none());
        assert_matches!(
            decide_initiation_placement(
                &record,
                &[0x01],
                &IdentityKey::decode(&[0x05; 33]).unwrap()
            )
            .unwrap(),
            NewSessionLocation::Active
        );
    }

    // A session the peer already knows (no pending pre-key) always yields the
    // active slot to an incoming initiation, regardless of stored origin.
    #[test_case(SessionOrigin::LocalAcked)]
    #[test_case(SessionOrigin::Remote)]
    #[test_case(SessionOrigin::Legacy)]
    fn decide_initiation_known_by_peer(origin: SessionOrigin) {
        let record = SessionRecord::new(SessionState::from_session_structure(SessionStructure {
            origin: origin.into(),
            alice_base_key: vec![0x01],
            ..Default::default()
        }));
        assert_matches!(
            decide_initiation_placement(
                &record,
                &[0x02],
                &IdentityKey::decode(&[0x05; 33]).unwrap()
            )
            .unwrap(),
            NewSessionLocation::Active
        );
    }

    // A pending pre-key means the session is locally initiated and not yet
    // acknowledged — even when the stored origin is Legacy (the migrated
    // pre-Tahini case). Without one, the peer knows the session regardless of
    // origin.
    #[test_case(SessionOrigin::LocalNew, false, true)]
    #[test_case(SessionOrigin::LocalAcked, false, true)]
    #[test_case(SessionOrigin::Remote, false, true)]
    #[test_case(SessionOrigin::Legacy, false, true)]
    #[test_case(SessionOrigin::LocalNew, true, false)]
    #[test_case(SessionOrigin::Legacy, true, false)]
    fn known_by_peer_keys_on_pending_pre_key(
        origin: SessionOrigin,
        has_pending: bool,
        expected_known: bool,
    ) {
        use crate::proto::storage::session_structure::PendingPreKey;
        let state = SessionState::from_session_structure(SessionStructure {
            origin: origin.into(),
            pending_pre_key: has_pending.then(PendingPreKey::default),
            ..Default::default()
        });
        assert_eq!(state.is_known_by_peer(), expected_known);
    }

    #[test]
    fn cross_upgrade_simultaneous_init_converges() {
        use crate::proto::storage::session_structure::PendingPreKey;

        // Both sides initiate, and their pre-key messages cross. One side is a
        // full Tahini session (origin LocalNew); the other is a migrated
        // pre-Tahini session (origin reads as Legacy) that still carries a
        // pending pre-key. Both must run the SID tiebreak and converge on the
        // same active session (the higher base key wins on both sides). Before
        // is_known_by_peer keyed on the pending pre-key, the Legacy side yielded
        // unconditionally and the two could diverge.

        // Returns the SID of whichever session ends up active after receiving a
        // crossing initiation: the incoming one if it takes the active slot,
        // otherwise our own.
        let active_after = |origin: SessionOrigin, own_sid: &[u8], incoming: &[u8]| -> Vec<u8> {
            let record =
                SessionRecord::new(SessionState::from_session_structure(SessionStructure {
                    origin: origin.into(),
                    alice_base_key: own_sid.to_vec(),
                    remote_identity_public: vec![0x05; 33],
                    pending_pre_key: Some(PendingPreKey::default()),
                    ..Default::default()
                }));
            match decide_initiation_placement(
                &record,
                incoming,
                &IdentityKey::decode(&[0x05; 33]).unwrap(),
            )
            .unwrap()
            {
                NewSessionLocation::Active => incoming.to_vec(),
                NewSessionLocation::Archived => own_sid.to_vec(),
            }
        };

        for (alice_sid, bob_sid) in [
            (vec![0x01], vec![0x02]), // Bob's SID higher
            (vec![0x02], vec![0x01]), // Alice's SID higher
        ] {
            let alice_active = active_after(SessionOrigin::Legacy, &alice_sid, &bob_sid);
            let bob_active = active_after(SessionOrigin::LocalNew, &bob_sid, &alice_sid);
            // Convergence: both sides pick the same active session...
            assert_eq!(alice_active, bob_active, "sids {alice_sid:?}/{bob_sid:?}");
            // ...and it is the higher SID.
            assert_eq!(alice_active, std::cmp::max(alice_sid, bob_sid));
        }
    }
}
