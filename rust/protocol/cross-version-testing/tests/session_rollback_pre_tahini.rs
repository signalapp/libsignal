//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Rolling a client back from Tahini to the pinned pre-Tahini release.
//!
//! The rolled-back side loads the state Tahini wrote, then keeps talking to a
//! peer that is either also rolled back or still on Tahini.

use libsignal_protocol_cross_version_testing::*;
use proptest::prelude::*;
use rand::SeedableRng as _;
use rand::rngs::StdRng;

#[derive(Clone, Copy, Debug)]
enum Action {
    /// `(alice_sends, burst)`: one to four messages, delivered immediately.
    Send(bool, u8),
    /// The given side archives its active session, so its next send
    /// initiates a new one.
    Reset { alice: bool },
}

#[derive(Clone, Copy, Debug)]
enum Rollback {
    Both,
    AliceOnly,
    BobOnly,
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        4 => (any::<bool>(), any::<u8>()).prop_map(|(a, b)| Action::Send(a, b)),
        1 => any::<bool>().prop_map(|alice| Action::Reset { alice }),
    ]
}

fn send_action() -> impl Strategy<Value = Action> {
    (any::<bool>(), any::<u8>()).prop_map(|(a, b)| Action::Send(a, b))
}

fn rollback() -> impl Strategy<Value = Rollback> {
    prop_oneof![
        Just(Rollback::Both),
        Just(Rollback::AliceOnly),
        Just(Rollback::BobOnly)
    ]
}

fn ensure_session(
    sender: &mut dyn LibSignalProtocolStore,
    sender_name: &str,
    recipient: &mut dyn LibSignalProtocolStore,
    recipient_name: &str,
    rng: &mut StdRng,
) {
    if sender.has_active_session(recipient_name) {
        return;
    }
    let bundle = recipient.create_pre_key_bundle(rng);
    sender.process_pre_key_bundle(recipient_name, sender_name, bundle, rng);
    assert!(sender.has_active_session(recipient_name));
}

fn send_and_deliver(
    sender: &mut dyn LibSignalProtocolStore,
    sender_name: &str,
    recipient: &mut dyn LibSignalProtocolStore,
    recipient_name: &str,
    message_id: u64,
    rng: &mut StdRng,
) {
    ensure_session(sender, sender_name, recipient, recipient_name, rng);
    let plaintext = message_id.to_le_bytes();
    let (ciphertext, msg_type) = sender
        .try_encrypt(recipient_name, sender_name, &plaintext, rng)
        .unwrap_or_else(|e| {
            panic!(
                "{sender_name} ({}) -> {recipient_name} ({}): encryption failed: {e}",
                sender.version(),
                recipient.version()
            )
        });
    let decrypted = recipient
        .decrypt(sender_name, recipient_name, &ciphertext, msg_type, rng)
        .unwrap_or_else(|e| {
            panic!(
                "{sender_name} ({}) -> {recipient_name} ({}): decryption failed: {e}",
                sender.version(),
                recipient.version()
            )
        });
    assert_eq!(decrypted, plaintext);
}

fn apply_actions(
    alice: &mut dyn LibSignalProtocolStore,
    bob: &mut dyn LibSignalProtocolStore,
    actions: &[Action],
    next_message_id: &mut u64,
    rng: &mut StdRng,
) {
    for action in actions.iter().copied() {
        match action {
            Action::Send(alice_sends, burst) => {
                for _ in 0..(burst % 4) + 1 {
                    if alice_sends {
                        send_and_deliver(alice, "alice", bob, "bob", *next_message_id, rng);
                    } else {
                        send_and_deliver(bob, "bob", alice, "alice", *next_message_id, rng);
                    }
                    *next_message_id += 1;
                }
            }
            Action::Reset { alice: true } => alice.archive_active_session("bob"),
            Action::Reset { alice: false } => bob.archive_active_session("alice"),
        }
    }
}

fn stabilize_conversation(
    alice: &mut dyn LibSignalProtocolStore,
    bob: &mut dyn LibSignalProtocolStore,
    next_message_id: &mut u64,
    rng: &mut StdRng,
) {
    for _ in 0..4 {
        send_and_deliver(alice, "alice", bob, "bob", *next_message_id, rng);
        *next_message_id += 1;
        send_and_deliver(bob, "bob", alice, "alice", *next_message_id, rng);
        *next_message_id += 1;
    }
}

/// Rolls `store` back if `roll_back`, asserting the active session survives.
fn maybe_roll_back(
    store: LibSignalProtocolCurrent,
    remote: &str,
    roll_back: bool,
) -> Box<dyn LibSignalProtocolStore> {
    if !roll_back {
        return Box::new(store);
    }
    let before = store.active_session_id(remote);
    let rolled_back = store.to_pre_tahini_for_remote(remote);
    assert_eq!(
        rolled_back.active_session_id(remote),
        before,
        "active session should survive rollback"
    );
    Box::new(rolled_back)
}

fn archived_session_count(store: &LibSignalProtocolCurrent, remote: &str) -> usize {
    store
        .serialize_conversation_state(remote)
        .session_record
        .map(|bytes| {
            libsignal_protocol_current::SessionRecord::deserialize(&bytes)
                .expect("valid record")
                .archived_session_count()
        })
        .unwrap_or(0)
}

/// Shape of each side's stored state at the moment of rollback.
#[derive(Debug)]
struct AtRollback {
    archived_sessions: usize,
    /// Size of the session record as Tahini wrote it, and after pre-Tahini
    /// loads and re-serializes it.
    record_len: usize,
    record_len_after_pre_tahini_rewrite: usize,
}

fn at_rollback(store: &LibSignalProtocolCurrent, remote: &str) -> AtRollback {
    let record_len = store
        .serialize_conversation_state(remote)
        .session_record
        .map_or(0, |r| r.len());
    let record_len_after_pre_tahini_rewrite = store
        .to_pre_tahini_for_remote(remote)
        .serialize_conversation_state(remote)
        .session_record
        .map_or(0, |r| r.len());
    AtRollback {
        archived_sessions: archived_session_count(store, remote),
        record_len,
        record_len_after_pre_tahini_rewrite,
    }
}

fn run(
    seed: u64,
    tahini_phase: &[Action],
    rollback: Rollback,
    rolled_back_phase: &[Action],
) -> (AtRollback, AtRollback) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut next_message_id = 0u64;

    let mut alice = LibSignalProtocolCurrent::new(&mut rng);
    let mut bob = LibSignalProtocolCurrent::new(&mut rng);
    apply_actions(
        &mut alice,
        &mut bob,
        tahini_phase,
        &mut next_message_id,
        &mut rng,
    );
    stabilize_conversation(&mut alice, &mut bob, &mut next_message_id, &mut rng);
    let shape = (at_rollback(&alice, "bob"), at_rollback(&bob, "alice"));

    let (roll_back_alice, roll_back_bob) = match rollback {
        Rollback::Both => (true, true),
        Rollback::AliceOnly => (true, false),
        Rollback::BobOnly => (false, true),
    };
    let mut alice = maybe_roll_back(alice, "bob", roll_back_alice);
    let mut bob = maybe_roll_back(bob, "alice", roll_back_bob);

    apply_actions(
        &mut *alice,
        &mut *bob,
        rolled_back_phase,
        &mut next_message_id,
        &mut rng,
    );
    stabilize_conversation(&mut *alice, &mut *bob, &mut next_message_id, &mut rng);
    for _ in 0..10 {
        send_and_deliver(
            &mut *alice,
            "alice",
            &mut *bob,
            "bob",
            next_message_id,
            &mut rng,
        );
        next_message_id += 1;
        send_and_deliver(
            &mut *bob,
            "bob",
            &mut *alice,
            "alice",
            next_message_id,
            &mut rng,
        );
        next_message_id += 1;
    }
    shape
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn tahini_state_survives_rollback_to_pre_tahini(
        seed in any::<u64>(),
        tahini_phase in proptest::collection::vec(action(), 0..32),
        rollback in rollback(),
        rolled_back_phase in proptest::collection::vec(send_action(), 0..24),
    ) {
        run(seed, &tahini_phase, rollback, &rolled_back_phase);
    }
}

/// The proptest gives no guarantee that any case rolls back a record with a
/// full Tahini archive and Tahini-only fields. Pin one that does.
#[test]
fn full_tahini_archive_survives_rollback_to_pre_tahini() {
    let resets: Vec<Action> = (0..6)
        .flat_map(|i| {
            [
                Action::Reset { alice: i % 2 == 0 },
                Action::Send(i % 2 == 0, 1),
                Action::Send(i % 2 != 0, 1),
            ]
        })
        .collect();
    let sends: Vec<Action> = (0..8).map(|i| Action::Send(i % 3 == 0, i)).collect();
    for rollback in [Rollback::Both, Rollback::AliceOnly, Rollback::BobOnly] {
        let (alice, bob) = run(0xC0FFEE, &resets, rollback, &sends);
        for (name, side) in [("alice", alice), ("bob", bob)] {
            assert_eq!(
                side.archived_sessions, 3,
                "{name}'s archive should be full at rollback"
            );
            // Pre-Tahini drops the Tahini-only fields when it rewrites the
            // record, so a shorter rewrite shows they were present.
            assert!(
                side.record_len_after_pre_tahini_rewrite < side.record_len,
                "{name}'s record should carry Tahini-only fields: {side:?}"
            );
        }
    }
}
