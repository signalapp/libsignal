//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol_cross_version_testing::*;
use proptest::prelude::*;
use rand::SeedableRng as _;
use rand::rngs::StdRng;

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
    let _ = sender_name;
}

fn send_and_deliver(
    sender: &mut dyn LibSignalProtocolStore,
    sender_name: &str,
    recipient: &mut dyn LibSignalProtocolStore,
    recipient_name: &str,
    message_id: u64,
    rng: &mut StdRng,
) {
    // `ensure_session` only creates one if there isn't an *active* session at
    // all — a simpler check than what real clients do, which is to ask whether
    // they have a *usable* sender chain (`SessionUsabilityRequirements`) and
    // rebuild via pre-key bundle if not.
    ensure_session(sender, sender_name, recipient, recipient_name, rng);
    let plaintext = message_id.to_le_bytes();
    let (ciphertext, msg_type) = sender
        .try_encrypt(recipient_name, sender_name, &plaintext, rng)
        .expect("encryption should succeed");
    let decrypted = recipient
        .decrypt(sender_name, recipient_name, &ciphertext, msg_type, rng)
        .expect("decryption should succeed");
    assert_eq!(decrypted, plaintext);
}

fn apply_phase_actions(
    alice: &mut dyn LibSignalProtocolStore,
    bob: &mut dyn LibSignalProtocolStore,
    actions: &[(bool, u8)],
    next_message_id: &mut u64,
    rng: &mut StdRng,
) {
    for (alice_sends, burst) in actions.iter().copied() {
        let sends = usize::from((burst % 4) + 1);
        if alice_sends {
            for _ in 0..sends {
                send_and_deliver(alice, "alice", bob, "bob", *next_message_id, rng);
                *next_message_id += 1;
            }
        } else {
            for _ in 0..sends {
                send_and_deliver(bob, "bob", alice, "alice", *next_message_id, rng);
                *next_message_id += 1;
            }
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

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn pre_tahini_session_store_roundtrip_survives_staged_upgrade_to_current(
        seed in any::<u64>(),
        phase1 in proptest::collection::vec((any::<bool>(), any::<u8>()), 0..24),
        phase2 in proptest::collection::vec((any::<bool>(), any::<u8>()), 0..24),
        phase3 in proptest::collection::vec((any::<bool>(), any::<u8>()), 0..24),
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut next_message_id = 0u64;

        let mut alice_pre_tahini = LibSignalProtocolPreTahini::new(&mut rng);
        let mut bob_pre_tahini = LibSignalProtocolPreTahini::new(&mut rng);
        apply_phase_actions(&mut alice_pre_tahini, &mut bob_pre_tahini, &phase1, &mut next_message_id, &mut rng);
        stabilize_conversation(&mut alice_pre_tahini, &mut bob_pre_tahini, &mut next_message_id, &mut rng);

        // Capture each side's session id (= alice_base_key) at every migration
        // boundary. Ratcheting does not change this identifier; a different id
        // after migration means the original session was lost and a fresh
        // pre-key bundle was used to rebuild one.
        let alice_session_pre_migration = alice_pre_tahini.active_session_id("bob");
        let bob_session_pre_migration = bob_pre_tahini.active_session_id("alice");
        prop_assert!(alice_session_pre_migration.is_some(), "alice has a session after phase 1");
        prop_assert!(bob_session_pre_migration.is_some(), "bob has a session after phase 1");

        let mut alice_pre_tahini: Box<dyn LibSignalProtocolStore> =
            Box::new(alice_pre_tahini.reload_session_only("bob"));
        let mut bob_current = bob_pre_tahini.to_current_for_remote("alice");
        let alice_session_post_reload = alice_pre_tahini.active_session_id("bob");
        prop_assert_eq!(
            alice_session_post_reload.as_ref(),
            alice_session_pre_migration.as_ref(),
            "alice's session id should survive the pre-tahini reload"
        );
        let bob_session_post_migration = bob_current.active_session_id("alice");
        prop_assert_eq!(
            bob_session_post_migration.as_ref(),
            bob_session_pre_migration.as_ref(),
            "bob's session id should survive the pre-tahini->current migration"
        );
        apply_phase_actions(&mut *alice_pre_tahini, &mut *bob_current, &phase2, &mut next_message_id, &mut rng);
        stabilize_conversation(&mut *alice_pre_tahini, &mut *bob_current, &mut next_message_id, &mut rng);

        let mut alice_current = alice_pre_tahini.to_current_for_remote("bob");
        let mut bob_current = bob_current.to_current_for_remote("alice");
        prop_assert_eq!(
            alice_current.active_session_id("bob"),
            alice_session_pre_migration,
            "alice's session id should survive the pre-tahini->current migration"
        );
        prop_assert_eq!(
            bob_current.active_session_id("alice"),
            bob_session_pre_migration,
            "bob's session id should survive the current->current re-upgrade"
        );
        apply_phase_actions(&mut *alice_current, &mut *bob_current, &phase3, &mut next_message_id, &mut rng);
        stabilize_conversation(&mut *alice_current, &mut *bob_current, &mut next_message_id, &mut rng);

        for i in 0..10 {
            send_and_deliver(&mut *alice_current, "alice", &mut *bob_current, "bob", next_message_id + i, &mut rng);
            send_and_deliver(&mut *bob_current, "bob", &mut *alice_current, "alice", next_message_id + 100 + i, &mut rng);
        }
    }
}
