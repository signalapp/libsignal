//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::FutureExt;
use libsignal_protocol_cross_version_testing::*;
use proptest::prelude::*;
use rand::SeedableRng as _;
use rand::rngs::StdRng;

fn arb_event() -> impl Strategy<Value = Event> {
    prop_oneof![
        Just(Event::Archive),
        Just(Event::Snapshot),
        any::<u8>().prop_map(|index| Event::Restore { index }),
        Just(Event::Receive),
        Just(Event::Drop),
        Just(Event::Shuffle),
        Just(Event::Corrupt),
        any::<u8>().prop_map(|count_times_eight| Event::Send { count_times_eight }),
    ]
}

fn apply_actions(
    alice: &mut Participant,
    bob: &mut Participant,
    actions: &[(bool, Event)],
    rng: &mut StdRng,
) {
    for (who, event) in actions.iter().cloned() {
        let (me, them) = if who {
            (&mut *alice, &mut *bob)
        } else {
            (&mut *bob, &mut *alice)
        };
        event.run(me, them, rng).now_or_never().expect("sync");
    }
}

fn quiesce(alice: &mut Participant, bob: &mut Participant, rng: &mut StdRng) -> bool {
    let mut rounds = 0;
    while alice.has_pending_incoming_messages() || bob.has_pending_incoming_messages() {
        alice
            .receive_messages(bob, rng)
            .now_or_never()
            .expect("sync");
        bob.receive_messages(alice, rng)
            .now_or_never()
            .expect("sync");
        rounds += 1;
        if rounds >= 200 {
            return false;
        }
    }
    true
}

fn clean_exchange_and_assert_convergence(
    alice: &mut Participant,
    bob: &mut Participant,
    rng: &mut StdRng,
) {
    for _ in 0..10 {
        alice.send_message(bob, rng).now_or_never().expect("sync");
        bob.receive_messages(alice, rng)
            .now_or_never()
            .expect("sync");
        bob.send_message(alice, rng).now_or_never().expect("sync");
        alice
            .receive_messages(bob, rng)
            .now_or_never()
            .expect("sync");
    }

    assert_eq!(
        alice.active_session_id(bob.address()),
        bob.active_session_id(alice.address()),
        "active sessions did not converge after a clean suffix"
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    // `seed` drives all of the test's randomness: the store identity keys,
    // base keys (= session ids), ratchet keys, and any other internal draws.
    // The same proptest input reproduces the same Tahini tiebreaking outcome.

    #[test]
    fn current_and_pre_tahini_all_sent_messages_are_accounted_for_after_quiescence(
        seed in any::<u64>(),
        actions in proptest::collection::vec((any::<bool>(), arb_event()), 0..40)
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut alice =
            Participant::new("alice", "alice", Box::new(LibSignalProtocolCurrent::new(&mut rng)));
        let mut bob =
            Participant::new("bob", "bob", Box::new(LibSignalProtocolPreTahini::new(&mut rng)));

        apply_actions(&mut alice, &mut bob, &actions, &mut rng);

        prop_assert!(quiesce(&mut alice, &mut bob, &mut rng));
        prop_assert!(alice.all_messages_accounted_for());
        prop_assert!(bob.all_messages_accounted_for());
    }

    #[test]
    fn current_and_pre_tahini_converge_after_a_clean_suffix(
        seed in any::<u64>(),
        actions in proptest::collection::vec((any::<bool>(), arb_event()), 0..40)
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut alice =
            Participant::new("alice", "alice", Box::new(LibSignalProtocolCurrent::new(&mut rng)));
        let mut bob =
            Participant::new("bob", "bob", Box::new(LibSignalProtocolPreTahini::new(&mut rng)));

        apply_actions(&mut alice, &mut bob, &actions, &mut rng);

        prop_assert!(quiesce(&mut alice, &mut bob, &mut rng));
        clean_exchange_and_assert_convergence(&mut alice, &mut bob, &mut rng);
    }
}
