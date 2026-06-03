//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use futures_util::FutureExt as _;
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use libsignal_protocol::*;
use libsignal_protocol_test_support::{Event, Participant};
use rand::prelude::*;

#[derive(Arbitrary, Debug, PartialEq, Eq)]
pub enum Who {
    A,
    B,
}

fuzz_target!(|actions: Vec<(Who, Event)>| {
    // Logs default to Off because we deliberately introduce session errors in this test.
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Off)
        .parse_default_env()
        .try_init();

    async {
        let mut csprng = StdRng::seed_from_u64(0);

        let mut alice = Participant::new(
            "alice",
            ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap()),
            &mut csprng,
        );
        let mut bob = Participant::new(
            "bob",
            ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap()),
            &mut csprng,
        );

        for (who, event) in actions {
            let (me, them) = match who {
                Who::A => (&mut alice, &mut bob),
                Who::B => (&mut bob, &mut alice),
            };
            event.run(me, them, &mut csprng).await
        }

        // Allow time to quiesce: bring both sides up to speed, send one message in each direction
        // (synchronized), and service resend requests until both queues are empty.
        log::info!("Quiescing...");
        while alice.has_pending_incoming_messages() || bob.has_pending_incoming_messages() {
            alice.receive_messages(&mut bob, &mut csprng).await;
            bob.receive_messages(&mut alice, &mut csprng).await;
        }

        async fn exchange_messages_until_agreement(
            attempts: usize,
            alice: &mut Participant,
            bob: &mut Participant,
            rng: &mut (impl Rng + CryptoRng),
        ) {
            for _ in 0..attempts {
                // Go back to taking turns and see if things even out.
                alice.send_message(bob, rng).await;
                bob.receive_messages(alice, rng).await;
                bob.send_message(alice, rng).await;
                alice.receive_messages(bob, rng).await;

                let a_to_b_session = alice
                    .current_store()
                    .load_session(bob.address())
                    .await
                    .expect("can load")
                    .expect("Alice has a session with Bob");
                let b_to_a_session = bob
                    .current_store()
                    .load_session(alice.address())
                    .await
                    .expect("can load")
                    .expect("Bob has a session with Alice");
                if a_to_b_session
                    .alice_base_key()
                    .expect("A->B session established")
                    == b_to_a_session
                        .alice_base_key()
                        .expect("B->A session established")
                {
                    return;
                }
            }
            panic!(
                "even after {attempts} more messages in each direction, Alice and Bob are not on the same session"
            );
        }

        exchange_messages_until_agreement(10, &mut alice, &mut bob, &mut csprng).await;
    }
    .now_or_never()
    .expect("sync");
});
