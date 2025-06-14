//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::new_without_default)]

pub use libsignal_protocol_current::{
    CiphertextMessageType, PreKeyBundle, UnidentifiedSenderMessageContent,
};

pub trait LibSignalProtocolStore {
    fn version(&self) -> &'static str;
    fn create_pre_key_bundle(&mut self) -> PreKeyBundle;
    fn process_pre_key_bundle(&mut self, remote: &str, pre_key_bundle: PreKeyBundle);
    fn encrypt(&mut self, remote: &str, msg: &[u8]) -> (Vec<u8>, CiphertextMessageType);
    fn decrypt(&mut self, remote: &str, msg: &[u8], msg_type: CiphertextMessageType) -> Vec<u8>;

    fn encrypt_sealed_sender_v1(
        &self,
        remote: &str,
        msg: &UnidentifiedSenderMessageContent,
    ) -> Vec<u8>;
    fn encrypt_sealed_sender_v2(
        &self,
        remote: &str,
        msg: &UnidentifiedSenderMessageContent,
    ) -> Vec<u8>;
    fn decrypt_sealed_sender(&self, msg: &[u8]) -> UnidentifiedSenderMessageContent;
}

mod current;
pub use current::LibSignalProtocolCurrent;

mod v70;
pub use v70::LibSignalProtocolV70;

// Use this function to debug tests
pub fn init_test_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .is_test(true)
        .try_init();
}

pub fn try_all_combinations(
    f: fn(&mut dyn LibSignalProtocolStore, &mut dyn LibSignalProtocolStore),
    make_previous: &[fn() -> Box<dyn LibSignalProtocolStore>],
) {
    let run = |alice_store: &mut dyn LibSignalProtocolStore,
               bob_store: &mut dyn LibSignalProtocolStore| {
        log::info!(
            "alice: {}, bob: {}",
            alice_store.version(),
            bob_store.version()
        );
        f(alice_store, bob_store)
    };

    // Current<->Current, to test that the test is correct.
    run(
        &mut LibSignalProtocolCurrent::new(),
        &mut LibSignalProtocolCurrent::new(),
    );

    // Current<->Previous
    for bob_store_maker in make_previous {
        let mut alice_store = LibSignalProtocolCurrent::new();
        let mut bob_store = bob_store_maker();
        run(&mut alice_store, &mut *bob_store);
    }

    // Previous<->Current
    for alice_store_maker in make_previous {
        let mut alice_store = alice_store_maker();
        let mut bob_store = LibSignalProtocolCurrent::new();
        run(&mut *alice_store, &mut bob_store);
    }
}
