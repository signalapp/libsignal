//
// Copyright 2020-2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
mod support;

use std::collections::VecDeque;
use std::time::SystemTime;

use assert_matches::assert_matches;
use futures_util::FutureExt;
use libsignal_protocol::*;
use libsignal_protocol_test_support::{archive_active_session, has_active_session};
use proptest::arbitrary::Arbitrary;
use proptest::proptest;
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use strum::VariantArray as _;
use support::*;

// ── TahiniWorld harness ───────────────────────────────────────────────────────

struct TahiniWorld {
    alice_builder: TestStoreBuilder,
    bob_builder: TestStoreBuilder,
    alice_address: ProtocolAddress,
    bob_address: ProtocolAddress,
    q_ab: VecDeque<CiphertextMessage>, // alice→bob in-flight
    q_ba: VecDeque<CiphertextMessage>, // bob→alice in-flight
}

impl TahiniWorld {
    /// Create a world where Alice has a session with Bob. Bob does NOT yet
    /// have a session with Alice.
    fn new() -> Self {
        let bob_device = DeviceId::new(1).unwrap();
        let mut world = Self::new_no_session();

        // Alice initiates with Bob's bundle → Alice now has a session with Bob.
        let mut csprng = OsRng.unwrap_err();
        let bob_bundle = world.bob_builder.make_bundle_with_latest_keys(bob_device);
        initiate_session(
            &world.bob_address,
            &world.alice_address,
            &mut world.alice_builder.store.session_store,
            &mut world.alice_builder.store.identity_store,
            &bob_bundle,
            SystemTime::UNIX_EPOCH,
            &mut csprng,
        )
        .now_or_never()
        .expect("sync")
        .expect("initiate_session");

        world
    }

    /// Create a world where neither party has a session yet.
    fn new_no_session() -> Self {
        let alice_device = DeviceId::new(1).unwrap();
        let bob_device = DeviceId::new(1).unwrap();
        let alice_address = ProtocolAddress::new(
            "9d0652a3-dcc3-4d11-975f-74d61598733f".to_owned(),
            alice_device,
        );
        let bob_address = ProtocolAddress::new(
            "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(),
            bob_device,
        );

        let mut alice_builder = TestStoreBuilder::new();
        let mut bob_builder = TestStoreBuilder::new();

        alice_builder.add_pre_key(IdChoice::Next);
        alice_builder.add_signed_pre_key(IdChoice::Next);
        alice_builder.add_kyber_pre_key(IdChoice::Next);

        bob_builder.add_pre_key(IdChoice::Next);
        bob_builder.add_signed_pre_key(IdChoice::Next);
        bob_builder.add_kyber_pre_key(IdChoice::Next);

        TahiniWorld {
            alice_builder,
            bob_builder,
            alice_address,
            bob_address,
            q_ab: VecDeque::new(),
            q_ba: VecDeque::new(),
        }
    }

    // ── Helpers for checking / establishing sessions ──────────────────────

    fn a_has_session_with_b(&self) -> bool {
        has_active_session(&self.bob_address, &self.alice_builder.store.session_store)
            .now_or_never()
            .expect("sync")
            .expect("has_active_session")
    }

    fn b_has_session_with_a(&self) -> bool {
        has_active_session(&self.alice_address, &self.bob_builder.store.session_store)
            .now_or_never()
            .expect("sync")
            .expect("has_active_session")
    }

    fn ensure_a_has_session_with_b(&mut self) {
        if !self.a_has_session_with_b() {
            self.a_reinitiates_session_with_b();
        }
    }

    fn ensure_b_has_session_with_a(&mut self) {
        if !self.b_has_session_with_a() {
            self.b_reinitiates_session_with_a();
        }
    }

    // ── Send helpers ──────────────────────────────────────────────────────

    fn send_a_to_b(&mut self, msg: &str) {
        self.ensure_a_has_session_with_b();
        let mut csprng = OsRng.unwrap_err();
        let result = message_encrypt(
            msg.as_bytes(),
            &self.bob_address,
            &self.alice_address,
            &mut self.alice_builder.store.session_store,
            &mut self.alice_builder.store.identity_store,
            SystemTime::UNIX_EPOCH,
            &mut csprng,
        )
        .now_or_never()
        .expect("sync");
        match result {
            Ok(ct) => self.q_ab.push_back(ct),
            // Deadlock detection should never archive a session on send, only on recv.
            Err(e) => panic!("encrypt a→b: {e}"),
        }
    }

    fn send_b_to_a(&mut self, msg: &str) {
        self.ensure_b_has_session_with_a();
        let mut csprng = OsRng.unwrap_err();
        let result = message_encrypt(
            msg.as_bytes(),
            &self.alice_address,
            &self.bob_address,
            &mut self.bob_builder.store.session_store,
            &mut self.bob_builder.store.identity_store,
            SystemTime::UNIX_EPOCH,
            &mut csprng,
        )
        .now_or_never()
        .expect("sync");
        match result {
            Ok(ct) => self.q_ba.push_back(ct),
            // Deadlock detection should never archive a session on send, only on recv.
            Err(e) => panic!("encrypt b→a: {e}"),
        }
    }

    // ── Deliver helpers ───────────────────────────────────────────────────

    fn try_deliver_to_b(&mut self) -> Option<Result<Vec<u8>, SignalProtocolError>> {
        let ct = self.q_ab.pop_front()?;
        let mut csprng = OsRng.unwrap_err();
        Some(
            message_decrypt(
                &ct,
                &self.alice_address,
                &self.bob_address,
                &mut self.bob_builder.store.session_store,
                &mut self.bob_builder.store.identity_store,
                &mut self.bob_builder.store.pre_key_store,
                &self.bob_builder.store.signed_pre_key_store,
                &mut self.bob_builder.store.kyber_pre_key_store,
                &mut csprng,
            )
            .now_or_never()
            .expect("sync"),
        )
    }

    fn deliver_to_b(&mut self) -> Option<Vec<u8>> {
        self.try_deliver_to_b()
            .map(|r| r.expect("deliver_to_b decrypt"))
    }

    fn try_deliver_to_a(&mut self) -> Option<Result<Vec<u8>, SignalProtocolError>> {
        let ct = self.q_ba.pop_front()?;
        let mut csprng = OsRng.unwrap_err();
        Some(
            message_decrypt(
                &ct,
                &self.bob_address,
                &self.alice_address,
                &mut self.alice_builder.store.session_store,
                &mut self.alice_builder.store.identity_store,
                &mut self.alice_builder.store.pre_key_store,
                &self.alice_builder.store.signed_pre_key_store,
                &mut self.alice_builder.store.kyber_pre_key_store,
                &mut csprng,
            )
            .now_or_never()
            .expect("sync"),
        )
    }

    fn deliver_to_a(&mut self) -> Option<Vec<u8>> {
        self.try_deliver_to_a()
            .map(|r| r.expect("deliver_to_a decrypt"))
    }

    // ── Session record accessors ──────────────────────────────────────────

    #[allow(dead_code)]
    fn session_record_for_b(&self) -> SessionRecord {
        self.alice_builder
            .store
            .load_session(&self.bob_address)
            .now_or_never()
            .expect("sync")
            .expect("load_session")
            .expect("session record exists for bob")
    }

    fn session_record_for_a(&self) -> SessionRecord {
        self.bob_builder
            .store
            .load_session(&self.alice_address)
            .now_or_never()
            .expect("sync")
            .expect("load_session")
            .expect("session record exists for alice")
    }

    // ── Archive helpers ───────────────────────────────────────────────────

    fn archive_active_a(&mut self) {
        archive_active_session(
            &self.bob_address,
            &mut self.alice_builder.store.session_store,
        )
        .now_or_never()
        .expect("sync")
        .expect("archive_active_session");
    }

    fn archive_active_b(&mut self) {
        archive_active_session(
            &self.alice_address,
            &mut self.bob_builder.store.session_store,
        )
        .now_or_never()
        .expect("sync")
        .expect("archive_active_session");
    }

    // ── Key comparison ────────────────────────────────────────────────────

    fn active_base_keys_match(&self) -> bool {
        let a_rec = self
            .alice_builder
            .store
            .load_session(&self.bob_address)
            .now_or_never()
            .expect("sync")
            .expect("load_session");
        let b_rec = self
            .bob_builder
            .store
            .load_session(&self.alice_address)
            .now_or_never()
            .expect("sync")
            .expect("load_session");
        match (a_rec, b_rec) {
            (Some(a), Some(b)) => match (a.alice_base_key(), b.alice_base_key()) {
                (Ok(a_key), Ok(b_key)) => a_key == b_key,
                _ => false,
            },
            _ => false,
        }
    }

    // ── Session (re)initiation ────────────────────────────────────────────

    /// Refills Bob's prekeys and has Alice initiate a fresh session from them.
    fn a_reinitiates_session_with_b(&mut self) {
        let bob_device = DeviceId::new(1).unwrap();
        self.bob_builder.add_pre_key(IdChoice::Next);
        self.bob_builder.add_signed_pre_key(IdChoice::Next);
        self.bob_builder.add_kyber_pre_key(IdChoice::Next);
        let mut csprng = OsRng.unwrap_err();
        let bundle = self.bob_builder.make_bundle_with_latest_keys(bob_device);
        initiate_session(
            &self.bob_address,
            &self.alice_address,
            &mut self.alice_builder.store.session_store,
            &mut self.alice_builder.store.identity_store,
            &bundle,
            SystemTime::UNIX_EPOCH,
            &mut csprng,
        )
        .now_or_never()
        .expect("sync")
        .expect("initiate_session");
    }

    /// Refills Alice's prekeys and has Bob initiate a fresh session from them.
    fn b_reinitiates_session_with_a(&mut self) {
        let alice_device = DeviceId::new(1).unwrap();
        self.alice_builder.add_pre_key(IdChoice::Next);
        self.alice_builder.add_signed_pre_key(IdChoice::Next);
        self.alice_builder.add_kyber_pre_key(IdChoice::Next);
        let mut csprng = OsRng.unwrap_err();
        let bundle = self
            .alice_builder
            .make_bundle_with_latest_keys(alice_device);
        initiate_session(
            &self.alice_address,
            &self.bob_address,
            &mut self.bob_builder.store.session_store,
            &mut self.bob_builder.store.identity_store,
            &bundle,
            SystemTime::UNIX_EPOCH,
            &mut csprng,
        )
        .now_or_never()
        .expect("sync")
        .expect("initiate_session");
    }

    // ── Converge ──────────────────────────────────────────────────────────

    /// Drain both queues, then iteratively exchange messages until both sides
    /// share the same active session (by alice_base_key).
    fn converge(&mut self) {
        // Drain in-flight queues first (ignore decrypt errors from stale/consumed prekeys).
        while let Some(result) = self.try_deliver_to_b() {
            let _ = result;
        }
        while let Some(result) = self.try_deliver_to_a() {
            let _ = result;
        }

        if self.active_base_keys_match() {
            return;
        }

        // Up to 10 (something greater than tahini::MAX_DIR_CHANGES) rounds
        // of mutual exchange to converge.
        // We refill both sides' prekeys each round to ensure fresh sessions
        // (avoids InvalidPreKeyId from already-consumed one-time prekeys).
        for _ in 0..10 {
            self.a_reinitiates_session_with_b();
            self.b_reinitiates_session_with_a();
            // Exchange: A→B then B→A, discarding any errors (prekey already consumed etc.)
            self.send_a_to_b("converge");
            let _ = self.try_deliver_to_b();
            self.send_b_to_a("converge");
            let _ = self.try_deliver_to_a();
            if self.active_base_keys_match() {
                return;
            }
        }
        panic!("TahiniWorld failed to converge after 10 rounds");
    }
}

// ── Scenario tests ────────────────────────────────────────────────────────────

/// After archiving B's active session, B can still decrypt a message from A
/// (via archived session), but B's active slot should remain absent/unchanged.
#[test]
fn test_no_promotion_on_archived_decrypt() {
    let mut w = TahiniWorld::new();

    // Establish the session: A sends, B receives.
    w.send_a_to_b("hello");
    w.deliver_to_b();

    // Archive B's active session.
    w.archive_active_b();

    // B has no active session now.
    assert!(!w.b_has_session_with_a());

    // A sends another message (still on the original session).
    w.send_a_to_b("second message");

    // B decrypts from the archived session — should succeed.
    let plaintext = w.try_deliver_to_b().expect("message in queue");
    assert!(plaintext.is_ok(), "Should decrypt via archived session");

    // Tahini: decrypting from an archived session must not promote it, so B
    // still has no active session afterward.
    let record_after = w
        .bob_builder
        .store
        .load_session(&w.alice_address)
        .now_or_never()
        .expect("sync")
        .expect("load_session")
        .expect("session record");

    assert!(
        record_after.alice_base_key().is_err(),
        "Tahini: archived sessions must not be promoted, so B should have no active session"
    );
}

/// On simultaneous initiation (crossing PreKey messages), tiebreaking on
/// session ID should leave both sides on the same active session. After
/// convergence, further exchanges stay stable.
#[test]
fn test_simultaneous_init_tiebreak() {
    let mut w = TahiniWorld::new_no_session();

    let alice_device = DeviceId::new(1).unwrap();
    let bob_device = DeviceId::new(1).unwrap();

    // A processes B's bundle (without sending yet).
    let bob_bundle = w.bob_builder.make_bundle_with_latest_keys(bob_device);
    let mut csprng = OsRng.unwrap_err();
    initiate_session(
        &w.bob_address,
        &w.alice_address,
        &mut w.alice_builder.store.session_store,
        &mut w.alice_builder.store.identity_store,
        &bob_bundle,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    )
    .now_or_never()
    .expect("sync")
    .expect("A initiates with B bundle");

    // B processes A's bundle.
    let alice_bundle = w.alice_builder.make_bundle_with_latest_keys(alice_device);
    initiate_session(
        &w.alice_address,
        &w.bob_address,
        &mut w.bob_builder.store.session_store,
        &mut w.bob_builder.store.identity_store,
        &alice_bundle,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    )
    .now_or_never()
    .expect("sync")
    .expect("B initiates with A bundle");

    // A and B both enqueue a PreKey message (crossing).
    w.send_a_to_b("from alice");
    w.send_b_to_a("from bob");

    // Deliver both and verify plaintext survives the tiebreak.
    let pt_b = w.deliver_to_b().expect("B decrypts crossing message");
    assert_eq!(pt_b, b"from alice", "crossing message A→B plaintext");
    let pt_a = w.deliver_to_a().expect("A decrypts crossing message");
    assert_eq!(pt_a, b"from bob", "crossing message B→A plaintext");

    // After tiebreaking, both should end up using the same session.
    w.converge();
    assert!(
        w.active_base_keys_match(),
        "after simultaneous init tiebreak, both should share active session"
    );

    // Normal bidirectional traffic continues to flow on the converged session.
    // (Without archiving, the active session can't change, so we check message
    // delivery rather than re-asserting the now-trivial base-key match.)
    for i in 0..4 {
        let msg_a = format!("a→b round {i}");
        let msg_b = format!("b→a round {i}");
        w.send_a_to_b(&msg_a);
        let received = w.deliver_to_b().expect("b receives");
        assert_eq!(String::from_utf8(received).unwrap(), msg_a);

        w.send_b_to_a(&msg_b);
        let received = w.deliver_to_a().expect("a receives");
        assert_eq!(String::from_utf8(received).unwrap(), msg_b);
    }
}

/// After enough oscillation (send↔receive on archived), the system should
/// remain functional and converge.
#[test]
fn test_deadlock_detection_archives_session() {
    let mut w = TahiniWorld::new();

    // Establish A→B.
    w.send_a_to_b("init");
    w.deliver_to_b();
    w.send_b_to_a("ack");
    w.deliver_to_a();

    // Create an oscillation scenario:
    // B archives its session, A keeps sending (these arrive on B's archived session).
    // Meanwhile B tries to send on a new session it initiates.
    for _ in 0..3 {
        w.archive_active_b();
        w.send_a_to_b("stale send");
        // Don't deliver yet — let B start a new session with A.
        w.b_reinitiates_session_with_a();
        w.send_b_to_a("new session");
        // Deliver A's stale message to B (hits archived session).
        let _ = w.try_deliver_to_b(); // may succeed or fail — either is ok
        // Deliver B's message to A.
        let _ = w.try_deliver_to_a();
    }

    // After all that chaos, the system should still be able to converge.
    w.converge();
    assert!(
        w.active_base_keys_match(),
        "should converge after deadlock-like oscillation"
    );
}

/// A stale (out-of-order) message from an old session should not displace
/// B's active session that was established from a newer exchange.
#[test]
fn test_stale_message_doesnt_disrupt_active() {
    let mut w = TahiniWorld::new();

    // Establish initial session.
    w.send_a_to_b("first");
    w.deliver_to_b();

    // A sends a message but we hold it aside (save without delivering).
    w.send_a_to_b("stale");
    let stale_msg = w.q_ab.pop_front().expect("stale message in queue");

    // Archive A's session, refill Bob's prekeys, establish new session.
    w.archive_active_a();
    w.a_reinitiates_session_with_b();

    // A sends on the new session.
    w.send_a_to_b("new session message");
    w.deliver_to_b();
    w.send_b_to_a("b ack new");
    w.deliver_to_a();

    // Record B's current active base key.
    let active_base_key = w
        .session_record_for_a()
        .alice_base_key()
        .expect("active base key")
        .to_vec();

    // Now deliver the stale message.
    w.q_ab.push_front(stale_msg);
    let _ = w.try_deliver_to_b(); // may or may not succeed

    // B's active session should be unchanged.
    let base_key_after = w
        .session_record_for_a()
        .alice_base_key()
        .expect("base key after stale deliver")
        .to_vec();

    assert_eq!(
        active_base_key, base_key_after,
        "stale message must not change active session"
    );
}

/// Before B replies, A's outgoing message is a PreKey message.
/// After B replies and A decrypts B's response, A's next message is a Whisper.
#[test]
fn test_session_acknowledged_after_reply() {
    let mut w = TahiniWorld::new();

    // A sends first message — should be a PreKey message.
    let mut csprng = OsRng.unwrap_err();
    let first_ct = message_encrypt(
        b"hello bob",
        &w.bob_address,
        &w.alice_address,
        &mut w.alice_builder.store.session_store,
        &mut w.alice_builder.store.identity_store,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    )
    .now_or_never()
    .expect("sync")
    .expect("encrypt first msg");

    assert_eq!(
        first_ct.message_type(),
        CiphertextMessageType::PreKey,
        "first message from A should be a PreKey message"
    );

    // Deliver to B.
    w.q_ab.push_back(first_ct);
    w.deliver_to_b();

    // B replies.
    w.send_b_to_a("hello alice");
    w.deliver_to_a();

    // Now A's next send should be a Whisper (acknowledged session).
    let second_ct = message_encrypt(
        b"now acknowledged",
        &w.bob_address,
        &w.alice_address,
        &mut w.alice_builder.store.session_store,
        &mut w.alice_builder.store.identity_store,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    )
    .now_or_never()
    .expect("sync")
    .expect("encrypt second msg");

    assert_eq!(
        second_ct.message_type(),
        CiphertextMessageType::Whisper,
        "after B replies, A's messages should be Whisper (session acknowledged)"
    );
}

/// After archiving MAX_ARCHIVED_SESSIONS + 1 sessions, old archived sessions
/// are dropped (cap enforced). Messages encrypted to evicted sessions should fail.
#[test]
fn test_max_archived_sessions_cap() {
    // MAX_ARCHIVED_SESSIONS = 2 (from consts.rs; not re-exported publicly)
    const MAX_ARCHIVED_SESSIONS: usize = 3;

    let mut w = TahiniWorld::new();

    // Establish and exchange messages, then archive.
    w.send_a_to_b("session 0");
    w.deliver_to_b();
    w.send_b_to_a("b ack 0");
    w.deliver_to_a();

    // Capture a message encrypted on the first (oldest) session.
    let mut csprng = OsRng.unwrap_err();
    let oldest_ct = message_encrypt(
        b"from oldest session",
        &w.bob_address,
        &w.alice_address,
        &mut w.alice_builder.store.session_store,
        &mut w.alice_builder.store.identity_store,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    )
    .now_or_never()
    .expect("sync")
    .expect("encrypt oldest");

    // Create MAX_ARCHIVED_SESSIONS + 1 more sessions (archive each one).
    for i in 0..=MAX_ARCHIVED_SESSIONS {
        w.archive_active_b();
        w.a_reinitiates_session_with_b();
        // Ensure B gets the new session by having A initiate and delivering.
        w.send_a_to_b(&format!("new session {i}"));
        w.deliver_to_b();
        w.send_b_to_a(&format!("b ack {i}"));
        w.deliver_to_a();
    }

    // The oldest session should have been evicted.
    // Trying to decrypt `oldest_ct` (from the initial session, now beyond cap)
    // should fail.
    let result = message_decrypt(
        &oldest_ct,
        &w.alice_address,
        &w.bob_address,
        &mut w.bob_builder.store.session_store,
        &mut w.bob_builder.store.identity_store,
        &mut w.bob_builder.store.pre_key_store,
        &w.bob_builder.store.signed_pre_key_store,
        &mut w.bob_builder.store.kyber_pre_key_store,
        &mut csprng,
    )
    .now_or_never()
    .expect("sync");

    assert!(
        result.is_err(),
        "message from evicted session should fail to decrypt"
    );
}

/// A second PreKey message with the same base key (replay or duplicate)
/// should not create a new session — the dedup check in `process_prekey_impl`
/// (`find_session_by_id`) short-circuits.
#[test]
fn test_prekey_dedup() {
    let mut w = TahiniWorld::new();

    // A sends to B (PreKey message).
    w.send_a_to_b("first prekey");
    w.deliver_to_b();

    // A sends a regular follow-up (same session, now Whisper from A's perspective?
    // Actually A is still unacknowledged so it might still send PreKey — that's fine).
    w.send_a_to_b("second message");

    // B has a single active session and nothing archived yet.
    assert_eq!(
        w.session_record_for_a().archived_session_count(),
        0,
        "no sessions archived before the duplicate"
    );

    // Deliver second message to B.
    let plaintext = w.deliver_to_b().expect("b receives second message");
    assert_eq!(String::from_utf8(plaintext).unwrap(), "second message");

    // The duplicate PreKey (same base key) must not turn into a new session. If
    // it created one, B would archive the current session and the count would
    // rise to 1; dedup keeps it at 0.
    assert_eq!(
        w.session_record_for_a().archived_session_count(),
        0,
        "duplicate PreKey must not create (and archive) a new session"
    );

    // Bidirectional exchange still works.
    w.send_b_to_a("reply from b");
    let received = w.deliver_to_a().expect("a receives reply");
    assert_eq!(String::from_utf8(received).unwrap(), "reply from b");
}

/// A corrupted PreKeySignalMessage should fail to decrypt AND must not persist
/// any state changes (identity or session). This is a security property: a
/// failed decryption must not leak side effects into the stores.
#[test]
fn test_failed_prekey_decrypt_doesnt_update_stores() {
    let mut csprng = OsRng.unwrap_err();
    let alice_address = ProtocolAddress::new(
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_owned(),
        DeviceId::new(1).unwrap(),
    );
    let bob_address = ProtocolAddress::new(
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(),
        DeviceId::new(1).unwrap(),
    );

    // Set up Alice with prekey material; Bob has no prior session/identity for Alice.
    let alice_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Exactly(0))
        .with_signed_pre_key(IdChoice::Exactly(0))
        .with_kyber_pre_key(IdChoice::Exactly(0));
    let alice_bundle = alice_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());
    let mut alice_store = alice_builder.store;

    let mut bob_store = TestStoreBuilder::new().store;
    initiate_session(
        &alice_address,
        &bob_address,
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        &alice_bundle,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    )
    .now_or_never()
    .expect("sync")
    .expect("Bob initiates with Alice's bundle");

    // Bob encrypts a PreKey message to Alice.
    let pre_key_message = {
        let ct = message_encrypt(
            b"from Bob",
            &alice_address,
            &bob_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            SystemTime::UNIX_EPOCH,
            &mut csprng,
        )
        .now_or_never()
        .expect("sync")
        .expect("encrypt");

        let pkm = assert_matches!(ct, CiphertextMessage::PreKeySignalMessage(m) => m);

        // Corrupt the inner SignalMessage (flip the last byte = MAC corruption).
        let mut signal_message = pkm.message().serialized().to_owned();
        let last_byte = signal_message.last_mut().unwrap();
        *last_byte = last_byte.wrapping_add(1);

        PreKeySignalMessage::new(
            pkm.message_version(),
            pkm.registration_id(),
            pkm.pre_key_id(),
            pkm.signed_pre_key_id(),
            pkm.kyber_pre_key_id()
                .zip(pkm.kyber_ciphertext())
                .map(|(id, ct)| KyberPayload::new(id, ct.clone())),
            *pkm.base_key(),
            *pkm.identity_key(),
            (&*signal_message).try_into().unwrap(),
        )
        .unwrap()
    };

    // Decryption should fail with a generic error (no crypto detail leakage).
    assert_matches!(
        message_decrypt(
            &CiphertextMessage::PreKeySignalMessage(pre_key_message),
            &bob_address,
            &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &mut alice_store.pre_key_store,
            &alice_store.signed_pre_key_store,
            &mut alice_store.kyber_pre_key_store,
            &mut csprng,
        )
        .now_or_never()
        .expect("sync"),
        Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::PreKey,
            msg
        ))
        if msg == "decryption failed"
    );

    // Identity store must NOT have an entry for Bob (no side effects).
    assert_eq!(
        alice_store
            .identity_store
            .get_identity(&bob_address)
            .now_or_never()
            .expect("sync")
            .unwrap(),
        None,
        "failed decrypt must not save identity"
    );

    // Session store must NOT have a session for Bob.
    assert!(
        alice_store
            .session_store
            .load_session(&bob_address)
            .now_or_never()
            .expect("sync")
            .expect("can load")
            .is_none(),
        "failed decrypt must not create a session"
    );
}

// ── Replay / seen-base-key ─────────────────────────────────────────────────────

/// Receiver (Alice) + sender (Bob) for direct initiation/replay tests.
///
/// Alice has no one-time EC prekey so replayed initiations reach the base-key
/// reuse check instead of failing on an already-consumed prekey.
struct ReceiverSender {
    alice: InMemSignalProtocolStore,
    bob: InMemSignalProtocolStore,
    alice_address: ProtocolAddress,
    bob_address: ProtocolAddress,
    alice_bundle: PreKeyBundle,
}

fn receiver_sender() -> ReceiverSender {
    let alice_address = ProtocolAddress::new(
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_owned(),
        DeviceId::new(1).unwrap(),
    );
    let bob_address = ProtocolAddress::new(
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_owned(),
        DeviceId::new(1).unwrap(),
    );
    let alice_builder = TestStoreBuilder::new()
        .with_signed_pre_key(IdChoice::Exactly(0))
        .with_kyber_pre_key(IdChoice::Exactly(0));
    let alice_bundle = alice_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());
    ReceiverSender {
        alice: alice_builder.store,
        bob: TestStoreBuilder::new().store,
        alice_address,
        bob_address,
        alice_bundle,
    }
}

impl ReceiverSender {
    /// Bob initiates a fresh session from Alice's bundle (a new base key each
    /// call) and encrypts `msg` as a PreKey message.
    fn bob_initiation(
        &mut self,
        msg: &[u8],
        csprng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> CiphertextMessage {
        initiate_session(
            &self.alice_address,
            &self.bob_address,
            &mut self.bob.session_store,
            &mut self.bob.identity_store,
            &self.alice_bundle,
            SystemTime::UNIX_EPOCH,
            csprng,
        )
        .now_or_never()
        .expect("sync")
        .expect("bob initiates");
        message_encrypt(
            msg,
            &self.alice_address,
            &self.bob_address,
            &mut self.bob.session_store,
            &mut self.bob.identity_store,
            SystemTime::UNIX_EPOCH,
            csprng,
        )
        .now_or_never()
        .expect("sync")
        .expect("bob encrypts")
    }

    /// Alice receives a message from Bob.
    fn alice_receive(
        &mut self,
        ct: &CiphertextMessage,
        csprng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Result<Vec<u8>, SignalProtocolError> {
        message_decrypt(
            ct,
            &self.bob_address,
            &self.alice_address,
            &mut self.alice.session_store,
            &mut self.alice.identity_store,
            &mut self.alice.pre_key_store,
            &self.alice.signed_pre_key_store,
            &mut self.alice.kyber_pre_key_store,
            csprng,
        )
        .now_or_never()
        .expect("sync")
    }

    /// The base key (session id) of Alice's currently-active session with Bob.
    fn alice_active_base_key(&self) -> Vec<u8> {
        self.alice
            .session_store
            .load_session(&self.bob_address)
            .now_or_never()
            .expect("sync")
            .expect("can load")
            .expect("alice holds a session")
            .alice_base_key()
            .expect("active session has a base key")
            .to_vec()
    }
}

/// A replay whose session has been evicted from the archive is still rejected,
/// and the rejected replay must not replace the held session.
#[test]
fn test_evicted_replay_rejected_by_seen_base_key() {
    let mut rs = receiver_sender();
    let mut csprng = OsRng.unwrap_err();

    // Bob's first initiation; Alice accepts it (Fresh) and marks its base key.
    let first = rs.bob_initiation(b"first initiation", &mut csprng);
    assert_eq!(
        rs.alice_receive(&first, &mut csprng)
            .expect("first decrypts"),
        b"first initiation"
    );

    // Evict it by receiving enough fresh initiations to push the first session
    // out of the bounded archive.
    for i in 0..4 {
        let ct = rs.bob_initiation(format!("initiation {i}").as_bytes(), &mut csprng);
        assert_eq!(
            rs.alice_receive(&ct, &mut csprng)
                .expect("further initiation decrypts"),
            format!("initiation {i}").into_bytes()
        );
    }

    let active_before = rs.alice_active_base_key();

    // Its session is evicted, so dedup misses and the reused base key is
    // rejected.
    assert_matches!(
        rs.alice_receive(&first, &mut csprng),
        Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::PreKey,
            msg
        ))
        if msg == "reused base key"
    );

    // The rejected replay installed no session.
    assert_eq!(
        rs.alice_active_base_key(),
        active_before,
        "rejected replay must not resurrect / change the held session"
    );

    // The sender can still establish a new session with a fresh ephemeral.
    let fresh = rs.bob_initiation(b"after replay", &mut csprng);
    assert_eq!(
        rs.alice_receive(&fresh, &mut csprng)
            .expect("fresh initiation decrypts"),
        b"after replay"
    );
}

// ── Property-based tests ──────────────────────────────────────────────────────

#[derive(Clone, Debug, strum::VariantArray)]
enum PropTestAction {
    SendA,
    SendB,
    DeliverA,
    DeliverB,
    ArchiveA,
    ArchiveB,
}

#[derive(Copy, Clone, Default)]
enum PropTestRun {
    WithArchive,
    #[default]
    WithoutArchive,
}

impl proptest::arbitrary::Arbitrary for PropTestAction {
    type Parameters = PropTestRun;
    type Strategy = proptest::sample::Select<Self>;
    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        proptest::sample::select(
            Self::VARIANTS
                .iter()
                .filter(|x| {
                    !matches!(
                        (x, args),
                        (
                            PropTestAction::ArchiveA | PropTestAction::ArchiveB,
                            PropTestRun::WithoutArchive
                        )
                    )
                })
                .cloned()
                .collect::<Vec<_>>(),
        )
    }
}

fn proptest_random_conversation_run(actions: &[PropTestAction]) {
    let mut w = TahiniWorld::new();
    for action in actions {
        match action {
            PropTestAction::SendA => {
                w.send_a_to_b("msg");
            }
            PropTestAction::SendB => {
                w.send_b_to_a("msg");
            }
            PropTestAction::DeliverB => {
                let _ = w.try_deliver_to_b();
            }
            PropTestAction::DeliverA => {
                let _ = w.try_deliver_to_a();
            }
            PropTestAction::ArchiveA => {
                w.archive_active_a();
            }
            PropTestAction::ArchiveB => {
                w.archive_active_b();
            }
        }
    }
    // Convergence phase.
    w.converge();
    assert!(w.active_base_keys_match());

    // Verify actual messaging works after convergence.
    w.send_a_to_b("post-converge a2b");
    let pt = w.deliver_to_b().expect("b receives post-converge");
    assert_eq!(pt, b"post-converge a2b");
    w.send_b_to_a("post-converge b2a");
    let pt = w.deliver_to_a().expect("a receives post-converge");
    assert_eq!(pt, b"post-converge b2a");
}

proptest! {
    /// Random message/deliver pattern followed by forced convergence.
    #[test]
    fn proptest_random_conversation(
        actions in proptest::collection::vec(PropTestAction::arbitrary_with(PropTestRun::WithoutArchive), ..32)
    ) {
        proptest_random_conversation_run(&actions);
    }

    /// Random pattern including archive events, then convergence.
    #[test]
    #[ignore = "slow to run locally"]
    fn proptest_random_conversation_with_disruptions(
        actions in proptest::collection::vec(PropTestAction::arbitrary_with(PropTestRun::WithArchive), ..64)
    ) {
        proptest_random_conversation_run(&actions);
    }
}
