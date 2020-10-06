//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

mod support;

use libsignal_protocol_rust::*;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;
use std::convert::TryFrom;
use support::test_in_memory_protocol_store;

#[test]
fn group_no_send_session() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let mut alice_store = test_in_memory_protocol_store();

    assert!(group_encrypt(
        &mut alice_store,
        &group_sender,
        "space camp?".as_bytes(),
        &mut csprng,
        None,
    )
    .is_err());

    Ok(())
}

pub struct ContextUsingSenderKeyStore {
    store: InMemSenderKeyStore,
    expected_context: Context,
}

impl ContextUsingSenderKeyStore {
    pub fn new(expected_context: Context) -> Self {
        Self {
            store: InMemSenderKeyStore::new(),
            expected_context,
        }
    }
}

impl SenderKeyStore for ContextUsingSenderKeyStore {
    fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        assert_eq!(ctx, self.expected_context);
        self.store.store_sender_key(sender_key_name, record, ctx)
    }

    fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        assert_eq!(ctx, self.expected_context);
        self.store.load_sender_key(sender_key_name, ctx)
    }
}

#[test]
fn group_using_context_arg() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let x = Box::new(1);

    let context = Some(Box::into_raw(x) as _);

    let mut alice_store = ContextUsingSenderKeyStore::new(context);

    let _sent_distribution_message = create_sender_key_distribution_message(
        &group_sender,
        &mut alice_store,
        &mut csprng,
        context,
    )?;

    Ok(())
}

#[test]
fn group_no_recv_session() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let mut alice_store = test_in_memory_protocol_store();
    let mut bob_store = test_in_memory_protocol_store();

    let sent_distribution_message =
        create_sender_key_distribution_message(&group_sender, &mut alice_store, &mut csprng, None)?;

    let _recv_distribution_message =
        SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized()).unwrap();

    let alice_ciphertext = group_encrypt(
        &mut alice_store,
        &group_sender,
        "space camp?".as_bytes(),
        &mut csprng,
        None,
    )?;

    let bob_plaintext = group_decrypt(&alice_ciphertext, &mut bob_store, &group_sender, None);

    assert!(bob_plaintext.is_err());

    Ok(())
}

#[test]
fn group_basic_encrypt_decrypt() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let mut alice_store = test_in_memory_protocol_store();
    let mut bob_store = test_in_memory_protocol_store();

    let sent_distribution_message =
        create_sender_key_distribution_message(&group_sender, &mut alice_store, &mut csprng, None)?;

    let recv_distribution_message =
        SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized()).unwrap();

    let alice_ciphertext = group_encrypt(
        &mut alice_store,
        &group_sender,
        "space camp?".as_bytes(),
        &mut csprng,
        None,
    )?;

    process_sender_key_distribution_message(
        &group_sender,
        &recv_distribution_message,
        &mut bob_store,
        None,
    )?;

    let bob_plaintext = group_decrypt(&alice_ciphertext, &mut bob_store, &group_sender, None)?;

    assert_eq!(String::from_utf8(bob_plaintext).unwrap(), "space camp?");

    Ok(())
}

#[test]
fn group_large_messages() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let mut alice_store = test_in_memory_protocol_store();
    let mut bob_store = test_in_memory_protocol_store();

    let sent_distribution_message =
        create_sender_key_distribution_message(&group_sender, &mut alice_store, &mut csprng, None)?;

    let recv_distribution_message =
        SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized()).unwrap();

    let mut large_message: Vec<u8> = Vec::with_capacity(1024);
    for _ in 0..large_message.capacity() {
        large_message.push(csprng.gen());
    }

    let alice_ciphertext = group_encrypt(
        &mut alice_store,
        &group_sender,
        &large_message,
        &mut csprng,
        None,
    )?;

    process_sender_key_distribution_message(
        &group_sender,
        &recv_distribution_message,
        &mut bob_store,
        None,
    )?;

    let bob_plaintext = group_decrypt(&alice_ciphertext, &mut bob_store, &group_sender, None)?;

    assert_eq!(bob_plaintext, large_message);

    Ok(())
}

#[test]
fn group_basic_ratchet() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let mut alice_store = test_in_memory_protocol_store();
    let mut bob_store = test_in_memory_protocol_store();

    let sent_distribution_message =
        create_sender_key_distribution_message(&group_sender, &mut alice_store, &mut csprng, None)?;

    let recv_distribution_message =
        SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized()).unwrap();

    process_sender_key_distribution_message(
        &group_sender,
        &recv_distribution_message,
        &mut bob_store,
        None,
    )?;

    let alice_ciphertext1 = group_encrypt(
        &mut alice_store,
        &group_sender,
        "swim camp".as_bytes(),
        &mut csprng,
        None,
    )?;
    let alice_ciphertext2 = group_encrypt(
        &mut alice_store,
        &group_sender,
        "robot camp".as_bytes(),
        &mut csprng,
        None,
    )?;
    let alice_ciphertext3 = group_encrypt(
        &mut alice_store,
        &group_sender,
        "ninja camp".as_bytes(),
        &mut csprng,
        None,
    )?;

    let bob_plaintext1 = group_decrypt(&alice_ciphertext1, &mut bob_store, &group_sender, None)?;
    assert_eq!(String::from_utf8(bob_plaintext1).unwrap(), "swim camp");

    assert_eq!(
        group_decrypt(&alice_ciphertext1, &mut bob_store, &group_sender, None),
        Err(SignalProtocolError::DuplicatedMessage(1, 0))
    );

    let bob_plaintext3 = group_decrypt(&alice_ciphertext3, &mut bob_store, &group_sender, None)?;
    assert_eq!(String::from_utf8(bob_plaintext3).unwrap(), "ninja camp");

    let bob_plaintext2 = group_decrypt(&alice_ciphertext2, &mut bob_store, &group_sender, None)?;
    assert_eq!(String::from_utf8(bob_plaintext2).unwrap(), "robot camp");

    Ok(())
}

#[test]
fn group_late_join() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let mut alice_store = test_in_memory_protocol_store();
    let mut bob_store = test_in_memory_protocol_store();

    let sent_distribution_message =
        create_sender_key_distribution_message(&group_sender, &mut alice_store, &mut csprng, None)?;

    let recv_distribution_message =
        SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized()).unwrap();

    for i in 0..100 {
        group_encrypt(
            &mut alice_store,
            &group_sender,
            format!("nefarious plotting {}/100", i).as_bytes(),
            &mut csprng,
            None,
        )?;
    }

    // now bob joins:
    process_sender_key_distribution_message(
        &group_sender,
        &recv_distribution_message,
        &mut bob_store,
        None,
    )?;

    let alice_ciphertext = group_encrypt(
        &mut alice_store,
        &group_sender,
        "welcome bob".as_bytes(),
        &mut csprng,
        None,
    )?;

    let bob_plaintext = group_decrypt(&alice_ciphertext, &mut bob_store, &group_sender, None)?;
    assert_eq!(String::from_utf8(bob_plaintext).unwrap(), "welcome bob");

    Ok(())
}

#[test]
fn group_out_of_order() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let mut alice_store = test_in_memory_protocol_store();
    let mut bob_store = test_in_memory_protocol_store();

    let sent_distribution_message =
        create_sender_key_distribution_message(&group_sender, &mut alice_store, &mut csprng, None)?;

    let recv_distribution_message =
        SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized()).unwrap();

    process_sender_key_distribution_message(
        &group_sender,
        &recv_distribution_message,
        &mut bob_store,
        None,
    )?;

    let mut ciphertexts = Vec::with_capacity(100);

    for i in 0..ciphertexts.capacity() {
        ciphertexts.push(group_encrypt(
            &mut alice_store,
            &group_sender,
            format!("nefarious plotting {:02}/100", i).as_bytes(),
            &mut csprng,
            None,
        )?);
    }

    ciphertexts.shuffle(&mut csprng);

    let mut plaintexts = Vec::with_capacity(ciphertexts.len());

    for ciphertext in ciphertexts {
        plaintexts.push(group_decrypt(
            &ciphertext,
            &mut bob_store,
            &group_sender,
            None,
        )?);
    }

    plaintexts.sort();

    for (i, plaintext) in plaintexts.iter().enumerate() {
        assert_eq!(
            String::from_utf8(plaintext.to_vec()).unwrap(),
            format!("nefarious plotting {:02}/100", i)
        );
    }

    Ok(())
}

#[test]
fn group_too_far_in_the_future() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let mut alice_store = test_in_memory_protocol_store();
    let mut bob_store = test_in_memory_protocol_store();

    let sent_distribution_message =
        create_sender_key_distribution_message(&group_sender, &mut alice_store, &mut csprng, None)?;

    let recv_distribution_message =
        SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized()).unwrap();

    process_sender_key_distribution_message(
        &group_sender,
        &recv_distribution_message,
        &mut bob_store,
        None,
    )?;

    for i in 0..2001 {
        group_encrypt(
            &mut alice_store,
            &group_sender,
            format!("nefarious plotting {}", i).as_bytes(),
            &mut csprng,
            None,
        )?;
    }

    let alice_ciphertext = group_encrypt(
        &mut alice_store,
        &group_sender,
        "you got the plan?".as_bytes(),
        &mut csprng,
        None,
    )?;

    assert!(group_decrypt(&alice_ciphertext, &mut bob_store, &group_sender, None).is_err());

    Ok(())
}

#[test]
fn group_message_key_limit() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let mut alice_store = test_in_memory_protocol_store();
    let mut bob_store = test_in_memory_protocol_store();

    let sent_distribution_message =
        create_sender_key_distribution_message(&group_sender, &mut alice_store, &mut csprng, None)?;

    let recv_distribution_message =
        SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized()).unwrap();

    process_sender_key_distribution_message(
        &group_sender,
        &recv_distribution_message,
        &mut bob_store,
        None,
    )?;

    let mut ciphertexts = Vec::with_capacity(2010);

    for _ in 0..ciphertexts.capacity() {
        ciphertexts.push(group_encrypt(
            &mut alice_store,
            &group_sender,
            "too many messages".as_bytes(),
            &mut csprng,
            None,
        )?);
    }

    assert_eq!(
        String::from_utf8(group_decrypt(
            &ciphertexts[1000],
            &mut bob_store,
            &group_sender,
            None,
        )?)
        .unwrap(),
        "too many messages"
    );
    assert_eq!(
        String::from_utf8(group_decrypt(
            &ciphertexts[ciphertexts.len() - 1],
            &mut bob_store,
            &group_sender,
            None,
        )?)
        .unwrap(),
        "too many messages"
    );
    assert!(group_decrypt(&ciphertexts[0], &mut bob_store, &group_sender, None).is_err());

    Ok(())
}
