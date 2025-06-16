use libsignal_protocol::*;
use rand::{rng, RngCore};
use std::time::SystemTime;

fn main() -> Result<(), SignalProtocolError> {
    use std::thread;
    
    // Create a thread with larger stack to run the async main
    let handle = thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32MB stack
        .spawn(|| {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async_main())
        })
        .unwrap();
    
    handle.join().unwrap()
}

async fn async_main() -> Result<(), SignalProtocolError> {
    // Initialize random number generator
    let mut csprng = rng();
    println!("=== TRADITIONAL RATCHET TEST (NO POST-QUANTUM) ===");
    
    // Create addresses for Alice and Bob
    let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14151112222".to_owned(), 1.into());
    
    // Generate identity key pairs for both parties
    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    let bob_identity = IdentityKeyPair::generate(&mut csprng);
    
    // Create in-memory stores for both parties
    let mut alice_store = InMemSignalProtocolStore::new(alice_identity, csprng.next_u32(), true)?;
    let mut bob_store = InMemSignalProtocolStore::new(bob_identity, csprng.next_u32(), false)?;
    
    println!("STEP 1: Basic setup completed");
    
    // Generate Bob's signed pre-key
    let bob_signed_prekey_pair = KeyPair::generate(&mut csprng);
    let bob_signed_prekey_id = SignedPreKeyId::from(1u32);
    let bob_signed_prekey_signature = bob_identity
        .private_key()
        .calculate_signature(&bob_signed_prekey_pair.public_key.serialize(), &mut csprng)?;
    
    let bob_signed_prekey = SignedPreKeyRecord::new(
        bob_signed_prekey_id,
        Timestamp::from_epoch_millis(0),
        &bob_signed_prekey_pair,
        &bob_signed_prekey_signature,
    );
    
    println!("STEP 2: Signed pre-key generated");
    
    // Store Bob's pre-keys (NO KYBER)
    bob_store.save_signed_pre_key(bob_signed_prekey_id, &bob_signed_prekey).await?;
    
    println!("STEP 3: Signed pre-key stored");
    
    // Optional: Generate one-time pre-key for Bob
    let bob_prekey_pair = KeyPair::generate(&mut csprng);
    let bob_prekey_id = PreKeyId::from(1u32);
    let bob_prekey = PreKeyRecord::new(bob_prekey_id, &bob_prekey_pair);
    bob_store.save_pre_key(bob_prekey_id, &bob_prekey).await?;
    
    println!("STEP 4: One-time pre-key stored");
    
    // Create pre-key bundle for Bob WITHOUT Kyber key (traditional ratchet only)
    let bob_prekey_bundle = PreKeyBundle::new(
        bob_store.get_local_registration_id().await?,
        1.into(), // device_id
        Some((bob_prekey_id, bob_prekey.public_key()?)),
        bob_signed_prekey_id,
        bob_signed_prekey.public_key()?,
        bob_signed_prekey.signature().unwrap(),
        *bob_identity.identity_key(),
    )?;
    // Note: NO .with_kyber_pre_key() call
    
    println!("STEP 5: Traditional pre-key bundle created (no Kyber)");
    
    // Alice processes Bob's pre-key bundle to establish session (traditional ratchet)
    println!("STEP 6: About to call process_prekey_bundle with traditional ratchet");
    
    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_prekey_bundle,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
        UsePQRatchet::No, // Traditional ratchet
    ).await?;
    
    println!("STEP 7: Session established successfully with traditional ratchet");
    
    // Test message encryption with traditional ratchet
    println!("STEP 8: About to encrypt message with traditional ratchet");
    
    let alice_message = "Hello Bob! (Traditional ratchet)";
    let alice_ciphertext = message_encrypt(
        alice_message.as_bytes(),
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    ).await?;
    
    println!("STEP 9: Message encrypted successfully with traditional ratchet!");
    
    // Test decryption
    println!("STEP 10: About to decrypt message");
    
    let bob_plaintext = match &alice_ciphertext {
        CiphertextMessage::PreKeySignalMessage(prekey_msg) => {
            message_decrypt_prekey(
                prekey_msg,
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &mut bob_store.pre_key_store,
                &mut bob_store.signed_pre_key_store,
                &mut bob_store.kyber_pre_key_store,
                &mut csprng,
                UsePQRatchet::No, // Traditional ratchet
            ).await?
        },
        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected PreKeySignalMessage")),
    };
    
    println!("STEP 11: Message decrypted successfully!");
    
    let decrypted_message = String::from_utf8(bob_plaintext).expect("Valid UTF-8");
    println!("Decrypted: {}", decrypted_message);
    
    // Test second message (should be SignalMessage now)
    println!("STEP 12: Testing second message exchange");
    
    let bob_reply = "Hello Alice! (Traditional ratchet reply)";
    let bob_ciphertext = message_encrypt(
        bob_reply.as_bytes(),
        &alice_address,
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    ).await?;
    
    println!("STEP 13: Bob's reply encrypted successfully!");
    
    // Alice decrypts Bob's reply
    let alice_received = match &bob_ciphertext {
        CiphertextMessage::SignalMessage(signal_msg) => {
            message_decrypt_signal(
                signal_msg,
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &mut csprng,
            ).await?
        },
        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected SignalMessage")),
    };
    
    println!("STEP 14: Alice decrypted Bob's reply successfully!");
    
    let alice_decrypted_reply = String::from_utf8(alice_received).expect("Valid UTF-8");
    println!("Alice received: {}", alice_decrypted_reply);
    
    println!("SUCCESS: Traditional ratchet communication completed without stack overflow!");
    
    Ok(())
}
