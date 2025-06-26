use libsignal_protocol::*;
use libsignal_protocol::process_swoosh_prekey_bundle;
use pswoosh::keys::SwooshKeyPair;
use rand::{rng, RngCore};
use std::time::SystemTime;

fn main() -> Result<(), SignalProtocolError> {
    use std::thread;
    
    // Create a thread with larger stack to run the async main
    let handle = thread::Builder::new()
        .stack_size(100 * 1024 * 1024) // 32MB stack
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
    println!("=== SIGNAL PROTOCOL COMMUNICATION EXAMPLE (WITH SWOOSH POST-QUANTUM) ===");
    // Create addresses for Alice and Bob
    let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14151112222".to_owned(), 1.into());
    
    // Generate identity key pairs for both parties
    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    let bob_identity = IdentityKeyPair::generate(&mut csprng);
    
    println!("=== IDENTITY KEYS ===");
    println!("Alice Identity Public Key: {:?}", hex::encode(alice_identity.identity_key().serialize()));
    println!("Bob Identity Public Key: {:?}", hex::encode(bob_identity.identity_key().serialize()));
    
    // Create in-memory stores for both parties
    let mut alice_store = InMemSignalProtocolStore::new(alice_identity, csprng.next_u32(), true)?;
    let mut bob_store = InMemSignalProtocolStore::new(bob_identity, csprng.next_u32(), false)?;
    
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
    
    println!("\n=== BOB'S SIGNED PRE-KEY ===");
    println!("Signed Pre-Key ID: {:?}", bob_signed_prekey_id);
    println!("Signed Pre-Key Public: {:?}", hex::encode(bob_signed_prekey_pair.public_key.serialize()));
    println!("Signed Pre-Key Signature: {:?}", hex::encode(&bob_signed_prekey_signature));

    // Generate Bob's Swoosh pre-key (required for PQ ratchet)
    let bob_swoosh_key_pair = SwooshKeyPair::generate(false);
    let bob_swoosh_prekey_id = SwooshPreKeyId::from(1u32);
    let bob_swoosh_prekey_signature = bob_identity
        .private_key()
        .calculate_signature(&bob_swoosh_key_pair.public_key.serialize(), &mut csprng)?;

    let bob_swoosh_prekey = SwooshPreKeyRecord::new(
        bob_swoosh_prekey_id,
        Timestamp::from_epoch_millis(0),
        &bob_swoosh_key_pair,
        &bob_swoosh_prekey_signature,
    );

    println!("\n=== BOB'S SWOOSH PRE-KEY (Post-Quantum) ===");
    println!("Swoosh Pre-Key ID: {:?}", bob_swoosh_prekey_id);
    println!("Swoosh Public Key Length: {} bytes", bob_swoosh_key_pair.public_key.serialize().len());
    println!("First 8 bytes of Swoosh Pre-Key: {:?}", hex::encode(&bob_swoosh_key_pair.public_key.serialize()[..8]));
    println!("Swoosh Pre-Key Signature: {:?}", hex::encode(&bob_swoosh_prekey_signature));

    // Store Bob's pre-keys
    bob_store.save_signed_pre_key(bob_signed_prekey_id, &bob_signed_prekey).await?;
    bob_store.save_swoosh_pre_key(bob_swoosh_prekey_id, &bob_swoosh_prekey).await?;
    
    // Optional: Generate one-time pre-key for Bob
    let bob_prekey_pair = KeyPair::generate(&mut csprng);
    let bob_prekey_id = PreKeyId::from(1u32);
    let bob_prekey = PreKeyRecord::new(bob_prekey_id, &bob_prekey_pair);
    
    println!("\n=== BOB'S ONE-TIME PRE-KEY ===");
    println!("One-Time Pre-Key ID: {:?}", bob_prekey_id);
    println!("One-Time Pre-Key Public: {:?}", hex::encode(bob_prekey_pair.public_key.serialize()));
    
    bob_store.save_pre_key(bob_prekey_id, &bob_prekey).await?;


    
    // Create pre-key bundle for Bob with swoosh pre-key
    let bob_prekey_bundle = PreKeyBundle::new(
        bob_store.get_local_registration_id().await?,
        1.into(), // device_id
        Some((bob_prekey_id, bob_prekey.public_key()?)),
        bob_signed_prekey_id,
        bob_signed_prekey.public_key()?,
        bob_signed_prekey.signature().unwrap(),
        *bob_identity.identity_key(),
    )?
    .with_swoosh_pre_key(
        bob_swoosh_prekey_id,
        bob_swoosh_prekey.public_key()?,
        bob_swoosh_prekey.signature().unwrap()
    );

    println!("\n=== PRE-KEY BUNDLE CREATED (WITH SWOOSH) ===");
    println!("Registration ID: {:?}", bob_store.get_local_registration_id().await?);
    
    // Alice processes Bob's pre-key bundle to establish session WITH Swoosh 
    // ====== CRITICAL POINT 1: Alice's Swoosh keys are established HERE ======
    process_swoosh_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_prekey_bundle,
        SystemTime::now(),
        &mut csprng,
        UsePQRatchet::No,
    ).await?;
    
    println!("\n=== SESSION ESTABLISHED (WITH SWOOSH POST-QUANTUM) ===");
    println!("✓ ALICE'S SWOOSH KEYS ARE NOW ESTABLISHED");
    println!("  At this point, Alice has generated her Swoosh ratchet keys");
    println!("  and can derive shared secrets with Bob's Swoosh pre-key");
    
    // Verification: Alice should have an active session now
    let alice_session = alice_store.session_store.load_session(&bob_address).await?.unwrap();
    println!("✓ Alice has active session: {}", alice_session.has_usable_sender_chain(SystemTime::now()).unwrap_or(false));
    
    // Alice encrypts a message to Bob
    let alice_message = "Hello Bob! This is Alice.";
    let alice_ciphertext = message_encrypt_swoosh(
        alice_message.as_bytes(),
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::now(),
        &mut csprng,
    ).await?;
    
    println!("\n=== ALICE'S MESSAGE ===");
    println!("Alice sent: {}", alice_message);
    println!("Ciphertext type: {:?}", alice_ciphertext.message_type());
    println!("Ciphertext length: {} bytes", alice_ciphertext.serialize().len());
    
    // ====== CRITICAL POINT 2: Bob's Swoosh keys are established during message decryption ======
    let bob_plaintext = match &alice_ciphertext {
        CiphertextMessage::PreKeySignalMessage(prekey_msg) => {
            println!("\n=== DECRYPTING PRE-KEY MESSAGE ===");
            println!("=== CRITICAL POINT 2: Bob will establish Swoosh keys NOW during decryption ===");
            
            let decrypted = message_decrypt_prekey(
                prekey_msg,
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &mut bob_store.pre_key_store,
                &mut bob_store.signed_pre_key_store,
                &mut bob_store.kyber_pre_key_store,
                &mut bob_store.swoosh_pre_key_store,
                &mut csprng,
                UsePQRatchet::No,
            ).await?;
            
            println!("✓ BOB'S SWOOSH KEYS ARE NOW ESTABLISHED");
            println!("  Bob has processed Alice's pre-key message and established");
            println!("  his Swoosh ratchet keys and derived the shared secret");
            
            // Verification: Bob should now have an active session
            let bob_session = bob_store.session_store.load_session(&alice_address).await?.unwrap();
            println!("✓ Bob has active session: {}", bob_session.has_usable_sender_chain(SystemTime::now()).unwrap_or(false));
            
            decrypted
        },
        CiphertextMessage::SignalMessage(signal_msg) => {
            println!("\n=== DECRYPTING SIGNAL MESSAGE ===");
            message_decrypt_signal(
                signal_msg,
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &mut csprng,
            ).await?
        },
        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Unexpected message type")),
    };
    
    let decrypted_message = String::from_utf8(bob_plaintext).expect("Valid UTF-8");
    println!("Bob received: {}", decrypted_message);
    
    // ====== VERIFICATION: Both parties now have established Swoosh keys ======
    println!("\n=== SWOOSH KEY ESTABLISHMENT VERIFICATION ===");
    
    // Both parties should have active sessions at this point
    let alice_final_session = alice_store.session_store.load_session(&bob_address).await?.unwrap();
    let bob_final_session = bob_store.session_store.load_session(&alice_address).await?.unwrap();
    
    println!("✓ Alice session is usable: {}", alice_final_session.has_usable_sender_chain(SystemTime::now()).unwrap_or(false));
    println!("✓ Bob session is usable: {}", bob_final_session.has_usable_sender_chain(SystemTime::now()).unwrap_or(false));
    
    // Now Bob can reply to Alice (session is established)
    let bob_reply = "Hello Alice! Nice to hear from you.";
    let bob_ciphertext = message_encrypt_swoosh(
        bob_reply.as_bytes(),
        &alice_address,
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        SystemTime::now(),
        &mut csprng,
    ).await?;
    
    println!("\n=== BOB'S REPLY ===");
    println!("Bob sent: {}", bob_reply);
    println!("Reply ciphertext type: {:?}", bob_ciphertext.message_type());
    println!("Reply ciphertext length: {} bytes", bob_ciphertext.serialize().len());
    //println!("Encrypted reply: {:?}", hex::encode(bob_ciphertext.serialize()));
    
    // Alice decrypts Bob's reply (should be SignalMessage after first exchange)
    let alice_received = match &bob_ciphertext {
        CiphertextMessage::SignalMessage(signal_msg) => {
            println!("\n=== ALICE DECRYPTING BOB'S REPLY ===");
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
    
    let alice_decrypted_reply = String::from_utf8(alice_received).expect("Valid UTF-8");
    println!("Alice received: {}", alice_decrypted_reply);
    
    // Continue the conversation - Alice sends another message (Turn 3)
    let alice_second_message = "Thanks Bob! How's the Swoosh post-quantum cryptography working for you?";
    let alice_second_ciphertext = message_encrypt_swoosh(
        alice_second_message.as_bytes(),
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::now(),
        &mut csprng,
    ).await?;
    
    println!("\n=== ALICE'S SECOND MESSAGE (Turn 3) ===");
    println!("Alice sent: {}", alice_second_message);
    println!("Ciphertext type: {:?}", alice_second_ciphertext.message_type());
    println!("Ciphertext length: {} bytes", alice_second_ciphertext.serialize().len());
    //println!("Encrypted message: {:?}", hex::encode(alice_second_ciphertext.serialize()));
    
    // Bob decrypts Alice's second message
    let bob_second_plaintext = match &alice_second_ciphertext {
        CiphertextMessage::SignalMessage(signal_msg) => {
            println!("\n=== BOB DECRYPTING ALICE'S SECOND MESSAGE ===");
            message_decrypt_signal(
                signal_msg,
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &mut csprng,
            ).await?
        },
        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected SignalMessage")),
    };
    
    let bob_decrypted_second = String::from_utf8(bob_second_plaintext).expect("Valid UTF-8");
    println!("Bob received: {}", bob_decrypted_second);
    
    // Bob sends another reply (Turn 4)
    let bob_second_reply = "It's reliable! SWOOSH provides excellent post-quantum forward secrecy.";
    let bob_second_ciphertext = message_encrypt_swoosh(
        bob_second_reply.as_bytes(),
        &alice_address,
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        SystemTime::now(),
        &mut csprng,
    ).await?;
    
    println!("\n=== BOB'S SECOND REPLY (Turn 4) ===");
    println!("Bob sent: {}", bob_second_reply);
    println!("Reply ciphertext type: {:?}", bob_second_ciphertext.message_type());
    println!("Reply ciphertext length: {} bytes", bob_second_ciphertext.serialize().len());
    //println!("Encrypted reply: {:?}", hex::encode(bob_second_ciphertext.serialize()));
    
    // Alice decrypts Bob's second reply
    let alice_second_received = match &bob_second_ciphertext {
        CiphertextMessage::SignalMessage(signal_msg) => {
            println!("\n=== ALICE DECRYPTING BOB'S SECOND REPLY ===");
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
    
    let alice_decrypted_second_reply = String::from_utf8(alice_second_received).expect("Valid UTF-8");
    println!("Alice received reply: {}", alice_decrypted_second_reply);
    
    println!("\n=== COMMUNICATION COMPLETE ===");
    println!("Communication established successfully!");
    println!("Total double ratchet turns: 4");
    println!("Messages exchanged: 4 (2 from Alice, 2 from Bob)");
    println!("Using Swoosh post-quantum cryptography");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pswoosh::keys::SwooshKeyPair;
    use rand::RngCore;

    #[tokio::test]
    async fn test_swoosh_shared_secret_derivation() -> Result<(), SignalProtocolError> {
        println!("\n=== TESTING SWOOSH SHARED SECRET DERIVATION ===");
        
        // Test 1: Basic SwooshKeyPair shared secret derivation
        let alice_keypair = SwooshKeyPair::generate(true);   // Alice is true
        let bob_keypair = SwooshKeyPair::generate(false);    // Bob is false
        
        let alice_secret = alice_keypair.derive_shared_secret(&bob_keypair.public_key, true)
            .expect("Alice should derive shared secret");
        let bob_secret = bob_keypair.derive_shared_secret(&alice_keypair.public_key, false)
            .expect("Bob should derive shared secret");
        
        println!("✓ Alice derived secret: {} bytes, first 8: {:02x?}", 
                alice_secret.len(), &alice_secret[..8]);
        println!("✓ Bob derived secret: {} bytes, first 8: {:02x?}", 
                bob_secret.len(), &bob_secret[..8]);
        
        assert_eq!(alice_secret, bob_secret, "Alice and Bob should derive identical shared secrets");
        println!("🎉 SUCCESS: Alice and Bob derived identical shared secrets!");
        
        // Test 2: Verify different role assignments produce different results
        let alice_secret_wrong_role = alice_keypair.derive_shared_secret(&bob_keypair.public_key, false)
            .expect("Alice should derive shared secret with wrong role");
        
        assert_ne!(alice_secret, alice_secret_wrong_role, 
                  "Different roles should produce different shared secrets");
        println!("✓ Different roles produce different secrets (as expected)");
        
        // Test 3: Verify reproducibility
        let alice_secret2 = alice_keypair.derive_shared_secret(&bob_keypair.public_key, true)
            .expect("Alice should derive shared secret again");
        
        assert_eq!(alice_secret, alice_secret2, "Shared secret derivation should be reproducible");
        println!("✓ Shared secret derivation is reproducible");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_swoosh_key_establishment_points() -> Result<(), SignalProtocolError> {
        println!("\n=== TESTING SWOOSH KEY ESTABLISHMENT POINTS ===");
        
        let mut csprng = rand::rng();
        
        // Create addresses
        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151112222".to_owned(), 1.into());
        
        // Generate identity key pairs
        let alice_identity = IdentityKeyPair::generate(&mut csprng);
        let bob_identity = IdentityKeyPair::generate(&mut csprng);
        
        // Create stores
        let mut alice_store = InMemSignalProtocolStore::new(alice_identity, csprng.next_u32(), true)?;
        let mut bob_store = InMemSignalProtocolStore::new(bob_identity, csprng.next_u32(), false)?;
        
        // Generate Bob's keys
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
        
        let bob_swoosh_key_pair = SwooshKeyPair::generate(false);
        let bob_swoosh_prekey_id = SwooshPreKeyId::from(1u32);
        let bob_swoosh_prekey_signature = bob_identity
            .private_key()
            .calculate_signature(&bob_swoosh_key_pair.public_key.serialize(), &mut csprng)?;

        let bob_swoosh_prekey = SwooshPreKeyRecord::new(
            bob_swoosh_prekey_id,
            Timestamp::from_epoch_millis(0),
            &bob_swoosh_key_pair,
            &bob_swoosh_prekey_signature,
        );
        
        // Store Bob's keys
        bob_store.save_signed_pre_key(bob_signed_prekey_id, &bob_signed_prekey).await?;
        bob_store.save_swoosh_pre_key(bob_swoosh_prekey_id, &bob_swoosh_prekey).await?;
        
        // Create pre-key bundle
        let bob_prekey_bundle = PreKeyBundle::new(
            bob_store.get_local_registration_id().await?,
            1.into(),
            None,
            bob_signed_prekey_id,
            bob_signed_prekey.public_key()?,
            bob_signed_prekey.signature().unwrap(),
            *bob_identity.identity_key(),
        )?
        .with_swoosh_pre_key(
            bob_swoosh_prekey_id,
            bob_swoosh_prekey.public_key()?,
            bob_swoosh_prekey.signature().unwrap()
        );
        
        // BEFORE: Alice should not have a session
        assert!(alice_store.session_store.load_session(&bob_address).await?.is_none(), 
               "Alice should not have a session before key establishment");
        
        // ESTABLISHMENT POINT 1: Alice processes pre-key bundle
        process_swoosh_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_prekey_bundle,
            SystemTime::now(),
            &mut csprng,
            UsePQRatchet::No,
        ).await?;
        
        // AFTER: Alice should have a session
        let alice_session = alice_store.session_store.load_session(&bob_address).await?
            .expect("Alice should have a session after processing pre-key bundle");
        assert!(alice_session.has_usable_sender_chain(SystemTime::now())?,
               "Alice session should be usable");
        println!("✓ POINT 1: Alice established Swoosh keys after processing pre-key bundle");
        
        // BEFORE: Bob should not have a session
        assert!(bob_store.session_store.load_session(&alice_address).await?.is_none(),
               "Bob should not have a session before message decryption");
        
        // Alice sends message
        let alice_message = "Test message";
        let alice_ciphertext = message_encrypt_swoosh(
            alice_message.as_bytes(),
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
            &mut csprng,
        ).await?;
        
        // ESTABLISHMENT POINT 2: Bob decrypts message
        match &alice_ciphertext {
            CiphertextMessage::PreKeySignalMessage(prekey_msg) => {
                let _decrypted = message_decrypt_prekey(
                    prekey_msg,
                    &alice_address,
                    &mut bob_store.session_store,
                    &mut bob_store.identity_store,
                    &mut bob_store.pre_key_store,
                    &mut bob_store.signed_pre_key_store,
                    &mut bob_store.kyber_pre_key_store,
                    &mut bob_store.swoosh_pre_key_store,
                    &mut csprng,
                    UsePQRatchet::No,
                ).await?;
                
                // AFTER: Bob should have a session
                let bob_session = bob_store.session_store.load_session(&alice_address).await?
                    .expect("Bob should have a session after decrypting message");
                assert!(bob_session.has_usable_sender_chain(SystemTime::now())?,
                       "Bob session should be usable");
                println!("✓ POINT 2: Bob established Swoosh keys after decrypting first message");
            },
            _ => panic!("Expected PreKeySignalMessage"),
        }
        
        println!("🎉 SUCCESS: Both key establishment points verified!");
        
        Ok(())
    }
}
