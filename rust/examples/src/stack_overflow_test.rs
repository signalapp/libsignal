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
    println!("=== STACK OVERFLOW DEBUG TEST ===");
    
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
    
    // Generate Bob's Kyber pre-key (required for PQ ratchet)
    let bob_kyber_keypair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);
    let bob_kyber_prekey_id = KyberPreKeyId::from(1u32);
    let bob_kyber_prekey_signature = bob_identity
        .private_key()
        .calculate_signature(&bob_kyber_keypair.public_key.serialize(), &mut csprng)?;
    
    let bob_kyber_prekey = KyberPreKeyRecord::new(
        bob_kyber_prekey_id,
        Timestamp::from_epoch_millis(0),
        &bob_kyber_keypair,
        &bob_kyber_prekey_signature,
    );
    
    println!("STEP 3: Kyber pre-key generated");
    
    // Store Bob's pre-keys
    bob_store.save_signed_pre_key(bob_signed_prekey_id, &bob_signed_prekey).await?;
    bob_store.save_kyber_pre_key(bob_kyber_prekey_id, &bob_kyber_prekey).await?;
    
    println!("STEP 4: Pre-keys stored");
    
    // Optional: Generate one-time pre-key for Bob
    let bob_prekey_pair = KeyPair::generate(&mut csprng);
    let bob_prekey_id = PreKeyId::from(1u32);
    let bob_prekey = PreKeyRecord::new(bob_prekey_id, &bob_prekey_pair);
    bob_store.save_pre_key(bob_prekey_id, &bob_prekey).await?;
    
    println!("STEP 5: One-time pre-key stored");
    
    // Create pre-key bundle for Bob with Kyber key
    let bob_prekey_bundle = PreKeyBundle::new(
        bob_store.get_local_registration_id().await?,
        1.into(), // device_id
        Some((bob_prekey_id, bob_prekey.public_key()?)),
        bob_signed_prekey_id,
        bob_signed_prekey.public_key()?,
        bob_signed_prekey.signature().unwrap(),
        *bob_identity.identity_key(),
    )?
    .with_kyber_pre_key(
        bob_kyber_prekey_id,
        bob_kyber_prekey.public_key().unwrap(),
        bob_kyber_prekey.signature().unwrap(),
    );
    
    println!("STEP 6: Pre-key bundle created");
    
    // THIS IS WHERE THE STACK OVERFLOW LIKELY HAPPENS
    println!("STEP 7: About to call process_prekey_bundle - THIS MIGHT CAUSE STACK OVERFLOW");
    
    // Alice processes Bob's pre-key bundle to establish session
    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_prekey_bundle,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
        UsePQRatchet::No, // Use traditional ratchet to avoid PQ-related stack overflow
    ).await?;
    
    println!("STEP 8: Session established successfully! (process_prekey_bundle completed)");
    
    // If we get here, the issue is in message operations
    println!("STEP 9: About to encrypt message - checking if this causes stack overflow");
    
    // Alice encrypts a message to Bob
    let alice_message = "Hello Bob!";
    let alice_ciphertext = message_encrypt(
        alice_message.as_bytes(),
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::UNIX_EPOCH,
        &mut csprng,
    ).await?;
    
    println!("STEP 10: Message encrypted successfully!");
    
    // Test decryption
    println!("STEP 11: About to decrypt message - checking if this causes stack overflow");
    
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
                UsePQRatchet::No, // Use traditional ratchet to avoid PQ-related stack overflow
            ).await?
        },
        _ => return Err(SignalProtocolError::InvalidMessage(CiphertextMessageType::Plaintext, "Expected PreKeySignalMessage")),
    };
    
    println!("STEP 12: Message decrypted successfully!");
    
    let decrypted_message = String::from_utf8(bob_plaintext).expect("Valid UTF-8");
    println!("Decrypted: {}", decrypted_message);
    
    println!("SUCCESS: All operations completed without stack overflow!");
    
    Ok(())
}
