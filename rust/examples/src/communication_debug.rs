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
    println!("=== SIGNAL PROTOCOL COMMUNICATION EXAMPLE ===");
    println!("DEBUG: Starting main function");
    
    // Test just the key generation first
    println!("DEBUG: Testing basic key generation...");
    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    println!("DEBUG: Alice identity key generated");
    
    let bob_identity = IdentityKeyPair::generate(&mut csprng);
    println!("DEBUG: Bob identity key generated");
    
    // Test Kyber key generation (this might be the issue)
    println!("DEBUG: Testing Kyber key generation...");
    let bob_kyber_keypair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);
    println!("DEBUG: Kyber key generated successfully!");
    println!("DEBUG: Kyber public key size: {} bytes", bob_kyber_keypair.public_key.serialize().len());
    
    // Create addresses for Alice and Bob
    let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14151112222".to_owned(), 1.into());
    println!("DEBUG: Created addresses");
    
    // Test store creation
    println!("DEBUG: Creating stores...");
    let mut alice_store = InMemSignalProtocolStore::new(alice_identity, csprng.next_u32(), true)?;
    let mut bob_store = InMemSignalProtocolStore::new(bob_identity, csprng.next_u32(), false)?;
    println!("DEBUG: Stores created successfully");
    
    println!("DEBUG: Basic test completed successfully!");
    Ok(())
}
