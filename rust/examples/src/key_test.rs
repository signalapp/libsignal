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
    println!("=== TESTING KEY SERIALIZATION ===");
    
    // Test basic key generation and serialization
    println!("1. Testing basic key generation...");
    let test_keypair = KeyPair::generate(&mut csprng);
    let serialized_private = test_keypair.private_key.serialize();
    let serialized_public = test_keypair.public_key.serialize();
    
    println!("   Private key length: {} bytes", serialized_private.len());
    println!("   Public key length: {} bytes", serialized_public.len());
    
    // Test deserialization
    println!("2. Testing key deserialization...");
    match PrivateKey::deserialize(&serialized_private) {
        Ok(_) => println!("   ✓ Private key deserialization works"),
        Err(e) => {
            println!("   ✗ Private key deserialization failed: {:?}", e);
            return Err(SignalProtocolError::InvalidArgument("Key deserialization failed".to_string()));
        }
    }
    
    match PublicKey::deserialize(&serialized_public) {
        Ok(_) => println!("   ✓ Public key deserialization works"),
        Err(e) => {
            println!("   ✗ Public key deserialization failed: {:?}", e);
            return Err(SignalProtocolError::InvalidArgument("Key deserialization failed".to_string()));
        }
    }
    
    println!("SUCCESS: Basic key serialization/deserialization works correctly!");
    println!("The issue is likely in the session state management, not key serialization.");
    
    Ok(())
}
