use libsignal_protocol_rust::*;
use rand::rngs::OsRng;

pub fn test_in_memory_protocol_store() -> InMemSignalProtocolStore {
    let mut csprng = OsRng;
    let identity_key = IdentityKeyPair::generate(&mut csprng);
    let registration_id = 5; // fixme randomly generate this

    InMemSignalProtocolStore::new(identity_key, registration_id).unwrap()
}
