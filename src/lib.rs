#![deny(warnings)]
#![allow(dead_code)]
#![deny(unsafe_code)]

mod address;
mod consts;
mod crypto;
mod curve;
mod error;
mod fingerprint;
mod group_cipher;
mod identity_key;
mod kdf;
mod proto;
mod protocol;
mod ratchet;
mod sender_keys;
mod session;
mod session_cipher;
mod state;
mod storage;

pub use {
    address::ProtocolAddress,
    curve::{KeyPair, PrivateKey, PublicKey},
    error::SignalProtocolError,
    fingerprint::{DisplayableFingerprint, Fingerprint, ScannableFingerprint},
    group_cipher::{
        create_sender_key_distribution_message, group_decrypt, group_encrypt,
        process_sender_key_distribution_message,
    },
    identity_key::{IdentityKey, IdentityKeyPair},
    protocol::{
        CiphertextMessage, CiphertextMessageType, PreKeySignalMessage,
        SenderKeyDistributionMessage, SenderKeyMessage, SignalMessage,
    },
    ratchet::{
        initialize_alice_session, initialize_bob_session, AliceSignalProtocolParameters,
        BobSignalProtocolParameters,
    },
    sender_keys::{SenderKeyName, SenderKeyRecord},
    session::*,
    session_cipher::SessionCipher,
    state::{PreKeyBundle, PreKeyRecord, SessionRecord, SessionState, SignedPreKeyRecord},
    storage::{
        IdentityKeyStore, InMemIdentityKeyStore, InMemPreKeyStore, InMemSenderKeyStore,
        InMemSessionStore, InMemSignalProtocolStore, InMemSignedPreKeyStore, PreKeyStore,
        ProtocolStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
    },
};
