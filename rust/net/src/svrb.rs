// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::time::Duration;

use futures_util::StreamExt as _;
use hmac::{Hmac, Mac};
use libsignal_account_keys::{
    BackupForwardSecrecyEncryptionKey, BackupForwardSecrecyToken, BackupKey,
};
use libsignal_net_infra::errors::{LogSafeDisplay, RetryLater};
use libsignal_net_infra::ws::attested::AttestedConnectionError;
use libsignal_net_infra::ws::{WebSocketConnectError, WebSocketError};
use libsignal_svrb::proto::backup_metadata;
use libsignal_svrb::{Backup4, Secret};
use protobuf::Message;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, TryRngCore};
use sha2::Sha256;
use signal_crypto::Aes256Ctr32;
use subtle::ConstantTimeEq;
use thiserror::Error;

mod ppss_ops;

pub mod traits;

#[cfg(any(test, feature = "test-util"))]
pub mod direct;

const IV_SIZE: usize = Aes256Ctr32::NONCE_SIZE;
/// Used to avoid a potentially very large number of TCP connections
/// all being initiated at the same time, when hitting multiple backends
/// in parallel.
const BACKUP_CONNECTION_DELAY: Duration = Duration::from_millis(50);

/// SVRB-specific error type
///
/// In its essence it is simply a union of two other error types:
/// - libsignal_svrb::Error for the errors originating in the PPSS implementation. Most of them are
///   unlikely due to the way higher level APIs invoke the lower-level primitives from
///   libsignal_svrb.
/// - libsignal_net::svr::Error for network related errors.
#[derive(Debug, Error, displaydoc::Display)]
#[ignore_extra_doc_attributes]
pub enum Error {
    /// Connection error: {0}
    Connect(WebSocketConnectError),
    /// {0}
    RateLimited(RetryLater),
    /// Network error: {0}
    Service(#[from] WebSocketError),
    /// Protocol error after establishing a connection: {0}
    Protocol(String),
    /// Enclave attestation failed: {0}
    AttestationError(#[from] attest::enclave::Error),
    /// Failure to restore data. {0} tries remaining.
    ///
    /// This could be caused by an invalid password or share set.
    RestoreFailed(u32),
    /// Restore request failed with MISSING status,
    ///
    /// This could mean either the data was never backed-up or we ran out of attempts to restore
    /// it.
    DataMissing,
    /// No connection attempts succeeded before timeout
    AllConnectionAttemptsFailed,
    /// Invalid data from previous backup
    PreviousBackupDataInvalid,
    /// Invalid metadata from backup
    MetadataInvalid,
    /// Decryption error: {0}
    DecryptionError(#[from] signal_crypto::DecryptionError),
}

impl From<libsignal_svrb::Error> for Error {
    fn from(err: libsignal_svrb::Error) -> Self {
        use libsignal_svrb::Error as LogicError;
        match err {
            LogicError::RestoreFailed(tries_remaining) => Self::RestoreFailed(tries_remaining),
            LogicError::BadResponseStatus4(libsignal_svrb::V4Status::MISSING) => Self::DataMissing,
            LogicError::BadData
            | LogicError::BadResponse
            | LogicError::NumServers { .. }
            | LogicError::NoUsableVersion
            | LogicError::BadResponseStatus4(_) => Self::Protocol(err.to_string()),
        }
    }
}

impl From<super::svr::Error> for Error {
    fn from(err: super::svr::Error) -> Self {
        use super::svr::Error as SvrError;
        match err {
            SvrError::WebSocketConnect(inner) => Self::Connect(inner),
            SvrError::RateLimited(inner) => Self::RateLimited(inner),
            SvrError::WebSocket(inner) => Self::Service(inner),
            SvrError::Protocol(error) => Self::Protocol(error.to_string()),
            SvrError::AttestationError(inner) => Self::AttestationError(inner),
            SvrError::AllConnectionAttemptsFailed => Self::AllConnectionAttemptsFailed,
        }
    }
}

impl From<AttestedConnectionError> for Error {
    fn from(err: AttestedConnectionError) -> Self {
        Self::from(super::svr::Error::from(err))
    }
}

impl LogSafeDisplay for Error {}

impl Error {
    /// prioritize_error is used in both backup operations (when combining errors across multiple
    /// backup attempts) and remove errors (when consolidating removals across multiple `current`
    /// enclaves).
    fn prioritize_error(first: Self, second: Self) -> Self {
        match (first, second) {
            // Structural errors first (these shouldn't actually happen, but if they do we don't
            // want to hide them).
            // These will not be returned by `remove` operations.
            (e @ Self::PreviousBackupDataInvalid, _) | (_, e @ Self::PreviousBackupDataInvalid) => {
                e
            }
            (e @ Self::MetadataInvalid, _) | (_, e @ Self::MetadataInvalid) => e,

            // Then errors where we successfully fetched data from the enclave, but it didn't work.
            // This indicates a messed up backup (or a logic error), since the enclave is validating
            // that we have a correct password before returning anything, not just returning
            // whatever's stored for a particular key.
            // These will not be returned by `remove` operations.
            (e @ Self::DecryptionError(_), _) | (_, e @ Self::DecryptionError(_)) => e,

            // Then connection errors, because maybe *another* enclave would have the right data.
            // These may be returned by `remove` operations.
            // These are sorted by "errors that indicate issues that Signal is responsible for"...
            (e @ Self::AttestationError(_), _) | (_, e @ Self::AttestationError(_)) => e,
            (e @ Self::Protocol(_), _) | (_, e @ Self::Protocol(_)) => e,
            // ...then "actionable errors"...
            (e @ Self::RateLimited(_), _) | (_, e @ Self::RateLimited(_)) => e,
            // ...and finally generic "try-again" errors.
            (e @ Self::Service(_), _) | (_, e @ Self::Service(_)) => e,
            (e @ Self::Connect(_), _) | (_, e @ Self::Connect(_)) => e,
            (e @ Self::AllConnectionAttemptsFailed, _)
            | (_, e @ Self::AllConnectionAttemptsFailed) => e,

            // Finally, errors related to the contents of the enclave. It's subtle that
            // RestoreFailed is here! But consider the case where uploading to a new enclave
            // succeeds, deleting from an old enclave *fails*, and then the old enclave is consulted
            // first on restore. We should not return RestoreFailed over whatever connection error
            // we had getting to the new enclave, because we can't definitively say the key is
            // altogether wrong.
            // These will not be returned by `remove` operations.
            (e @ Self::RestoreFailed(_), _) | (_, e @ Self::RestoreFailed(_)) => e,
            (e @ Self::DataMissing, _) /*| (_, e @ Self::DataMissing)*/ => e,
        }
    }
}

/// provide 32 bytes of entropy pulled from the given rng as an array.
fn random_32b<R: CryptoRng + Rng>(rng: &mut R) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.try_fill_bytes(&mut bytes).expect("available entropy");
    bytes
}

const HMAC_SHA256_TRUNCATED_BYTES: usize = 16;

/// provide a HMAC-SHA256 as a 32-byte array.
fn hmac_sha256(key: &[u8], iv: &[u8; IV_SIZE], data: &[u8]) -> [u8; 32] {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 should accept any size key");
    hmac.update(iv);
    hmac.update(data);
    hmac.finalize().into_bytes().into()
}

/// encrypt-then-hmac with AES256-CTR and HMAC-SHA256 truncated to HMAC_SHA256_TRUNCATED_BYTES,
/// concatenating the results.  IV is not attached to the output.
fn aes_256_ctr_encrypt_hmacsha256(
    ek: &BackupForwardSecrecyEncryptionKey,
    iv: &[u8; IV_SIZE],
    ptext: &[u8],
) -> Vec<u8> {
    let mut aes = Aes256Ctr32::from_key(&ek.cipher_key, iv, 0).expect("key size valid");
    let mut ctext = ptext.to_vec();
    aes.process(&mut ctext);
    ctext.extend_from_slice(&hmac_sha256(&ek.hmac_key, iv, &ctext)[..HMAC_SHA256_TRUNCATED_BYTES]);
    ctext
}

/// hmac-then-decrypt with AES256-CTR and HMAC-SHA256 truncated to HMAC_SHA256_TRUNCATED_BYTES,
/// pulling the HMAC bytes from the end of the ciphertext.  IV is not pulled from the input
/// and must be provided separately.
fn aes_256_ctr_hmacsha256_decrypt(
    ek: &BackupForwardSecrecyEncryptionKey,
    iv: &[u8; IV_SIZE],
    ctext: &[u8],
) -> Result<Vec<u8>, signal_crypto::DecryptionError> {
    if ctext.len() < HMAC_SHA256_TRUNCATED_BYTES {
        return Err(signal_crypto::DecryptionError::BadCiphertext(
            "truncated ciphertext",
        ));
    }
    let ctext_len = ctext.len() - HMAC_SHA256_TRUNCATED_BYTES;
    let (ctext, their_mac) = (&ctext[..ctext_len], &ctext[ctext_len..]);
    let our_mac = hmac_sha256(&ek.hmac_key, iv, ctext);
    if our_mac[..HMAC_SHA256_TRUNCATED_BYTES]
        .ct_eq(their_mac)
        .into()
    {
        let mut aes = Aes256Ctr32::from_key(&ek.cipher_key, iv, 0).expect("key size valid");
        let mut ptext = ctext.to_vec();
        aes.process(&mut ptext);
        Ok(ptext)
    } else {
        Err(signal_crypto::DecryptionError::BadCiphertext(
            "MAC verification failed",
        ))
    }
}

pub struct BackupFileMetadata(pub Vec<u8>);
pub struct BackupFileMetadataRef<'a>(pub &'a [u8]);
pub struct BackupPreviousSecretData(pub Vec<u8>);
pub struct BackupPreviousSecretDataRef<'a>(pub &'a [u8]);

impl BackupFileMetadata {
    pub fn as_ref(&self) -> BackupFileMetadataRef<'_> {
        BackupFileMetadataRef(&self.0)
    }
}

impl BackupPreviousSecretData {
    pub fn as_ref(&self) -> BackupPreviousSecretDataRef<'_> {
        BackupPreviousSecretDataRef(&self.0)
    }
}

pub struct BackupStoreResponse {
    pub forward_secrecy_token: BackupForwardSecrecyToken,
    pub next_backup_data: BackupPreviousSecretData,
    pub metadata: BackupFileMetadata,
}

fn create_backup<SvrB: traits::Prepare, R: Rng + CryptoRng>(
    svrb: &SvrB,
    backup_key: &BackupKey,
    rng: &mut R,
) -> (Backup4, [u8; 32]) {
    let password_salt = random_32b(rng);
    let password_key = backup_key.derive_forward_secrecy_password(&password_salt).0;
    (svrb.prepare(&password_key), password_salt)
}

pub fn create_new_backup_chain<SvrB: traits::Prepare>(
    svrb: &SvrB,
    backup_key: &BackupKey,
) -> BackupPreviousSecretData {
    let mut rng = OsRng.unwrap_err();
    let (backup4, pw_salt) = create_backup(svrb, backup_key, &mut rng);
    let secret_data = backup_metadata::NextBackupPb {
        from_previous: Some(backup_metadata::next_backup_pb::From_previous::Backup(
            backup_metadata::next_backup_pb::Backup {
                pw_salt: pw_salt.to_vec(),
                backup4: protobuf::MessageField::some(backup4.into_pb()),
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    BackupPreviousSecretData(secret_data.write_to_bytes().expect("can serialize"))
}

pub async fn store_backup<B: traits::Backup + traits::Prepare, R: traits::Remove>(
    current_svrbs: &[B],
    previous_svrbs: &[R],
    backup_key: &BackupKey,
    previous_backup_data: BackupPreviousSecretDataRef<'_>,
) -> Result<BackupStoreResponse, Error> {
    let mut rng = OsRng.unwrap_err();
    let parsed_prev_data = backup_metadata::NextBackupPb::parse_from_bytes(previous_backup_data.0)
        .map_err(|_| Error::PreviousBackupDataInvalid)?;
    let (prev_encryption_key_salt, prev_backup4, prev_password_salt) = match parsed_prev_data
        .from_previous
        .ok_or(Error::PreviousBackupDataInvalid)?
    {
        backup_metadata::next_backup_pb::From_previous::Restore(restore) => {
            // `previous_backup_data` came from a `restore_backup` call,
            // not a `store_backup` call.  In this case, we want to just keep
            // what's currently in SVRB still in SVRB.  There is no backup4
            // to store, and we use the existing key_salt+pw_salt.
            (
                restore
                    .enc_salt
                    .try_into()
                    .map_err(|_| Error::PreviousBackupDataInvalid)?,
                None,
                restore
                    .pw_salt
                    .try_into()
                    .map_err(|_| Error::PreviousBackupDataInvalid)?,
            )
        }
        backup_metadata::next_backup_pb::From_previous::Backup(mut backup) => {
            // `previous_backup_data` came from a `store_backup` call,
            // so we know that we can write a new backup into SVRB and still
            // have the old backup file decrypt.  Do that.
            let pw_salt = backup
                .pw_salt
                .try_into()
                .map_err(|_| Error::PreviousBackupDataInvalid)?;
            let backup4 = Backup4::from_pb(
                backup
                    .backup4
                    .take()
                    .ok_or(Error::PreviousBackupDataInvalid)?,
            )?;
            (backup4.output, Some(backup4), pw_salt)
        }
        _ => {
            return Err(Error::PreviousBackupDataInvalid);
        }
    };
    // We create a single backup object using the most current SVRB.
    // We then use that backup for all SVRB instances.
    let (next_backup4, next_password_salt) = create_backup(&current_svrbs[0], backup_key, &mut rng);
    let forward_secrecy_token = BackupForwardSecrecyToken(random_32b(&mut rng));

    let mut iv = [0u8; 12];
    rng.try_fill_bytes(&mut iv)
        .expect("should generate entropy");
    let mut metadata_pb = backup_metadata::MetadataPb {
        iv: iv.to_vec(),
        ..Default::default()
    };
    for (encryption_key_salt, password_salt) in [
        (prev_encryption_key_salt, prev_password_salt),
        (next_backup4.output, next_password_salt),
    ] {
        let encryption_key = backup_key.derive_forward_secrecy_encryption_key(&encryption_key_salt);
        metadata_pb.pair.push(backup_metadata::metadata_pb::Pair {
            pw_salt: password_salt.to_vec(),
            ct: aes_256_ctr_encrypt_hmacsha256(&encryption_key, &iv, &forward_secrecy_token.0),
            ..Default::default()
        });
    }

    let next_backup_pb = backup_metadata::NextBackupPb {
        from_previous: Some(backup_metadata::next_backup_pb::From_previous::Backup(
            backup_metadata::next_backup_pb::Backup {
                pw_salt: next_password_salt.to_vec(),
                backup4: protobuf::MessageField::some(next_backup4.into_pb()),
                ..Default::default()
            },
        )),
        ..Default::default()
    };

    if let Some(prev_backup4) = prev_backup4 {
        let mut futures = current_svrbs
            .iter()
            .map(|svrb| svrb.finalize(&prev_backup4))
            .collect::<futures_util::stream::FuturesUnordered<_>>();
        while let Some(result) = futures.next().await {
            result?;
        }

        for r in
            futures_util::future::join_all(previous_svrbs.iter().enumerate().map(async |(i, p)| {
                tokio::time::sleep(
                    u32::try_from(i).expect("should be a small non-negative integer")
                        * BACKUP_CONNECTION_DELAY,
                )
                .await;
                p.remove().await
            }))
            .await
        {
            if let Err(e) = r {
                // Errors here are acceptable, since they might be caused by irreparable
                // issues like a SVRB replica group going down forever.  We do want to
                // do our best to remove, though, so we keep trying each time, and we
                // do report the errors up for debugging purposes.
                log::info!("previous svrb instance remove failure: {e:?}");
            }
        }
    } else {
        log::info!("previous backup data came from a restore; skipping upload to SVR-B");
    }

    Ok(BackupStoreResponse {
        forward_secrecy_token,
        next_backup_data: BackupPreviousSecretData(
            next_backup_pb.write_to_bytes().expect("should serialize"),
        ),
        metadata: BackupFileMetadata(metadata_pb.write_to_bytes().expect("should serialize")),
    })
}

async fn restore_backup_attempt<'a, R: traits::Restore>(
    svrb: &R,
    backup_key: &BackupKey,
    iv: &[u8; IV_SIZE],
    pair: &'a backup_metadata::metadata_pb::Pair,
) -> Result<
    (
        [u8; 32],
        &'a backup_metadata::metadata_pb::Pair,
        BackupForwardSecrecyToken,
    ),
    Error,
> {
    let password_key = backup_key.derive_forward_secrecy_password(&pair.pw_salt).0;
    let encryption_key_salt = svrb.restore(&password_key).await?;
    let encryption_key = backup_key.derive_forward_secrecy_encryption_key(&encryption_key_salt);
    let token = aes_256_ctr_hmacsha256_decrypt(&encryption_key, iv, &pair.ct)?
        .try_into()
        .map_err(|_| signal_crypto::DecryptionError::BadCiphertext("should decrypt to 32 bytes"))?;
    Ok((encryption_key_salt, pair, BackupForwardSecrecyToken(token)))
}

pub struct BackupRestoreResponse {
    pub forward_secrecy_token: BackupForwardSecrecyToken,
    pub next_backup_data: BackupPreviousSecretData,
}

pub async fn restore_backup<R: traits::Restore>(
    current_and_previous_svrbs: &[R],
    backup_key: &BackupKey,
    metadata: BackupFileMetadataRef<'_>,
) -> Result<BackupRestoreResponse, Error> {
    assert!(
        !current_and_previous_svrbs.is_empty(),
        "can't restore from 0 enclaves"
    );
    let metadata = backup_metadata::MetadataPb::parse_from_bytes(metadata.0)
        .map_err(|_| Error::MetadataInvalid)?;
    if metadata.pair.is_empty() {
        return Err(Error::MetadataInvalid);
    }
    let iv: [u8; IV_SIZE] = metadata.iv.try_into().map_err(|_| Error::MetadataInvalid)?;

    let describe_enclave = |i| -> Cow<'static, str> {
        if i == 0 {
            "current enclave".into()
        } else {
            format!("previous enclave {i}").into()
        }
    };
    let mut most_important_error: Option<Error> = None;

    fn delay(enclave_index: usize, pair_index: usize, pairs_len: usize) -> Duration {
        u32::try_from(pair_index + enclave_index * pairs_len)
            .expect("should be a small non-negative integer")
            * BACKUP_CONNECTION_DELAY
    }
    let mut futures = itertools::iproduct!(
        current_and_previous_svrbs.iter().enumerate(),
        metadata.pair.iter().enumerate()
    )
    .map(async |((enclave_index, svrb), (pair_index, pair))| {
        tokio::time::sleep(delay(enclave_index, pair_index, metadata.pair.len())).await;
        let result = restore_backup_attempt(svrb, backup_key, &iv, pair).await;
        (enclave_index, pair_index, result)
    })
    .collect::<futures_util::stream::FuturesUnordered<_>>();
    while let Some((enclave_index, pair_index, result)) = futures.next().await {
        match result {
            Ok((encryption_key_salt, pair, forward_secrecy_token)) => {
                let next_backup_pb = backup_metadata::NextBackupPb {
                    from_previous: Some(backup_metadata::next_backup_pb::From_previous::Restore(
                        backup_metadata::next_backup_pb::Restore {
                            pw_salt: pair.pw_salt.clone(),
                            enc_salt: encryption_key_salt.to_vec(),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                };
                log::info!(
                    "successfully restored from {} using metadata.pair[{pair_index}]",
                    describe_enclave(enclave_index)
                );
                return Ok(BackupRestoreResponse {
                    forward_secrecy_token,
                    next_backup_data: BackupPreviousSecretData(
                        next_backup_pb.write_to_bytes().expect("should serialize"),
                    ),
                });
            }
            Err(e) => {
                log::warn!(
                    "failed to restore from {} using metadata.pair[{pair_index}]: {}",
                    describe_enclave(enclave_index),
                    &e as &dyn LogSafeDisplay,
                );
                most_important_error = Some(match most_important_error {
                    None => e,
                    Some(prev) => Error::prioritize_error(prev, e),
                })
            }
        }
    }
    Err(most_important_error.expect("at least one request and no successes"))
}

pub async fn remove_backup<R: traits::Remove>(
    current_svrbs: &[R],
    previous_svrbs: &[R],
) -> Result<(), Error> {
    let mut most_important_error: Result<(), Error> = Ok(());
    for r in
        futures_util::future::join_all(current_svrbs.iter().chain(previous_svrbs).enumerate().map(
            async |(i, p)| {
                tokio::time::sleep(
                    u32::try_from(i).expect("should be a small non-negative integer")
                        * BACKUP_CONNECTION_DELAY,
                )
                .await;
                p.remove().await
            },
        ))
        .await
        .into_iter()
        // we only care about error codes from the current SVRBs
        .take(current_svrbs.len())
    {
        if let Err(e) = r {
            most_important_error = Err(match most_important_error {
                Ok(_) => e,
                Err(prev) => Error::prioritize_error(prev, e),
            });
        }
    }
    most_important_error
}

#[cfg(feature = "test-util")]
pub mod test_support {

    use libsignal_net_infra::utils::no_network_change_events;

    use crate::auth::Auth;
    use crate::enclave::PpssSetup;
    use crate::env::SvrBEnv;

    impl SvrBEnv<'static> {
        /// Simplest way to connect to an SVRB Environment in integration tests, command
        /// line tools, and examples.
        pub async fn connect_directly(
            &self,
            auth: &Auth,
        ) -> <Self as PpssSetup>::ConnectionResults {
            super::direct::direct_connect(
                self.current()
                    .next()
                    .expect("should have at least one current SVRB"),
                auth,
                &no_network_change_events(),
            )
            .await
        }
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU8, Ordering};

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use futures::future::BoxFuture;
    use libsignal_account_keys::{AccountEntropyPool, BackupKey};
    use libsignal_svrb::{Backup4, Secret};
    use proptest::prelude::*;
    use strum::VariantArray as _;

    use super::*;

    struct TestSvrBClient {
        prepare_fn: fn() -> Backup4,
        finalize_fn: fn() -> Result<(), Error>,
        restore_fn: fn() -> Result<Secret, Error>,
        remove_fn: fn() -> Result<(), Error>,
    }

    impl Default for TestSvrBClient {
        fn default() -> Self {
            Self {
                prepare_fn: || panic!("Unexpected call to prepare_fn"),
                finalize_fn: || panic!("Unexpected call to backup"),
                restore_fn: || panic!("Unexpected call to restore"),
                remove_fn: || panic!("Unexpected call to remove"),
            }
        }
    }

    impl traits::Prepare for TestSvrBClient {
        fn prepare(&self, _password: &[u8]) -> Backup4 {
            (self.prepare_fn)()
        }
    }

    impl traits::Prepare for &TestSvrBClient {
        fn prepare(&self, _password: &[u8]) -> Backup4 {
            (self.prepare_fn)()
        }
    }

    #[async_trait]
    impl traits::Backup for &TestSvrBClient {
        async fn finalize(&self, _b4: &Backup4) -> Result<(), Error> {
            (self.finalize_fn)()
        }
    }

    #[async_trait]
    impl traits::Remove for TestSvrBClient {
        async fn remove(&self) -> Result<(), Error> {
            (self.remove_fn)()
        }
    }

    #[async_trait]
    impl traits::Restore for TestSvrBClient {
        async fn restore(&self, _password: &[u8]) -> Result<Secret, Error> {
            (self.restore_fn)()
        }
    }

    #[async_trait]
    impl traits::Query for TestSvrBClient {
        async fn query(&self) -> Result<u32, Error> {
            unreachable!()
        }
    }

    #[test]
    fn aes_roundtrip() -> Result<(), Error> {
        let ek = BackupForwardSecrecyEncryptionKey {
            hmac_key: [1u8; 32],
            cipher_key: [2u8; 32],
        };
        let iv = [0u8; 12];
        let mut ct = aes_256_ctr_encrypt_hmacsha256(&ek, &iv, b"plaintext");
        assert_eq!(
            b"plaintext" as &[u8],
            &aes_256_ctr_hmacsha256_decrypt(&ek, &iv, &ct)?,
        );
        ct[0] ^= 1;
        assert!(matches!(
            aes_256_ctr_hmacsha256_decrypt(&ek, &iv, &ct).unwrap_err(),
            signal_crypto::DecryptionError::BadCiphertext("MAC verification failed")
        ));
        Ok(())
    }

    // typed empty list of SVRB clients to pass to store_backup.
    static EMPTY: [TestSvrBClient; 0] = [];

    #[tokio::test(start_paused = true)]
    async fn backup_key_created_and_restored() {
        let svrb = TestSvrBClient {
            prepare_fn: || Backup4 {
                requests: vec![],
                output: [1u8; 32],
            },
            finalize_fn: || Ok(()),
            restore_fn: || Ok([1u8; 32]),
            ..TestSvrBClient::default()
        };
        let aep = AccountEntropyPool::from_str(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("should create AEP");
        let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);
        let backup = store_backup(
            &[&svrb],
            &EMPTY,
            &backup_key,
            create_new_backup_chain(&svrb, &backup_key).as_ref(),
        )
        .await
        .expect("should store");
        let restored = restore_backup(
            &[svrb],
            &backup_key,
            BackupFileMetadataRef(&backup.metadata.0),
        )
        .await
        .expect("should restore");
        assert_eq!(
            backup.forward_secrecy_token.0,
            restored.forward_secrecy_token.0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backup_key_created_and_restore_failed_due_to_restore_mismatch() {
        let svrb = TestSvrBClient {
            prepare_fn: || Backup4 {
                requests: vec![],
                output: [1u8; 32],
            },
            finalize_fn: || Ok(()),
            restore_fn: || Ok([2u8; 32]),
            ..TestSvrBClient::default()
        };
        let aep = AccountEntropyPool::from_str(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("should create AEP");
        let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);
        let backup = store_backup(
            &[&svrb],
            &EMPTY,
            &backup_key,
            create_new_backup_chain(&svrb, &backup_key).as_ref(),
        )
        .await
        .expect("should store");
        assert!(
            restore_backup(
                &[svrb],
                &backup_key,
                BackupFileMetadataRef(&backup.metadata.0)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backup_store_restore_store() {
        let svrb = TestSvrBClient {
            prepare_fn: || Backup4 {
                requests: vec![],
                output: [1u8; 32],
            },
            finalize_fn: || Ok(()),
            restore_fn: || Ok([1u8; 32]),
            ..TestSvrBClient::default()
        };
        let aep = AccountEntropyPool::from_str(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("should create AEP");
        let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);
        let backup = store_backup(
            &[&svrb],
            &EMPTY,
            &backup_key,
            create_new_backup_chain(&svrb, &backup_key).as_ref(),
        )
        .await
        .expect("should store");
        let restored = restore_backup(
            &[svrb],
            &backup_key,
            BackupFileMetadataRef(&backup.metadata.0),
        )
        .await
        .expect("should restore");
        assert_eq!(
            backup.forward_secrecy_token.0,
            restored.forward_secrecy_token.0
        );

        // The next store call should not actually finalize a backup,
        // since it should just use the key in `restore_previous_secret_data`
        let svrb = TestSvrBClient {
            prepare_fn: || Backup4 {
                requests: vec![],
                output: [2u8; 32],
            },
            restore_fn: || Ok([1u8; 32]),
            ..TestSvrBClient::default()
        };
        let backup = store_backup(
            &[&svrb],
            &EMPTY,
            &backup_key,
            restored.next_backup_data.as_ref(),
        )
        .await
        .expect("should store");
        let restored2 = restore_backup(
            &[svrb],
            &backup_key,
            BackupFileMetadataRef(&backup.metadata.0),
        )
        .await
        .expect("should restore");
        let r1 = assert_matches!(
            backup_metadata::NextBackupPb::parse_from_bytes(&restored.next_backup_data.0)
                .expect("should deserialize")
                .from_previous
                .unwrap(), backup_metadata::next_backup_pb::From_previous::Restore(r) => r);
        let r2 = assert_matches!(
            backup_metadata::NextBackupPb::parse_from_bytes(&restored2.next_backup_data.0)
                .expect("should deserialize")
                .from_previous
                .unwrap(), backup_metadata::next_backup_pb::From_previous::Restore(r) => r);
        assert_eq!(r1.enc_salt, r2.enc_salt);
        assert_eq!(r1.pw_salt, r2.pw_salt);
        // The actual forward secrecy tokens should differ.
        assert!(restored2.forward_secrecy_token.0 != restored.forward_secrecy_token.0);
    }

    #[tokio::test(start_paused = true)]
    async fn restore_primary_success() {
        let svrb = TestSvrBClient {
            prepare_fn: || Backup4 {
                requests: vec![],
                output: [1u8; 32],
            },
            finalize_fn: || Ok(()),
            restore_fn: || Ok([1u8; 32]),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || panic!("Must not be called"),
            ..TestSvrBClient::default()
        };
        let aep = AccountEntropyPool::from_str(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("should create AEP");
        let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);
        let backup = store_backup(
            &[&svrb],
            &EMPTY,
            &backup_key,
            create_new_backup_chain(&svrb, &backup_key).as_ref(),
        )
        .await
        .expect("should store");
        let restored = restore_backup(
            &[svrb, fallback],
            &backup_key,
            BackupFileMetadataRef(&backup.metadata.0),
        )
        .await
        .expect("should restore");
        assert_eq!(
            backup.forward_secrecy_token.0,
            restored.forward_secrecy_token.0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn restore_primary_error_fallback_success() {
        let svrb = TestSvrBClient {
            prepare_fn: || Backup4 {
                requests: vec![],
                output: [1u8; 32],
            },
            finalize_fn: || Ok(()),
            restore_fn: || Err(Error::RestoreFailed(31415)),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || Ok([1u8; 32]),
            ..TestSvrBClient::default()
        };
        let aep = AccountEntropyPool::from_str(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("should create AEP");
        let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);
        let backup = store_backup(
            &[&svrb],
            &EMPTY,
            &backup_key,
            create_new_backup_chain(&svrb, &backup_key).as_ref(),
        )
        .await
        .expect("should finalize");
        let restored = restore_backup(
            &[svrb, fallback],
            &backup_key,
            BackupFileMetadataRef(&backup.metadata.0),
        )
        .await
        .expect("should restore");
        assert_eq!(
            backup.forward_secrecy_token.0,
            restored.forward_secrecy_token.0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn restore_primary_error_fallback_error() {
        let svrb = TestSvrBClient {
            prepare_fn: || Backup4 {
                requests: vec![],
                output: [1u8; 32],
            },
            finalize_fn: || Ok(()),
            restore_fn: || Err(Error::RestoreFailed(11111)),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || Err(Error::RestoreFailed(22222)),
            ..TestSvrBClient::default()
        };
        let aep = AccountEntropyPool::from_str(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("should create AEP");
        let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);
        let backup = store_backup(
            &[&svrb],
            &EMPTY,
            &backup_key,
            create_new_backup_chain(&svrb, &backup_key).as_ref(),
        )
        .await
        .expect("should store");
        assert!(
            restore_backup(
                &[svrb, fallback],
                &backup_key,
                BackupFileMetadataRef(&backup.metadata.0),
            )
            .await
            .is_err()
        );
    }

    static BACKUP_DELETES_PREVIOUS_ALL_CALLED: AtomicU8 = AtomicU8::new(0);

    #[tokio::test(start_paused = true)]
    async fn backup_deletes_previous() {
        let svrb = TestSvrBClient {
            prepare_fn: || Backup4 {
                requests: vec![],
                output: [1u8; 32],
            },
            finalize_fn: || Ok(()),
            restore_fn: || Err(Error::RestoreFailed(11111)),
            ..TestSvrBClient::default()
        };
        let previous1 = TestSvrBClient {
            remove_fn: || {
                BACKUP_DELETES_PREVIOUS_ALL_CALLED.fetch_add(1, Ordering::SeqCst);
                Err(Error::AllConnectionAttemptsFailed)
            },
            ..TestSvrBClient::default()
        };
        let previous2 = TestSvrBClient {
            remove_fn: || {
                BACKUP_DELETES_PREVIOUS_ALL_CALLED.fetch_add(1, Ordering::SeqCst);
                Err(Error::AllConnectionAttemptsFailed)
            },
            ..TestSvrBClient::default()
        };
        let aep = AccountEntropyPool::from_str(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("should create AEP");
        let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);
        store_backup(
            &[&svrb],
            &[previous1, previous2],
            &backup_key,
            create_new_backup_chain(&svrb, &backup_key).as_ref(),
        )
        .await
        .expect("should store");
        assert_eq!(BACKUP_DELETES_PREVIOUS_ALL_CALLED.load(Ordering::SeqCst), 2);
    }

    struct Scenario {
        backup_key: BackupKey,
        // We emulate N enclaves at a time, where the first `current_enclaves` are current,
        // and the remaining ones are previous.  Each enclave can store new data.
        // This is affected by the following functions:
        //   create_new_current_enclave - pushes a new `current` enclave on the front of the deque
        //   demote_oldest_current_enclave - marks the oldest `current` enclave as `previous`
        //   remove_oldest_previous_enclave - pops the last `previous` enclave, if one exists
        currently_stored_in_enclaves: VecDeque<RefCell<Option<Secret>>>,
        current_enclaves: usize,

        current_uploaded_backup_metadata: Option<BackupFileMetadata>,
        backup_secret_data: Option<BackupPreviousSecretData>,
    }

    enum ScenarioClientOutcome {
        Success,
        Failure,
    }

    struct ScenarioClient<'a>(&'a RefCell<Option<Secret>>, ScenarioClientOutcome);

    impl traits::Prepare for ScenarioClient<'_> {
        fn prepare(&self, _password: &[u8]) -> Backup4 {
            let output = random_32b(&mut OsRng.unwrap_err());
            Backup4 {
                requests: vec![],
                output,
            }
        }
    }

    impl traits::Backup for ScenarioClient<'_> {
        // Written explicitly so we can modify `self` *before* producing the Future.
        fn finalize<'life0, 'life1, 'async_trait>(
            &'life0 self,
            backup: &'life1 Backup4,
        ) -> BoxFuture<'life0, Result<(), Error>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            if let ScenarioClientOutcome::Failure = self.1 {
                return Box::pin(std::future::ready(Err(Error::AllConnectionAttemptsFailed)));
            }
            let mut state = self.0.borrow_mut();
            *state = Some(backup.output);
            Box::pin(std::future::ready(Ok(())))
        }
    }

    impl traits::Remove for ScenarioClient<'_> {
        // Written explicitly so we can modify `self` *before* producing the Future.
        fn remove<'life0, 'async_trait>(&'life0 self) -> BoxFuture<'life0, Result<(), Error>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            if let ScenarioClientOutcome::Failure = self.1 {
                return Box::pin(std::future::ready(Err(Error::AllConnectionAttemptsFailed)));
            }
            let mut state = self.0.borrow_mut();
            *state = None;
            Box::pin(std::future::ready(Ok(())))
        }
    }

    impl traits::Restore for ScenarioClient<'_> {
        // Written explicitly so we can access `self` *before* producing the Future.
        fn restore<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _password: &'life1 [u8],
        ) -> BoxFuture<'life0, Result<Secret, Error>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            if let ScenarioClientOutcome::Failure = self.1 {
                return Box::pin(std::future::ready(Err(Error::AllConnectionAttemptsFailed)));
            }
            let result = self.0.borrow().ok_or(Error::DataMissing);
            Box::pin(std::future::ready(result))
        }
    }

    impl Scenario {
        fn new() -> Self {
            let aep = AccountEntropyPool::from_str(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("should create AEP");
            let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);
            let mut currently_stored_in_enclaves = VecDeque::new();
            currently_stored_in_enclaves.push_back(RefCell::new(None));
            Self {
                backup_key,
                currently_stored_in_enclaves,
                current_enclaves: 1,
                current_uploaded_backup_metadata: None,
                backup_secret_data: None,
            }
        }

        fn client(&self, i: usize, outcome: ScenarioClientOutcome) -> ScenarioClient<'_> {
            ScenarioClient(&self.currently_stored_in_enclaves[i], outcome)
        }

        fn create_new_backup_chain(&mut self) {
            self.backup_secret_data = Some(create_new_backup_chain(
                &self.client(0, ScenarioClientOutcome::Success),
                &self.backup_key,
            ));
        }

        fn failures_outcome(i: usize, failures: &[usize]) -> ScenarioClientOutcome {
            if failures.contains(&i) {
                ScenarioClientOutcome::Failure
            } else {
                ScenarioClientOutcome::Success
            }
        }

        fn current_stored_values(&self) -> Vec<Option<Secret>> {
            self.currently_stored_in_enclaves
                .iter()
                .map(|rc| *rc.borrow())
                .collect::<Vec<_>>()
        }

        fn current_enclaves(&self, failures: &[usize]) -> Vec<ScenarioClient<'_>> {
            (0..self.current_enclaves)
                .map(|i| self.client(i, Self::failures_outcome(i, failures)))
                .collect::<Vec<_>>()
        }

        fn previous_enclaves(&self, failures: &[usize]) -> Vec<ScenarioClient<'_>> {
            (self.current_enclaves..self.currently_stored_in_enclaves.len())
                .map(|i| self.client(i, Self::failures_outcome(i, failures)))
                .collect::<Vec<_>>()
        }

        fn current_and_previous_enclaves(&self, failures: &[usize]) -> Vec<ScenarioClient<'_>> {
            (0..self.currently_stored_in_enclaves.len())
                .map(|i| self.client(i, Self::failures_outcome(i, failures)))
                .collect::<Vec<_>>()
        }

        async fn upload_secret_to_svr(
            &self,
            failures: &[usize],
        ) -> Result<BackupStoreResponse, Error> {
            let previous_secret_data = self
                .backup_secret_data
                .as_ref()
                .expect("has secret data before store");
            store_backup(
                &self.current_enclaves(failures),
                &self.previous_enclaves(failures),
                &self.backup_key,
                previous_secret_data.as_ref(),
            )
            .await
        }

        async fn remove_secret_from_svr(&self, failures: &[usize]) -> Result<(), Error> {
            remove_backup(
                &self.current_enclaves(failures),
                &self.previous_enclaves(failures),
            )
            .await
        }

        fn upload_backup_to_server(&mut self, metadata: BackupFileMetadata) {
            self.current_uploaded_backup_metadata = Some(metadata);
        }

        fn save_secret_data(&mut self, secret_data: BackupPreviousSecretData) {
            self.backup_secret_data = Some(secret_data);
        }

        async fn complete_one_successful_backup(&mut self) {
            if self.backup_secret_data.is_none() {
                self.create_new_backup_chain();
            }
            let BackupStoreResponse {
                forward_secrecy_token: _,
                next_backup_data,
                metadata,
            } = self
                .upload_secret_to_svr(&[])
                .await
                .expect("upload should succeed");
            self.upload_backup_to_server(metadata);
            self.save_secret_data(next_backup_data);
        }

        async fn wipe_and_try_to_restore(&mut self, failures: &[usize]) -> Result<(), Error> {
            self.backup_secret_data = None; // clear even if restore might fail.
            let metadata = self
                .current_uploaded_backup_metadata
                .as_ref()
                .expect("never uploaded a backup");
            let BackupRestoreResponse {
                forward_secrecy_token: _,
                next_backup_data,
            } = restore_backup(
                &self.current_and_previous_enclaves(failures),
                &self.backup_key,
                metadata.as_ref(),
            )
            .await?;
            self.backup_secret_data = Some(next_backup_data);
            Ok(())
        }

        fn create_new_current_enclave(&mut self) {
            self.currently_stored_in_enclaves
                .push_front(RefCell::new(None));
            self.current_enclaves += 1;
        }

        fn demote_oldest_current_enclave(&mut self) -> Result<(), &'static str> {
            if self.current_enclaves <= 1 {
                Err("cowardly refusal to remove last remaining enclave")
            } else {
                self.current_enclaves -= 1;
                Ok(())
            }
        }

        fn remove_oldest_previous_enclave(&mut self) -> Result<(), &'static str> {
            if self.currently_stored_in_enclaves.len() <= self.current_enclaves {
                Err("cowardly refusal to remove a current enclave")
            } else if !self
                .currently_stored_in_enclaves
                .iter()
                .take(self.currently_stored_in_enclaves.len() - 1)
                .any(|enc| enc.borrow().is_some())
            {
                Err("cowardly refusal to remove the only enclave with data in it")
            } else {
                self.currently_stored_in_enclaves.pop_back();
                Ok(())
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn simple_scenario() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;

        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
        // Even if we're really unlucky...
        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn multiple_backups() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;
        scenario.complete_one_successful_backup().await;
        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn second_backup_interrupted() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;

        _ = scenario
            .upload_secret_to_svr(&[])
            .await
            .expect("upload should succeed");
        // Never upload the next backup.

        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn second_and_third_backup_interrupted() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;

        _ = scenario
            .upload_secret_to_svr(&[])
            .await
            .expect("upload should succeed");
        // Never upload the next backup.
        _ = scenario
            .upload_secret_to_svr(&[])
            .await
            .expect("upload should succeed");
        // Again.

        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn extremely_poorly_timed_power_outage() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;

        let BackupStoreResponse {
            forward_secrecy_token: _,
            next_backup_data: _,
            metadata,
        } = scenario
            .upload_secret_to_svr(&[])
            .await
            .expect("upload should succeed");
        scenario.upload_backup_to_server(metadata);
        // Forget to save the secret data.

        scenario.complete_one_successful_backup().await;
        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn extremely_poorly_timed_power_outage_with_next_backup_interrupted() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;

        let BackupStoreResponse {
            forward_secrecy_token: _,
            next_backup_data: _,
            metadata,
        } = scenario
            .upload_secret_to_svr(&[])
            .await
            .expect("upload should succeed");
        scenario.upload_backup_to_server(metadata);
        // Forget to save the secret data.
        _ = scenario
            .upload_secret_to_svr(&[])
            .await
            .expect("upload should succeed");
        // Never upload a new backup.

        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn backup_after_restore() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;

        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
        scenario.complete_one_successful_backup().await;

        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn backup_after_restore_interrupted() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;

        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
        _ = scenario
            .upload_secret_to_svr(&[])
            .await
            .expect("upload should succeed");
        // Never upload the next backup.

        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn backup_after_restore_second_interrupted() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;

        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
        scenario.complete_one_successful_backup().await;
        _ = scenario
            .upload_secret_to_svr(&[])
            .await
            .expect("upload should succeed");
        // Never upload the next backup.

        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn backup_from_previous_enclave() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;
        scenario.create_new_current_enclave();
        scenario
            .demote_oldest_current_enclave()
            .expect("demote should succeed");
        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn backup_after_previous_enclave_removed() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;
        scenario.create_new_current_enclave();
        scenario
            .demote_oldest_current_enclave()
            .expect("demote should succeed");
        scenario.complete_one_successful_backup().await;
        scenario
            .remove_oldest_previous_enclave()
            .expect("removal of previous enclave should succeed");
        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn backup_fails_when_one_current_enclave_fails() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;
        scenario.create_new_current_enclave();
        // Failure of either current enclave causes total failure
        assert!(scenario.upload_secret_to_svr(&[0]).await.is_err());
        assert!(scenario.upload_secret_to_svr(&[1]).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn backup_succeeds_when_previous_enclave_fails() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;
        scenario.create_new_current_enclave();
        scenario
            .demote_oldest_current_enclave()
            .expect("demote should succeed");
        scenario
            .upload_secret_to_svr(&[1])
            .await
            .expect("backup should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn backup_restore_succeeds_after_partial_write_failure() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;
        scenario.create_new_current_enclave();
        assert!(scenario.upload_secret_to_svr(&[0]).await.is_err());
        scenario
            .wipe_and_try_to_restore(&[0])
            .await
            .expect("restore should succeed when unable to talk to 0");
        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed when able to talk to all backends");
    }

    #[tokio::test(start_paused = true)]
    async fn operations_fail_if_all_enclaves_fail() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;
        scenario.create_new_current_enclave();
        assert!(scenario.upload_secret_to_svr(&[0, 1]).await.is_err());
        assert!(scenario.wipe_and_try_to_restore(&[0, 1]).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn backup_succeeds_if_multiple_previous_fail() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;
        scenario.create_new_current_enclave();
        scenario.create_new_current_enclave();
        scenario
            .demote_oldest_current_enclave()
            .expect("demote succeeds");
        scenario
            .demote_oldest_current_enclave()
            .expect("demote succeeds");
        scenario
            .upload_secret_to_svr(&[1, 2])
            .await
            .expect("should successfully upload");
    }

    #[tokio::test(start_paused = true)]
    async fn remove_succeeds_if_multiple_previous_fail() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;
        scenario.create_new_current_enclave();
        scenario.create_new_current_enclave();
        scenario
            .demote_oldest_current_enclave()
            .expect("demote succeeds");
        scenario
            .demote_oldest_current_enclave()
            .expect("demote succeeds");
        scenario
            .remove_secret_from_svr(&[1, 2])
            .await
            .expect("should successfully remove");
    }

    #[tokio::test(start_paused = true)]
    async fn remove_succeeds_on_working_enclaves() {
        let mut scenario = Scenario::new();
        scenario.create_new_current_enclave();
        scenario.create_new_current_enclave();
        scenario.create_new_current_enclave();
        scenario.complete_one_successful_backup().await;
        scenario
            .demote_oldest_current_enclave()
            .expect("demote succeeds");
        scenario
            .demote_oldest_current_enclave()
            .expect("demote succeeds");
        assert!(scenario.remove_secret_from_svr(&[0, 2]).await.is_err());
        let values = scenario.current_stored_values();
        assert!(values[0].is_some());
        assert!(values[1].is_none());
        assert!(values[2].is_some());
        assert!(values[3].is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn backup_not_removed_on_upload_after_restore() {
        let mut scenario = Scenario::new();
        scenario.complete_one_successful_backup().await;
        scenario.create_new_current_enclave();
        scenario
            .demote_oldest_current_enclave()
            .expect("demote succeeds");
        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
        // This test makes sure right here that upload_secret_to_svr doesn't remove
        // the secret from the previous SVRB instance, even though it's been demoted.
        // Since we're "uploading" after a restore, we don't actually upload, which
        // also means we shouldn't actually remove old ones.
        _ = scenario
            .upload_secret_to_svr(&[])
            .await
            .expect("upload should succeed");
        scenario
            .wipe_and_try_to_restore(&[])
            .await
            .expect("restore should succeed");
    }

    #[test]
    fn proptest_latest_backup_is_always_restored() {
        #[derive(Clone, Debug, strum::VariantArray)]
        enum Action {
            UploadSecret,
            UploadSecretAndBackup,
            UploadSecretAndBackupAndSave,
            WipeAndRestore,
            AddNewEnclave,
            DemoteCurrentEnclave,
            RemovePreviousEnclave,
            FailedWriteToCurrent,
        }

        impl proptest::arbitrary::Arbitrary for Action {
            type Parameters = ();
            type Strategy = proptest::sample::Select<Self>;
            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                proptest::sample::select(Self::VARIANTS)
            }
        }

        proptest!(|(actions in proptest::collection::vec(Action::arbitrary(), ..20))| {
            let mut scenario = Scenario::new();

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .unwrap();
            rt.block_on(async {
                // If we haven't completed at least one backup fully, we don't have any of SVR-B's
                // guarantees. In particular:
                //
                // - If we haven't uploaded a backup, we obviously can't restore.
                // - More subtly, if we haven't saved the secret data from the first upload, we can't
                //   recover from the *second* backup process being interrupted.
                //
                // But if someone's very first backup fails, hopefully they don't have anything
                // irreplaceable in Signal yet anyway!
                scenario.complete_one_successful_backup().await;

                for action in actions {
                    match action {
                        Action::UploadSecret => {
                            _ = scenario.upload_secret_to_svr(&[]).await.expect("upload should succeed");
                        }
                        Action::UploadSecretAndBackup => {
                            let BackupStoreResponse {
                                forward_secrecy_token: _,
                                next_backup_data: _,
                                metadata,
                            } = scenario.upload_secret_to_svr(&[]).await.expect("upload should succeed");
                            scenario.upload_backup_to_server(metadata);
                        }
                        Action::UploadSecretAndBackupAndSave => {
                            scenario.complete_one_successful_backup().await;
                        }
                        Action::WipeAndRestore => {
                            scenario.wipe_and_try_to_restore(&[]).await.expect("restore should succeed");
                        }
                        Action::AddNewEnclave => {
                          scenario.create_new_current_enclave();
                        },
                        Action::DemoteCurrentEnclave => {
                          let _ = scenario.demote_oldest_current_enclave();
                        },
                        Action::RemovePreviousEnclave => {
                          let _ = scenario.remove_oldest_previous_enclave();
                        }
                        Action::FailedWriteToCurrent => {
                            let failing_instance = OsRng.unwrap_err().next_u32() as usize % scenario.current_enclaves(&[]).len();
                            // this may succeed if done directly after a WipeAndRestore,
                            // since it'd issue no writes, or it might fail otherwise.
                            let _ = scenario.upload_secret_to_svr(&[failing_instance]).await;
                        }
                    }
                }

                scenario.wipe_and_try_to_restore(&[]).await.expect("restore should succeed");
            });
        });
    }
}
