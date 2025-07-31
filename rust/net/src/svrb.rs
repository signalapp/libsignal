// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hmac::{Hmac, Mac};
use libsignal_account_keys::{
    BackupForwardSecrecyEncryptionKey, BackupForwardSecrecyToken, BackupKey,
};
use libsignal_net_infra::ws::WebSocketServiceError;
use libsignal_net_infra::ws2::attested::AttestedConnectionError;
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

use crate::ws::WebSocketServiceConnectError;

const IV_SIZE: usize = Aes256Ctr32::NONCE_SIZE;

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
    Connect(WebSocketServiceConnectError),
    /// Network error: {0}
    Service(#[from] WebSocketServiceError),
    /// Protocol error after establishing a connection: {0}
    Protocol(String),
    /// Enclave attestation failed: {0}
    AttestationError(attest::enclave::Error),
    /// Failure to restore data. {0} tries remaining.
    ///
    /// This could be caused by an invalid password or share set.
    RestoreFailed(u32),
    /// Restore request failed with MISSING status,
    ///
    /// This could mean either the data was never backed-up or we ran out of attempts to restore
    /// it.
    DataMissing,
    /// Connect timed out
    ConnectionTimedOut,
    /// Invalid data from previous backup
    PreviousBackupDataInvalid,
    /// Invalid metadata from backup
    MetadataInvalid,
    /// Encryption error: {0}
    EncryptionError(signal_crypto::EncryptionError),
    /// Decryption error: {0}
    DecryptionError(signal_crypto::DecryptionError),
    /// Multiple errors: {0:?}
    MultipleErrors(Vec<Error>),
}

impl From<attest::enclave::Error> for Error {
    fn from(err: attest::enclave::Error) -> Self {
        Self::AttestationError(err)
    }
}

impl From<signal_crypto::DecryptionError> for Error {
    fn from(err: signal_crypto::DecryptionError) -> Self {
        Self::DecryptionError(err)
    }
}

impl From<signal_crypto::EncryptionError> for Error {
    fn from(err: signal_crypto::EncryptionError) -> Self {
        Self::EncryptionError(err)
    }
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
            SvrError::WebSocket(inner) => Self::Service(inner),
            SvrError::Protocol(error) => Self::Protocol(error.to_string()),
            SvrError::AttestationError(inner) => Self::AttestationError(inner),
            SvrError::ConnectionTimedOut => Self::ConnectionTimedOut,
        }
    }
}

impl From<AttestedConnectionError> for Error {
    fn from(err: AttestedConnectionError) -> Self {
        Self::from(super::svr::Error::from(err))
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
) -> Result<Vec<u8>, signal_crypto::EncryptionError> {
    let mut aes = Aes256Ctr32::from_key(&ek.cipher_key, iv, 0).expect("key size valid");
    let mut ctext = ptext.to_vec();
    aes.process(&mut ctext);
    ctext.extend_from_slice(&hmac_sha256(&ek.hmac_key, iv, &ctext)[..HMAC_SHA256_TRUNCATED_BYTES]);
    Ok(ctext)
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

pub struct BackupHandle(Backup4);
pub struct BackupFileMetadata(pub Vec<u8>);
pub struct BackupFileMetadataRef<'a>(pub &'a [u8]);
pub struct BackupPreviousSecretData(pub Vec<u8>);
pub struct BackupPreviousSecretDataRef<'a>(pub &'a [u8]);

impl BackupFileMetadata {
    pub fn as_ref(&self) -> BackupFileMetadataRef {
        BackupFileMetadataRef(&self.0)
    }
}

impl BackupPreviousSecretData {
    pub fn as_ref(&self) -> BackupPreviousSecretDataRef {
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

pub async fn store_backup<SvrB: traits::Backup + traits::Prepare>(
    svrb: &SvrB,
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
    let (next_backup4, next_password_salt) = create_backup(svrb, backup_key, &mut rng);
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
            ct: aes_256_ctr_encrypt_hmacsha256(&encryption_key, &iv, &forward_secrecy_token.0)?,
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
        svrb.finalize(&prev_backup4).await?;
    }

    Ok(BackupStoreResponse {
        forward_secrecy_token,
        next_backup_data: BackupPreviousSecretData(
            next_backup_pb.write_to_bytes().expect("should serialize"),
        ),
        metadata: BackupFileMetadata(metadata_pb.write_to_bytes().expect("should serialize")),
    })
}

pub async fn finalize_backup<SvrB: traits::Backup>(
    svrb: &SvrB,
    handle: &BackupHandle,
) -> Result<(), Error> {
    svrb.finalize(&handle.0).await
}

async fn restore_backup_attempt<SvrB: traits::Restore>(
    svrb: &SvrB,
    backup_key: &BackupKey,
    iv: &[u8; IV_SIZE],
    pair: &backup_metadata::metadata_pb::Pair,
) -> Result<([u8; 32], BackupForwardSecrecyToken), Error> {
    let password_key = backup_key.derive_forward_secrecy_password(&pair.pw_salt).0;
    let encryption_key_salt = svrb.restore(&password_key).await?;
    let encryption_key = backup_key.derive_forward_secrecy_encryption_key(&encryption_key_salt);
    Ok((
        encryption_key_salt,
        BackupForwardSecrecyToken(
            aes_256_ctr_hmacsha256_decrypt(&encryption_key, iv, &pair.ct)?
                .try_into()
                .map_err(|_| {
                    signal_crypto::DecryptionError::BadCiphertext("should decrypt to 32 bytes")
                })?,
        ),
    ))
}

pub struct BackupRestoreResponse {
    pub forward_secrecy_token: BackupForwardSecrecyToken,
    pub next_backup_data: BackupPreviousSecretData,
}

pub async fn restore_backup<SvrB: traits::Restore>(
    svrb: &SvrB,
    backup_key: &BackupKey,
    metadata: BackupFileMetadataRef<'_>,
) -> Result<BackupRestoreResponse, Error> {
    let metadata = backup_metadata::MetadataPb::parse_from_bytes(metadata.0)
        .map_err(|_| Error::MetadataInvalid)?;
    if metadata.pair.is_empty() {
        return Err(Error::MetadataInvalid);
    }
    let mut multiple_errors: Vec<Error> = Vec::new();
    let iv: [u8; IV_SIZE] = metadata.iv.try_into().map_err(|_| Error::MetadataInvalid)?;
    for pair in metadata.pair {
        match restore_backup_attempt(svrb, backup_key, &iv, &pair).await {
            Ok((encryption_key_salt, forward_secrecy_token)) => {
                let next_backup_pb = backup_metadata::NextBackupPb {
                    from_previous: Some(backup_metadata::next_backup_pb::From_previous::Restore(
                        backup_metadata::next_backup_pb::Restore {
                            pw_salt: pair.pw_salt,
                            enc_salt: encryption_key_salt.to_vec(),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                };
                return Ok(BackupRestoreResponse {
                    forward_secrecy_token,
                    next_backup_data: BackupPreviousSecretData(
                        next_backup_pb.write_to_bytes().expect("should serialize"),
                    ),
                });
            }
            Err(e) => {
                multiple_errors.push(e);
            }
        }
    }
    Err(Error::MultipleErrors(multiple_errors))
}

/// Attempt a restore from a pair of SVRB instances.
///
/// The function is meant to be used in the registration flow, when the client
/// app does not yet know whether it is supposed to be trusting one set of enclaves
/// or another. Therefore, it first reads from the primary falling back to the
/// secondary enclaves only if the primary returned `DataMissing`, that is, the
/// data has not been migrated yet. Any other error terminates the whole operation
/// and will need to be retried.
///
/// The choice of terms "primary" and "fallback" is, perhaps, a little confusing
/// when thinking about the enclave migration, where they would be called,
/// respectively, "next" and "current", but ordering of parameters and actions in
/// the body of the function make "primary" and "fallback" a better fit.
pub async fn restore_with_fallback<Primary, Fallback>(
    clients: (&Primary, &Fallback),
    password: &[u8],
) -> Result<Secret, Error>
where
    Primary: traits::Restore + Sync,
    Fallback: traits::Restore + Sync,
{
    let (primary_conn, fallback_conn) = clients;

    match primary_conn.restore(password).await {
        Err(Error::DataMissing) => {}
        result @ (Err(_) | Ok(_)) => return result,
    }
    fallback_conn.restore(password).await
}

#[cfg(feature = "test-util")]
pub mod test_support {

    use libsignal_net_infra::testutil::no_network_change_events;

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
            super::direct::direct_connect(self.sgx(), auth, &no_network_change_events()).await
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use libsignal_account_keys::{AccountEntropyPool, BackupKey};
    use libsignal_svrb::{Backup4, Secret};

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

    #[async_trait]
    impl traits::Backup for TestSvrBClient {
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

    #[tokio::test]
    async fn restore_with_fallback_primary_success() {
        let primary = TestSvrBClient {
            restore_fn: || Ok(Secret::default()),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || panic!("Must not be called"),
            ..TestSvrBClient::default()
        };

        let result = restore_with_fallback((&primary, &fallback), b"").await;
        assert_matches!(result, Ok(output4) => assert_eq!(output4, Secret::default()));
    }

    #[tokio::test]
    async fn restore_with_fallback_primary_fatal_error() {
        let primary = TestSvrBClient {
            restore_fn: || Err(Error::ConnectionTimedOut),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || panic!("Must not be called"),
            ..TestSvrBClient::default()
        };

        let result = restore_with_fallback((&primary, &fallback), b"").await;
        assert_matches!(result, Err(Error::ConnectionTimedOut));
    }

    #[tokio::test]
    async fn restore_with_fallback_fallback_error() {
        let primary = TestSvrBClient {
            restore_fn: || Err(Error::DataMissing),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || Err(Error::RestoreFailed(31415)),
            ..TestSvrBClient::default()
        };
        let result = restore_with_fallback((&primary, &fallback), b"").await;
        assert_matches!(result, Err(Error::RestoreFailed(31415)));
    }

    #[tokio::test]
    async fn restore_with_fallback_fallback_success() {
        let primary = TestSvrBClient {
            restore_fn: || Err(Error::DataMissing),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || Ok(Secret::default()),
            ..TestSvrBClient::default()
        };
        let result = restore_with_fallback((&primary, &fallback), b"").await;
        assert_matches!(result, Ok(output4) => assert_eq!(output4, Secret::default()));
    }

    #[test]
    fn aes_roundtrip() -> Result<(), Error> {
        let ek = BackupForwardSecrecyEncryptionKey {
            hmac_key: [1u8; 32],
            cipher_key: [2u8; 32],
        };
        let iv = [0u8; 12];
        let mut ct = aes_256_ctr_encrypt_hmacsha256(&ek, &iv, b"plaintext")?;
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

    #[tokio::test]
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
            &svrb,
            &backup_key,
            create_new_backup_chain(&svrb, &backup_key).as_ref(),
        )
        .await
        .expect("should store");
        let restored = restore_backup(
            &svrb,
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

    #[tokio::test]
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
            &svrb,
            &backup_key,
            create_new_backup_chain(&svrb, &backup_key).as_ref(),
        )
        .await
        .expect("should store");
        assert!(restore_backup(
            &svrb,
            &backup_key,
            BackupFileMetadataRef(&backup.metadata.0)
        )
        .await
        .is_err());
    }

    #[tokio::test]
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
            &svrb,
            &backup_key,
            create_new_backup_chain(&svrb, &backup_key).as_ref(),
        )
        .await
        .expect("should store");
        let restored = restore_backup(
            &svrb,
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
        let backup = store_backup(&svrb, &backup_key, restored.next_backup_data.as_ref())
            .await
            .expect("should store");
        let restored2 = restore_backup(
            &svrb,
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
}
