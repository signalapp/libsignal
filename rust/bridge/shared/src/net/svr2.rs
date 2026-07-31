//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use attest::svr2::lookup_groupid;
use futures_util::stream::FuturesOrdered;
use futures_util::{FutureExt as _, StreamExt as _};
use libsignal_account_keys::PinHash;
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::svr2::Svr2ConnectImpl;
use libsignal_bridge_types::net::{ConnectionManager, TokioAsyncContext};
use libsignal_net::auth::Auth;
use libsignal_net::enclave::{EnclaveEndpoint, SvrSgx};
use libsignal_net::env::Svr2Env;
use libsignal_net::svr2::ops::{do_backup, do_delete, do_expose, do_restore};
use libsignal_net::svr2::{
    BackupSession as Svr2BackupSession, Error as Svr2Error,
    MigrationSession as Svr2MigrationSession, RestoreResult as Svr2RestoreResult,
};

use crate::support::*;
use crate::*;

bridge_handle_fns!(Svr2BackupSession, clone = false, ffi = false, jni = false);
bridge_handle_fns!(
    Svr2MigrationSession,
    clone = false,
    ffi = false,
    jni = false
);

fn svr2_client<'a>(
    connection_manager: &'a ConnectionManager,
    endpoint_selector: impl Fn(&'a Svr2Env) -> &'a EnclaveEndpoint<'a, SvrSgx>,
    auth: &'a Auth,
) -> Svr2ConnectImpl<'a> {
    Svr2ConnectImpl {
        connection_manager,
        endpoint: endpoint_selector(&connection_manager.env().svr2),
        auth,
    }
}

fn derive_svr2_pin_hash(mrenclave: &[u8], username: &str, normalized_pin: &[u8]) -> PinHash {
    let group_id = lookup_groupid(mrenclave).expect("SVR2 enclave has a known group id");
    let salt = PinHash::make_salt(username, group_id);
    PinHash::create(normalized_pin, &salt).expect("valid Argon2 parameters")
}

async fn connect_and_backup(
    connection_manager: &ConnectionManager,
    auth: Auth,
    pin: [u8; 32],
    data: Box<[u8]>,
    max_tries: u32,
) -> Result<Svr2BackupSession, Svr2Error> {
    let client = svr2_client(connection_manager, |e| &e.current, &auth);
    let mut conn = client.connect().await?;

    let max_tries = max_tries.try_into()?;
    let data = data.try_into()?;
    Svr2BackupSession::start(&mut conn, pin, data, max_tries).await
}

async fn connect_and_restore(
    connection_manager: &ConnectionManager,
    auth: Auth,
    pin: &[u8; 32],
) -> Result<(Vec<u8>, u32), Svr2Error> {
    let client = svr2_client(connection_manager, |e| &e.current, &auth);
    let mut conn = client.connect().await?;
    let Svr2RestoreResult {
        data,
        tries_remaining,
    } = do_restore(&mut conn, pin).await?;
    Ok((data, tries_remaining))
}

/// Restores the stored blob over `client` and decrypts it back to the master key.
async fn restore_and_decode(
    client: Svr2ConnectImpl<'_>,
    pin_hash: &PinHash,
) -> Result<([u8; 32], u32), Svr2Error> {
    let mut conn = client.connect().await?;
    let Svr2RestoreResult {
        data,
        tries_remaining,
    } = do_restore(&mut conn, &pin_hash.access_key).await?;

    // The stored blob is a 48-byte (16-byte IV || 32-byte ciphertext) encrypted
    // master key. Anything else means the data decoding is impossible.
    let blob: &[u8; 48] = data
        .as_slice()
        .try_into()
        .map_err(|_| Svr2Error::DecryptionError)?;
    let master_key = pin_hash
        .decode_master_key(blob)
        .ok_or(Svr2Error::DecryptionError)?;
    Ok((master_key, tries_remaining))
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn Svr2_StartBackup(
    pin: &[u8; 32],
    data: Box<[u8]>,
    max_tries: u32,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<Svr2BackupSession, Svr2Error> {
    connect_and_backup(
        connection_manager,
        Auth { username, password },
        *pin,
        data,
        max_tries,
    )
    .await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn Svr2_StartMasterKeyBackup(
    normalized_pin: &[u8],
    master_key: &[u8; 32],
    max_tries: u32,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<Svr2BackupSession, Svr2Error> {
    let auth = Auth { username, password };
    let env = connection_manager.env();

    // During an enclave rotation period (when both current and previous are
    // configured), write the master key to the previous enclave first, fully
    // (backup **and** expose). Restore reads the current enclave first and only
    // falls back to previous, so writing previous before current means a client
    // that falls back from current never reads staler data than a client
    // reading previous directly. Any failure here is returned so the caller
    // retries the whole backup; the previous write keeps no resumable state.
    if let Some(previous) = env.svr2.previous.as_ref() {
        let write_previous = async {
            let pin_hash = derive_svr2_pin_hash(
                previous.params.mr_enclave.as_ref(),
                &auth.username,
                normalized_pin,
            );
            let data = pin_hash
                .encode_master_key(master_key)
                .as_slice()
                .try_into()?;
            let mut conn = Svr2ConnectImpl {
                connection_manager,
                endpoint: previous,
                auth: &auth,
            }
            .connect()
            .await?;
            do_backup(
                &mut conn,
                &pin_hash.access_key,
                &data,
                max_tries.try_into()?,
            )
            .await?;
            do_expose(&mut conn, &data).await
        };
        match write_previous.await {
            Ok(()) => {}
            // Enclave was decommissioned but is still configured will 404.
            // Safe to skip.
            Err(e) if e.is_enclave_not_found() => {
                log::info!("SVR2 previous enclave is gone. Skipping the write to it");
            }
            Err(e) => return Err(e),
        }
    }

    // The current enclave uses a two-phase BackupSession: this sends the
    // BackupRequest and attempts the ExposeRequest in one go. If the expose
    // fails, the caller drives it to completion with `finishBackup`.
    let pin_hash = derive_svr2_pin_hash(
        env.svr2.current.params.mr_enclave.as_ref(),
        &auth.username,
        normalized_pin,
    );
    let data = Box::from(pin_hash.encode_master_key(master_key));
    connect_and_backup(
        connection_manager,
        auth,
        pin_hash.access_key,
        data,
        max_tries,
    )
    .await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn Svr2_FinishBackup(
    session: &Svr2BackupSession,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<(), Svr2Error> {
    // Technically finish should consume the session, but Expose operation
    // is idempotent, so cloning is fine.
    session
        .clone()
        .finish(async {
            let auth = Auth { username, password };
            let client = svr2_client(connection_manager, |e| &e.current, &auth);
            client.connect().await
        })
        .await?;
    Ok(())
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn Svr2_Restore(
    pin: &[u8; 32],
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<(Vec<u8>, u32), Svr2Error> {
    connect_and_restore(connection_manager, Auth { username, password }, pin).await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn Svr2_RestoreMasterKey(
    normalized_pin: &[u8],
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<([u8; 32], u32), Svr2Error> {
    let auth = Auth { username, password };
    let env = connection_manager.env();

    // Try the current enclave, then the previous one if available. Each enclave
    // derives its own pin hash because the salt depends on the enclave's group
    // id.
    for endpoint in env.svr2.current_and_previous() {
        let pin_hash = derive_svr2_pin_hash(
            endpoint.params.mr_enclave.as_ref(),
            &auth.username,
            normalized_pin,
        );
        let client = Svr2ConnectImpl {
            connection_manager,
            endpoint,
            auth: &auth,
        };
        match restore_and_decode(client, &pin_hash).await {
            // Data isn't in this enclave - fall through to the next one.
            Err(Svr2Error::DataMissing) => continue,
            // Enclave was decommissioned but is still configured will 404.
            // Safe to move on.
            Err(e) if e.is_enclave_not_found() => continue,
            // Any other error is returned as-is.
            // Successful responses also match the shape of the return type.
            result @ Ok(_) | result @ Err(_) => return result,
        }
    }
    Err(Svr2Error::DataMissing)
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn Svr2_Delete(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<(), Svr2Error> {
    let auth = Auth { username, password };
    let env = connection_manager.env();

    #[derive(PartialEq, Eq)]
    enum Tag {
        Current,
        Previous,
    }
    let endpoints = std::iter::once((&env.svr2.current, Tag::Current))
        .chain(env.svr2.previous.as_ref().map(|prev| (prev, Tag::Previous)));
    // Delete from every configured enclave concurrently, and attempt them all even
    // if one fails, so a failed delete against one enclave never leaves data behind
    // in another.
    let deletes = FuturesOrdered::from_iter(endpoints.map(|(endpoint, tag)| {
        let auth = &auth;
        async move {
            let client = Svr2ConnectImpl {
                connection_manager,
                endpoint,
                auth,
            };
            let mut conn = client.connect().await?;
            do_delete(&mut conn).await
        }
        .map(move |result| match result {
            // A decommissioned enclave that's still configured will 404. There
            // is nothing to delete, so treat it as a successful delete, but
            // only for the `previous` enclave.
            Err(e) if e.is_enclave_not_found() && tag == Tag::Previous => Ok(()),
            result => result,
        })
    }));

    // Run all deletes concurrently, attempting every enclave even if one fails.
    // If more than one fails, report the most important error instead of
    // whichever enclave happens to come first.
    deletes
        .fold(Ok(()), |acc, next| async move {
            match (acc, next) {
                (Err(acc), Err(next)) => Err(Svr2Error::prioritize_error(acc, next)),
                (e @ Err(_), Ok(())) | (Ok(()), e @ Err(_)) => e,
                (Ok(()), Ok(())) => Ok(()),
            }
        })
        .await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn Svr2_Migrate(
    prior_session: Option<&Svr2MigrationSession>,
    normalized_pin: &[u8],
    master_key: &[u8; 32],
    max_tries: u32,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<Svr2MigrationSession, Svr2Error> {
    let auth = Auth { username, password };
    let env = connection_manager.env();
    let max_tries = max_tries.try_into()?;

    let current_mrenclave = env.svr2.current.params.mr_enclave.as_ref();

    // The caller supplies the master key so only the current enclave's pin hash
    // is needed to write it. The previous enclave is never contacted. Derive the
    // pin hash lazily so the no-op and resume paths don't do any crypto.
    let derive_current_pin_hash =
        || derive_svr2_pin_hash(current_mrenclave, &auth.username, normalized_pin);
    let connect_current = async {
        Svr2ConnectImpl {
            connection_manager,
            endpoint: &env.svr2.current,
            auth: &auth,
        }
        .connect()
        .await
    };
    Svr2MigrationSession::migrate(
        prior_session.cloned(),
        connect_current,
        derive_current_pin_hash,
        current_mrenclave,
        master_key,
        max_tries,
    )
    .await
}

#[bridge_fn(ffi = false, jni = false)]
fn Svr2BackupSession_Serialize(session: &Svr2BackupSession) -> Vec<u8> {
    session.serialize()
}

#[bridge_fn(ffi = false, jni = false)]
fn Svr2BackupSession_Deserialize(bytes: &[u8]) -> Result<Svr2BackupSession, Svr2Error> {
    // A corrupt or incompatible serialized session is treated as invalid data.
    Svr2BackupSession::deserialize(bytes).map_err(|_| Svr2Error::DecryptionError)
}

#[bridge_fn(ffi = false, jni = false)]
fn Svr2MigrationSession_Serialize(session: &Svr2MigrationSession) -> Vec<u8> {
    session.serialize()
}

#[bridge_fn(ffi = false, jni = false)]
fn Svr2MigrationSession_Deserialize(bytes: &[u8]) -> Result<Svr2MigrationSession, Svr2Error> {
    // A corrupt or incompatible serialized session is treated as invalid data.
    Svr2MigrationSession::deserialize(bytes).map_err(|_| Svr2Error::DecryptionError)
}

#[bridge_fn(ffi = false, jni = false)]
fn Svr2MigrationSession_IsComplete(session: &Svr2MigrationSession) -> bool {
    session.is_complete()
}
