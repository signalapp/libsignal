//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::bridge_io;
use libsignal_bridge_types::net::svr2::Svr2ConnectImpl;
use libsignal_bridge_types::net::{ConnectionManager, TokioAsyncContext};
use libsignal_net::auth::Auth;
use libsignal_net::enclave::{EnclaveEndpoint, SvrSgx};
use libsignal_net::env::Svr2Env;
use libsignal_net::svr2::ops::{do_delete, do_restore};
use libsignal_net::svr2::{
    BackupSession as Svr2BackupSession, Error as Svr2Error, RestoreResult as Svr2RestoreResult,
};

use crate::support::*;
use crate::*;

bridge_handle_fns!(Svr2BackupSession, clone = false, ffi = false, jni = false);

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

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn Svr2_StartBackup(
    pin: &[u8; 32],
    data: Box<[u8]>,
    max_tries: u32,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<Svr2BackupSession, Svr2Error> {
    let auth = Auth { username, password };
    let client = svr2_client(connection_manager, |e| &e.current, &auth);
    let mut conn = client.connect().await?;

    let max_tries = max_tries.try_into()?;
    let data = data.try_into()?;
    let session = Svr2BackupSession::start(&mut conn, *pin, data, max_tries).await?;
    Ok(session)
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
    let auth = Auth { username, password };
    let client = svr2_client(connection_manager, |e| &e.current, &auth);
    let mut conn = client.connect().await?;
    let Svr2RestoreResult {
        data,
        tries_remaining,
    } = do_restore(&mut conn, pin).await?;
    Ok((data, tries_remaining))
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn Svr2_Delete(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<(), Svr2Error> {
    let auth = Auth { username, password };
    let client = svr2_client(connection_manager, |e| &e.current, &auth);
    let mut conn = client.connect().await?;
    do_delete(&mut conn).await
}
