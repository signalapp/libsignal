//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Low-level SVR2 proto exchange over an established AttestedConnection.

use libsignal_net_infra::ws::attested::AttestedConnection;
use prost::Message as _;

use super::{Error, MaxTries, RestoreResult};
use crate::proto::svr2 as proto;
use crate::svr2::types::Svr2Data;

pub trait Svr2Protocol {
    fn exchange(
        &mut self,
        request: proto::Request,
    ) -> impl Future<Output = Result<proto::Response, Error>>;
}

pub async fn do_backup<T: Svr2Protocol>(
    conn: &mut T,
    pin: &[u8; 32],
    data: &Svr2Data,
    max_tries: MaxTries,
) -> Result<(), Error> {
    let request = proto::Request {
        inner: Some(proto::request::Inner::Backup(proto::BackupRequest {
            pin: pin.to_vec(),
            data: data.as_ref().to_vec(),
            max_tries: max_tries.into(),
        })),
    };
    let response = conn.exchange(request).await?;
    match response.inner {
        Some(proto::response::Inner::Backup(r)) => match r.status() {
            proto::backup_response::Status::Ok => Ok(()),
            proto::backup_response::Status::Unset => Err(Error::Protocol(format!(
                "unexpected backup status: {:?}",
                r.status()
            ))),
        },
        _ => Err(Error::Protocol("unexpected response".to_string())),
    }
}

pub async fn do_expose<T: Svr2Protocol>(conn: &mut T, data: &Svr2Data) -> Result<(), Error> {
    let request = proto::Request {
        inner: Some(proto::request::Inner::Expose(proto::ExposeRequest {
            data: data.as_ref().to_vec(),
        })),
    };
    let response = conn.exchange(request).await?;
    match response.inner {
        Some(proto::response::Inner::Expose(r)) => match r.status() {
            proto::expose_response::Status::Ok => Ok(()),
            proto::expose_response::Status::Unset | proto::expose_response::Status::Error => Err(
                Error::Protocol(format!("unexpected expose status: {:?}", r.status())),
            ),
        },
        _ => Err(Error::Protocol("unexpected response".to_string())),
    }
}

pub async fn do_restore<T: Svr2Protocol>(
    conn: &mut T,
    pin: &[u8; 32],
) -> Result<RestoreResult, Error> {
    let request = proto::Request {
        inner: Some(proto::request::Inner::Restore(proto::RestoreRequest {
            pin: pin.to_vec(),
        })),
    };
    let response = conn.exchange(request).await?;
    match response.inner {
        Some(proto::response::Inner::Restore(r)) => match r.status() {
            proto::restore_response::Status::Ok => Ok(RestoreResult {
                data: r.data,
                tries_remaining: r.tries,
            }),
            proto::restore_response::Status::PinMismatch => Err(Error::RestoreFailed {
                tries_left: r.tries,
            }),
            proto::restore_response::Status::Missing => Err(Error::DataMissing),
            proto::restore_response::Status::Unset => {
                Err(Error::Protocol("unexpected UNSET status".to_string()))
            }
            proto::restore_response::Status::Error => {
                Err(Error::Protocol("error looking up the request".to_string()))
            }
        },
        _ => Err(Error::Protocol("unexpected response".to_string())),
    }
}

pub async fn do_delete<T: Svr2Protocol>(conn: &mut T) -> Result<(), Error> {
    let request = proto::Request {
        inner: Some(proto::request::Inner::Delete(proto::DeleteRequest {})),
    };
    let response = conn.exchange(request).await?;
    match response.inner {
        Some(proto::response::Inner::Delete(_)) => Ok(()),
        _ => Err(Error::Protocol("unexpected response".to_string())),
    }
}

impl Svr2Protocol for AttestedConnection {
    async fn exchange(&mut self, request: proto::Request) -> Result<proto::Response, Error> {
        self.send_bytes(&request.encode_to_vec())
            .await
            .map_err(Error::from_attested_error)?;

        let bytes = self
            .receive_bytes()
            .await
            .map_err(Error::from_attested_error)?;

        let bytes = bytes.next_or(Error::Protocol(
            "connection closed before response".to_string(),
        ))?;

        proto::Response::decode(bytes.as_slice())
            .map_err(|e| Error::Protocol(format!("failed to decode response: {e}")))
    }
}
