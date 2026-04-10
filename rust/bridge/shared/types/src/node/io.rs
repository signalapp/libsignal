//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cell::Cell;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};

use async_trait::async_trait;
use futures_util::TryFutureExt as _;
use libsignal_bridge_macros::bridge_callbacks;

use super::*;
use crate::io::{InputStream, InputStreamRead, SyncInputStream};
use crate::node;

#[bridge_callbacks(ffi = false, jni = false, node = "InputStream")]
trait BridgeInputStream {
    async fn read(&self, amount: u32) -> Result<Box<[u8]>, IoError>;
    async fn skip(&self, amount: u64) -> Result<(), IoError>;
}

#[async_trait(?Send)]
impl InputStream for NodeBridgeInputStream {
    fn read<'out, 'a: 'out>(&'a self, buf: &mut [u8]) -> IoResult<InputStreamRead<'out>> {
        Ok(InputStreamRead::Pending(Box::pin(
            BridgeInputStream::read(
                self,
                buf.len()
                    .try_into()
                    .expect("not trying to read gigabytes at once"),
            )
            .map_ok(|buf| buf.into_vec()),
        )))
    }

    async fn skip(&self, amount: u64) -> IoResult<()> {
        BridgeInputStream::skip(self, amount).await
    }
}

pub struct NodeSyncInputStream<'a> {
    buffer: AssumedImmutableBuffer<'a>,
    pos: Cell<usize>,
}

impl<'a> NodeSyncInputStream<'a> {
    pub(crate) fn new(buffer: AssumedImmutableBuffer<'a>) -> Self {
        Self {
            buffer,
            pos: Default::default(),
        }
    }
}

impl SyncInputStream for NodeSyncInputStream<'_> {
    fn read(&self, buf: &mut [u8]) -> IoResult<usize> {
        let buffer_remaining = &self.buffer[self.pos.get()..];
        let amount_read = buffer_remaining.len().min(buf.len());
        buf[..amount_read].copy_from_slice(&buffer_remaining[..amount_read]);
        self.pos.set(self.pos.get() + amount_read);
        Ok(amount_read)
    }

    fn skip(&self, amount: u64) -> IoResult<()> {
        let buffer_remaining = self.buffer[self.pos.get()..].len();
        if (buffer_remaining as u64) < amount {
            return Err(IoErrorKind::UnexpectedEof.into());
        }
        self.pos.set(
            self.pos.get()
                + usize::try_from(amount).expect("checking against buffer_remaining is sufficient"),
        );
        Ok(())
    }
}
