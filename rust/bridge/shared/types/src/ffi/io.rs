//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io;

use async_trait::async_trait;
use libsignal_bridge_macros::bridge_callbacks;

use crate::ffi::{self, BridgedStore};
use crate::io::{InputStream, InputStreamRead, SyncInputStream};
use crate::support::{ResultLike, WithContext};

#[bridge_callbacks(jni = false, node = false)]
trait BridgeInputStream {
    fn read(&self, buf: &mut [u8]) -> Result<usize, io::Error>;
    fn skip(&self, amount: u64) -> Result<(), io::Error>;
}

pub type FfiBridgeSyncInputStreamStruct = FfiBridgeInputStreamStruct;

// TODO: These aliases are because of the ffi_arg_type macro expecting all bridging structs to use a
// particular naming scheme; eventually we should be able to remove it.
pub type FfiInputStreamStruct = FfiBridgeInputStreamStruct;
pub type FfiSyncInputStreamStruct = FfiBridgeSyncInputStreamStruct;

#[async_trait(?Send)]
impl<T: BridgeInputStream> InputStream for BridgedStore<T> {
    fn read<'out, 'a: 'out>(&'a self, buf: &mut [u8]) -> io::Result<InputStreamRead<'out>> {
        let amount_read = self.0.read(buf)?;
        Ok(InputStreamRead::Ready { amount_read })
    }

    async fn skip(&self, amount: u64) -> io::Result<()> {
        self.0.skip(amount)
    }
}

impl<T: BridgeInputStream> SyncInputStream for BridgedStore<T> {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    fn skip(&self, amount: u64) -> io::Result<()> {
        self.0.skip(amount)
    }
}
