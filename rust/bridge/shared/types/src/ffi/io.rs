//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::{c_int, c_void};
use std::io;

use async_trait::async_trait;
use libsignal_protocol::SignalProtocolError;

use super::CallbackError;
use crate::io::{InputStream, InputStreamRead, SyncInputStream};

type Read =
    extern "C" fn(ctx: *mut c_void, buf: *mut u8, buf_len: usize, amount_read: *mut usize) -> c_int;
type Skip = extern "C" fn(ctx: *mut c_void, amount: u64) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiInputStreamStruct {
    ctx: *mut c_void,
    read: Read,
    skip: Skip,
}

pub type FfiSyncInputStreamStruct = FfiInputStreamStruct;

impl FfiInputStreamStruct {
    fn do_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut amount_read = 0;
        let result = (self.read)(self.ctx, buf.as_mut_ptr(), buf.len(), &mut amount_read);
        CallbackError::check(result).map_err(|e| {
            let err = SignalProtocolError::for_application_callback("read")(e);
            io::Error::new(io::ErrorKind::Other, err)
        })?;
        Ok(amount_read)
    }

    fn do_skip(&self, amount: u64) -> io::Result<()> {
        let result = (self.skip)(self.ctx, amount);
        CallbackError::check(result).map_err(|e| {
            let err = SignalProtocolError::for_application_callback("skip")(e);
            io::Error::new(io::ErrorKind::Other, err)
        })
    }
}

#[async_trait(?Send)]
impl InputStream for &FfiInputStreamStruct {
    fn read<'out, 'a: 'out>(&'a self, buf: &mut [u8]) -> io::Result<InputStreamRead<'out>> {
        let amount_read = self.do_read(buf)?;
        Ok(InputStreamRead::Ready { amount_read })
    }

    async fn skip(&self, amount: u64) -> io::Result<()> {
        self.do_skip(amount)
    }
}

impl SyncInputStream for &FfiInputStreamStruct {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.do_read(buf)
    }

    fn skip(&self, amount: u64) -> io::Result<()> {
        self.do_skip(amount)
    }
}
