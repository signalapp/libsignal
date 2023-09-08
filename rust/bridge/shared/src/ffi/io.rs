//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io;

use async_trait::async_trait;
use libc::{c_int, c_void};

use crate::io::{InputStream, InputStreamRead};

use super::CallbackError;

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

#[async_trait(?Send)]
impl InputStream for &FfiInputStreamStruct {
    fn read<'out, 'a: 'out>(&'a self, buf: &mut [u8]) -> io::Result<InputStreamRead<'out>> {
        let mut amount_read = 0;
        let result = (self.read)(self.ctx, buf.as_mut_ptr(), buf.len(), &mut amount_read);
        match CallbackError::check(result) {
            Some(error) => Err(io::Error::new(io::ErrorKind::Other, error)),
            None => Ok(InputStreamRead::Ready { amount_read }),
        }
    }

    async fn skip(&self, amount: u64) -> io::Result<()> {
        let result = (self.skip)(self.ctx, amount);
        match CallbackError::check(result) {
            Some(error) => Err(io::Error::new(io::ErrorKind::Other, error)),
            None => Ok(()),
        }
    }
}
