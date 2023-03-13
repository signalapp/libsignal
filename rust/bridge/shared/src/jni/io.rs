//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io;

use async_trait::async_trait;
use bytemuck::cast_slice_mut;

use super::*;

use crate::io::{InputStream, InputStreamRead};

pub type JavaInputStream<'a> = JObject<'a>;

pub struct JniInputStream<'a> {
    env: &'a JNIEnv<'a>,
    stream: JObject<'a>,
}

impl<'a> JniInputStream<'a> {
    pub fn new(env: &'a JNIEnv, stream: JObject<'a>) -> SignalJniResult<Self> {
        check_jobject_type(env, stream, jni_class_name!(java.io.InputStream))?;
        Ok(Self { env, stream })
    }

    fn do_read(&self, buf: &mut [u8]) -> SignalJniResult<usize> {
        let java_buf = self.env.new_byte_array(buf.len() as i32)?;
        let amount_read: jint = call_method_checked(
            self.env,
            self.stream,
            "read",
            jni_args!((java_buf => [byte]) -> int),
        )?;
        let amount_read = match amount_read {
            -1 => 0,
            _ => u32::convert_from(self.env, amount_read)? as usize,
        };
        self.env
            .get_byte_array_region(java_buf, 0, cast_slice_mut(&mut buf[..amount_read]))?;
        Ok(amount_read)
    }

    fn do_skip(&self, amount: u64) -> SignalJniResult<()> {
        let java_amount = amount.try_into().map_err(|_| {
            SignalJniError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "InputStream::skip more than i64::MAX not supported",
            ))
        })?;

        let amount_skipped: jlong = call_method_checked(
            self.env,
            self.stream,
            "skip",
            jni_args!((java_amount => long) -> long),
        )?;

        if amount_skipped != java_amount {
            return Err(SignalJniError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "InputStream skipped less than requested",
            )));
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl InputStream for JniInputStream<'_> {
    fn read<'out, 'a: 'out>(&'a self, buf: &mut [u8]) -> io::Result<InputStreamRead<'out>> {
        let amount_read = self.do_read(buf)?;
        Ok(InputStreamRead::Ready { amount_read })
    }

    async fn skip(&self, amount: u64) -> io::Result<()> {
        self.do_skip(amount)?;
        Ok(())
    }
}
