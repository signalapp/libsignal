//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cell::RefCell;
use std::io;

use super::*;
use crate::io::SyncInputStream;

pub type JavaInputStream<'a> = JObject<'a>;
pub type JavaSyncInputStream<'a> = JObject<'a>;

/// Implementation of [`InputStream`](crate::io::InputStream) for an argument to a bridge function.
pub struct JniBridgeInputStream<'a> {
    env: RefCell<EnvHandle<'a>>,
    stream: JObject<'a>,
}

/// Implementation of [`SyncInputStream`].
pub type JniBridgeSyncInputStream<'a> = JniBridgeInputStream<'a>;

#[derive(Debug, derive_more::From)]
enum BridgeOrIoError {
    Bridge(BridgeLayerError),
    Io(IoError),
}

impl<'a> JniBridgeInputStream<'a> {
    pub fn new(env: &mut jni::Env<'a>, stream: &JObject<'a>) -> Result<Self, BridgeLayerError> {
        check_jobject_type(env, stream, ClassName("java.io.InputStream"))?;
        let stream = env
            .new_local_ref(stream)
            .check_exceptions(env, "JniBridgeInputStream::new")?;
        Ok(Self {
            env: EnvHandle::new(env).into(),
            stream,
        })
    }

    fn do_read(&self, buf: &mut [u8]) -> Result<usize, BridgeOrIoError> {
        self.env.borrow_mut().with_local_frame(8, "read", |env| {
            let java_buf = env
                .new_byte_array(buf.len())
                .check_exceptions(env, "read")?;
            let amount_read: jint = call_method_checked(
                env,
                &self.stream,
                "read",
                jni_args!((java_buf => [byte]) -> int),
            )?;
            let amount_read = match amount_read {
                -1 => 0,
                _ => u32::convert_from(env, &amount_read)? as usize,
            };
            java_buf
                .get_region(
                    env,
                    0,
                    zerocopy::FromBytes::mut_from_bytes(&mut buf[..amount_read])
                        .expect("types have same alignment"),
                )
                .check_exceptions(env, "read")?;
            Ok(amount_read)
        })
    }

    fn do_skip(&self, amount: u64) -> Result<(), BridgeOrIoError> {
        self.env.borrow_mut().with_local_frame(8, "skip", |env| {
            let java_amount = amount.try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "InputStream::skip more than i64::MAX not supported",
                )
            })?;

            let amount_skipped: jlong = call_method_checked(
                env,
                &self.stream,
                "skip",
                jni_args!((java_amount => long) -> long),
            )?;

            if amount_skipped != java_amount {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "InputStream skipped less than requested",
                )
                .into());
            }
            Ok(())
        })
    }
}

impl From<BridgeOrIoError> for IoError {
    fn from(value: BridgeOrIoError) -> Self {
        match value {
            BridgeOrIoError::Io(error) => error,
            BridgeOrIoError::Bridge(bridge_layer_error) => match bridge_layer_error {
                BridgeLayerError::CallbackException(_method_name, exception) => {
                    IoError::other(exception)
                }
                e => IoError::other(e.to_string()),
            },
        }
    }
}

impl SyncInputStream for JniBridgeInputStream<'_> {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(self.do_read(buf)?)
    }

    fn skip(&self, amount: u64) -> io::Result<()> {
        Ok(self.do_skip(amount)?)
    }
}
