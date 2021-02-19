//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;
use async_trait::async_trait;
use libc::{c_int, c_void};

type LoadSenderKey = extern "C" fn(
    store_ctx: *mut c_void,
    *mut *mut SenderKeyRecord,
    *const SenderKeyName,
    ctx: *mut c_void,
) -> c_int;
type StoreSenderKey = extern "C" fn(
    store_ctx: *mut c_void,
    *const SenderKeyName,
    *const SenderKeyRecord,
    ctx: *mut c_void,
) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiSenderKeyStoreStruct {
    ctx: *mut c_void,
    load_sender_key: LoadSenderKey,
    store_sender_key: StoreSenderKey,
}

#[async_trait(?Send)]
impl SenderKeyStore for &FfiSenderKeyStoreStruct {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.store_sender_key)(self.ctx, &*sender_key_name, &*record, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "store_sender_key",
                Box::new(error),
            ));
        }

        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut record = std::ptr::null_mut();
        let result = (self.load_sender_key)(self.ctx, &mut record, &*sender_key_name, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "load_sender_key",
                Box::new(error),
            ));
        }

        if record.is_null() {
            return Ok(None);
        }

        let record = unsafe { Box::from_raw(record) };

        Ok(Some(*record))
    }
}
