//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_bridge_macros::bridge_callbacks;
use libsignal_protocol::{PreKeyId, PreKeyRecord, PreKeyStore, SignalProtocolError};

use crate::support::{BridgedCallbacks, ResultLike, WithContext};
use crate::*;

/// A bridge-friendly version of [`PreKeyStore`].
#[bridge_callbacks(jni = "org.signal.libsignal.protocol.state.internal.PreKeyStore")]
pub(crate) trait BridgePreKeyStore {
    async fn load_pre_key(&self, id: u32) -> Result<Option<PreKeyRecord>, SignalProtocolError>;
    async fn store_pre_key(&self, id: u32, record: PreKeyRecord)
    -> Result<(), SignalProtocolError>;
    async fn remove_pre_key(&self, id: u32) -> Result<(), SignalProtocolError>;
}

#[async_trait(?Send)]
impl<T: BridgePreKeyStore> PreKeyStore for BridgedCallbacks<T> {
    async fn get_pre_key(&self, pre_key_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        self.0
            .load_pre_key(pre_key_id.into())
            .await?
            .ok_or(SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        pre_key_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0
            .store_pre_key(pre_key_id.into(), record.clone())
            .await
    }

    async fn remove_pre_key(&mut self, pre_key_id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.0.remove_pre_key(pre_key_id.into()).await
    }
}
