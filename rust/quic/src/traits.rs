//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;

use crate::Result;

#[async_trait(?Send)]
pub trait QuicCallbackListener {
    async fn on_data(&mut self, data: Vec<u8>) -> Result<()>;
}
