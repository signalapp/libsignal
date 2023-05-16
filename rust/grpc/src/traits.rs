//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;

use crate::{GrpcReply, Result};

#[async_trait(?Send)]
pub trait GrpcReplyListener {
    async fn on_reply(
        &mut self,
        reply: GrpcReply,
    ) -> Result<()>;
}
