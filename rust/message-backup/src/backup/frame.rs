//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use intmap::IntKey;

use crate::backup::WithId;
use crate::proto::backup::{Chat, Recipient};

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, serde::Serialize)]
pub struct RecipientId(pub(super) u64);

/// Foreign key
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, serde::Serialize)]
pub struct ChatId(pub(super) u64);

macro_rules! impl_with_id {
    ($proto:ty, $id:ident, $id_field:ident) => {
        impl WithId for $proto {
            type Id = $id;

            fn id(&self) -> Self::Id {
                $id(self.$id_field)
            }
        }

        impl IntKey for $id {
            type Int = u64;
            const PRIME: Self::Int = u64::PRIME;
            fn into_int(self) -> u64 {
                self.0
            }
        }
    };
}

impl_with_id!(Chat, ChatId, id);
impl_with_id!(Recipient, RecipientId, id);
