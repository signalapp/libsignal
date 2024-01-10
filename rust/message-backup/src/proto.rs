//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub(crate) mod unknown;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

macro_rules! impl_into_oneof {
    ($msg:path, $oneof:path, $constructor:ident) => {
        impl From<$msg> for $oneof {
            fn from(value: $msg) -> Self {
                Self::$constructor(value)
            }
        }
    };
}

impl_into_oneof!(
    self::backup::AccountData,
    self::backup::frame::Item,
    Account
);
impl_into_oneof!(
    self::backup::Recipient,
    self::backup::frame::Item,
    Recipient
);
impl_into_oneof!(self::backup::Chat, self::backup::frame::Item, Chat);
impl_into_oneof!(self::backup::ChatItem, self::backup::frame::Item, ChatItem);
impl_into_oneof!(self::backup::Call, self::backup::frame::Item, Call);
impl_into_oneof!(
    self::backup::StickerPack,
    self::backup::frame::Item,
    StickerPack
);
impl_into_oneof!(
    self::backup::Group,
    self::backup::recipient::Destination,
    Group
);
impl_into_oneof!(
    self::backup::Contact,
    self::backup::recipient::Destination,
    Contact
);
impl_into_oneof!(
    self::backup::DistributionList,
    self::backup::recipient::Destination,
    DistributionList
);
