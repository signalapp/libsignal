//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

/// Implement [`From`] to allow construction of a `oneof` enum from a contained
/// message type.
macro_rules! impl_from_oneof {
    ($oneof:path, $msg:path, $constructor:ident) => {
        impl From<$msg> for $oneof {
            fn from(value: $msg) -> Self {
                Self::$constructor(value)
            }
        }
    };
}

use self::backup::*;

impl_from_oneof!(frame::Item, AccountData, Account);
impl_from_oneof!(frame::Item, Recipient, Recipient);
impl_from_oneof!(frame::Item, Chat, Chat);
impl_from_oneof!(frame::Item, ChatItem, ChatItem);
impl_from_oneof!(frame::Item, Call, Call);
impl_from_oneof!(frame::Item, StickerPack, StickerPack);

impl_from_oneof!(recipient::Destination, Group, Group);
impl_from_oneof!(recipient::Destination, Contact, Contact);
impl_from_oneof!(recipient::Destination, DistributionList, DistributionList);

impl_from_oneof!(chat_update_message::Update, SimpleChatUpdate, SimpleUpdate);
impl_from_oneof!(
    chat_update_message::Update,
    GroupDescriptionChatUpdate,
    GroupDescription
);
impl_from_oneof!(
    chat_update_message::Update,
    ExpirationTimerChatUpdate,
    ExpirationTimerChange
);
impl_from_oneof!(
    chat_update_message::Update,
    ProfileChangeChatUpdate,
    ProfileChange
);
impl_from_oneof!(
    chat_update_message::Update,
    ThreadMergeChatUpdate,
    ThreadMerge
);
impl_from_oneof!(
    chat_update_message::Update,
    SessionSwitchoverChatUpdate,
    SessionSwitchover
);
impl_from_oneof!(chat_update_message::Update, CallChatUpdate, CallingMessage);
