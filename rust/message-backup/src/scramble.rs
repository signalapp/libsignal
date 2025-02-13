//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Provides the functionality used by the `scramble` tool.
//!
//! The main entry point is the [`Scrambler`] struct.
//!
//! Located in the library proper so that matches over `oneof`s can be exhaustive.

use std::collections::HashMap;

use rand::SeedableRng as _;
use zkgroup::receipts::ReceiptCredentialPresentation;

use crate::backup::MY_STORY_UUID;
use crate::proto::backup as proto;

mod randomize;
use randomize::*;

pub struct Scrambler {
    rng: rand::rngs::StdRng,
    e164s: intmap::IntMap<u64, u64>,
    uuids: HashMap<Box<[u8]>, Box<[u8]>>,
    usernames: u64,
}

impl Scrambler {
    pub fn new() -> Self {
        Self {
            // Use a constant seed for consistent results given the same input.
            rng: rand::rngs::StdRng::seed_from_u64(0),
            e164s: Default::default(),
            uuids: Default::default(),
            usernames: 0,
        }
    }

    pub fn scramble<T>(&mut self, input: &T) -> T
    where
        T: Visit<Self> + Clone,
    {
        let mut result = input.clone();
        result.accept(self);
        result
    }

    fn replace_e164(&mut self, field: &mut u64) {
        // Start with numbers in the range +1-555-555-01xx, generate further plausible numbers after that.
        #[allow(clippy::inconsistent_digit_grouping)]
        const E164_START: u64 = 1_555_555_0100;

        let original = *field;
        let count_of_e164s_so_far: u64 = self.e164s.len().try_into().expect("u64 can hold usize");
        *field = match self.e164s.entry(original) {
            intmap::Entry::Occupied(replacement) => *replacement.get(),
            intmap::Entry::Vacant(entry) => *entry.insert(count_of_e164s_so_far + E164_START),
        };
    }

    /// Consistently replaces a serialized ServiceId (or other UUID) across a backup.
    ///
    /// Despite the name, it is permitted to put arbitrary UUIDs in here, not just ServiceIds.
    ///
    /// Empty fields and nil UUIDs will be left unchanged.
    fn replace_service_id(&mut self, field: &mut Vec<u8>) {
        if field.is_empty() || field[..] == uuid::Uuid::nil().as_bytes()[..] {
            return;
        }

        let original = std::mem::take(field);
        *field = self
            .uuids
            .entry(original.into_boxed_slice())
            .or_insert_with_key(|original| {
                let mut replacement = random_uuid(&mut self.rng);
                if original.len() == replacement.len() + 1 {
                    // Assume original is a non-ACI ServiceId; preserve the type.
                    replacement.insert(0, original[0]);
                } else {
                    // Otherwise, original is either an ACI / plain UUID, or not a valid ServiceId
                    // shape at all. In the latter case, truncate or pad to try to preserve the
                    // mistake.
                    replacement.resize(original.len(), 0xff);
                }
                replacement.into_boxed_slice()
            })
            .to_vec()
    }

    /// Generates a username
    fn next_username(&mut self) -> String {
        self.usernames += 1;
        format!("user.{:02}", self.usernames)
    }
}

impl Default for Scrambler {
    fn default() -> Self {
        Self::new()
    }
}

// Note that this contains REPLACEMENT_URL.
const REPLACEMENT_BODY_TEXT: &str = "https://signal.org: Why use Signal?
Explore below to see why Signal is a simple, powerful, and secure messenger

## Share Without Insecurity
State-of-the-art end-to-end encryption (powered by the open source Signal Protocol) keeps your conversations secure. We can't read your messages or listen to your calls, and no one else can either. Privacy isn't an optional mode - it's just the way that Signal works. Every message, every call, every time.

## Say Anything
Share text, voice messages, photos, videos, GIFs and files for free. Signal uses your phone's data connection so you can avoid SMS and MMS fees.

## Speak Freely
Make crystal-clear voice and video calls to people who live across town, or across the ocean, with no long-distance charges.

## Make Privacy Stick
Add a new layer of expression to your conversations with encrypted stickers. You can also create and share your own sticker packs.

## Get Together with Groups
Group chats make it easy to stay connected to your family, friends, and coworkers.

## No ads. No trackers. No kidding.
There are no ads, no affiliate marketers, and no creepy tracking in Signal. So focus on sharing the moments that matter with the people who matter to you.

## Free for Everyone
Signal is an independent nonprofit. We're not tied to any major tech companies, and we can never be acquired by one either. Development is supported by grants and donations from people like you.";

const REPLACEMENT_EMOJI: &str = "❌";
const REPLACEMENT_URL: &str = "https://signal.org";

fn scramble_content_type(content_type: &mut String) {
    if let Some(split_point) = content_type.find('/') {
        content_type.replace_range(split_point + 1.., "unknown");
    } else {
        *content_type = "unknown".to_owned();
    }
}

/// A generic trait for visiting with state.
///
/// The backup protobuf message types implement this with [`Scrambler`] as the visitor. In general
/// any `string` or `bytes` fields are scrambled in *some* way (usually by randomization), most
/// integers and enums are left intact (explicitly ignored), and sub-messages are recursed into.
///
/// Note that `oneof`s are handled in the parent type rather than as a distinct impl of `Visit`.
/// This is purely a stylistic choice for slightly more compact code; both ways would work.
///
/// There's no built-in traversal here, for a few reasons:
/// - It makes it clearer that a scrambler is supposed to act on or ignore every field explicitly.
/// - If there's ever a reason for scrambling to *not* recurse into a field, it's easier to do so.
///
/// But if we ever want another kind of stateful visitor, we may decide to revisit that decision.
pub trait Visit<T> {
    fn accept(&mut self, visitor: &mut T);
}

/// Recurse into a possibly-absent sub-message.
impl<T: Visit<Scrambler>> Visit<Scrambler> for protobuf::MessageField<T> {
    fn accept(&mut self, visitor: &mut Scrambler) {
        if let Some(x) = self.as_mut() {
            x.accept(visitor);
        }
    }
}

/// Recurse into a `repeated` sub-message.
impl<T: Visit<Scrambler>> Visit<Scrambler> for Vec<T> {
    fn accept(&mut self, visitor: &mut Scrambler) {
        self.iter_mut().for_each(|x| x.accept(visitor));
    }
}

impl Visit<Scrambler> for proto::BackupInfo {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            version: _,
            backupTimeMs: _,
            mediaRootBackupKey,
            currentAppVersion: _,
            firstAppVersion: _,
            special_fields: _,
        } = self;

        mediaRootBackupKey.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::Frame {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            item,
            special_fields: _,
        } = self;

        if let Some(item) = item {
            use proto::frame::Item;
            match item {
                Item::Account(item) => item.accept(visitor),
                Item::Recipient(item) => item.accept(visitor),
                Item::Chat(item) => item.accept(visitor),
                Item::ChatItem(item) => item.accept(visitor),
                Item::StickerPack(item) => item.accept(visitor),
                Item::AdHocCall(item) => item.accept(visitor),
                Item::NotificationProfile(item) => item.accept(visitor),
                Item::ChatFolder(item) => item.accept(visitor),
            }
        }
    }
}

impl Visit<Scrambler> for proto::AccountData {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            profileKey,
            username,
            usernameLink,
            givenName,
            familyName,
            avatarUrlPath,
            donationSubscriberData,
            accountSettings,
            backupsSubscriberData,
            special_fields: _,
        } = self;

        profileKey.randomize(&mut visitor.rng);
        if let Some(username) = username {
            *username = visitor.next_username();
        }
        usernameLink.accept(visitor);
        givenName.randomize(&mut visitor.rng);
        familyName.randomize(&mut visitor.rng);
        if !avatarUrlPath.is_empty() {
            *avatarUrlPath = "https://cdn.signal.org/avatarUrlPath".into();
        }
        donationSubscriberData.accept(visitor);
        accountSettings.accept(visitor);
        backupsSubscriberData.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::account_data::UsernameLink {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            entropy,
            serverId,
            color: _,
            special_fields: _,
        } = self;
        entropy.randomize(&mut visitor.rng);
        visitor.replace_service_id(serverId);
    }
}

impl Visit<Scrambler> for proto::account_data::SubscriberData {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            subscriberId,
            currencyCode: _,
            manuallyCancelled: _,
            special_fields: _,
        } = self;
        subscriberId.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::account_data::AccountSettings {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            readReceipts: _,
            sealedSenderIndicators: _,
            typingIndicators: _,
            linkPreviews: _,
            notDiscoverableByPhoneNumber: _,
            preferContactAvatars: _,
            universalExpireTimerSeconds: _,
            // Not replacing this, it doesn't reveal *that* much information and it might be the cause of problems.
            preferredReactionEmoji: _,
            displayBadgesOnProfile: _,
            keepMutedChatsArchived: _,
            hasSetMyStoriesPrivacy: _,
            hasViewedOnboardingStory: _,
            storiesDisabled: _,
            storyViewReceiptsEnabled: _,
            hasSeenGroupStoryEducationSheet: _,
            hasCompletedUsernameOnboarding: _,
            phoneNumberSharingMode: _,
            defaultChatStyle,
            customChatColors,
            special_fields: _,
        } = self;

        defaultChatStyle.accept(visitor);
        customChatColors.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::ChatStyle {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            dimWallpaperInDarkMode: _,
            wallpaper,
            bubbleColor,
            special_fields: _,
        } = self;

        if let Some(wallpaper) = wallpaper {
            use proto::chat_style::Wallpaper;
            match wallpaper {
                Wallpaper::WallpaperPreset(_) => {}
                Wallpaper::WallpaperPhoto(file) => file.accept(visitor),
            }
        }

        if let Some(color) = bubbleColor {
            use proto::chat_style::BubbleColor;
            match color {
                BubbleColor::AutoBubbleColor(_) => {}
                BubbleColor::BubbleColorPreset(_) => {}
                BubbleColor::CustomColorId(_) => {}
            }
        }
    }
}

impl Visit<Scrambler> for proto::FilePointer {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            contentType,
            incrementalMac,
            incrementalMacChunkSize: _,
            fileName,
            width: _,
            height: _,
            caption,
            blurHash,
            locator,
            special_fields: _,
        } = self;

        contentType.as_mut().map(scramble_content_type);
        incrementalMac.randomize(&mut visitor.rng);
        fileName.randomize(&mut visitor.rng);
        caption.randomize(&mut visitor.rng);
        blurHash.randomize(&mut visitor.rng);

        if let Some(loc) = locator {
            use proto::file_pointer::Locator;
            match loc {
                Locator::BackupLocator(loc) => loc.accept(visitor),
                Locator::AttachmentLocator(loc) => loc.accept(visitor),
                Locator::InvalidAttachmentLocator(loc) => loc.accept(visitor),
            }
        }
    }
}

impl Visit<Scrambler> for proto::file_pointer::BackupLocator {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            mediaName,
            cdnNumber: _,
            key,
            digest,
            size: _,
            transitCdnKey,
            transitCdnNumber: _,
            special_fields: _,
        } = self;

        key.randomize(&mut visitor.rng);
        digest.randomize(&mut visitor.rng);
        let is_thumbnail = mediaName.ends_with("_thumbnail");
        *mediaName = hex::encode(digest);
        if is_thumbnail {
            mediaName.push_str("_thumbnail");
        }
        transitCdnKey.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::file_pointer::AttachmentLocator {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            cdnKey,
            cdnNumber: _,
            uploadTimestamp: _,
            key,
            digest,
            size: _,
            special_fields: _,
        } = self;
        cdnKey.randomize(&mut visitor.rng);
        key.randomize(&mut visitor.rng);
        digest.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::file_pointer::InvalidAttachmentLocator {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Scrambler> for proto::chat_style::CustomChatColor {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            id: _,
            color,
            special_fields: _,
        } = self;

        if let Some(color) = color {
            use proto::chat_style::custom_chat_color::Color;
            match color {
                Color::Solid(_) => {}
                Color::Gradient(_) => {
                    // formally we should recurse into Gradient as well, but seriously now
                }
            }
        }
    }
}

impl Visit<Scrambler> for proto::account_data::IAPSubscriberData {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            subscriberId,
            iapSubscriptionId,
            special_fields: _,
        } = self;

        subscriberId.randomize(&mut visitor.rng);

        if let Some(iap) = iapSubscriptionId {
            use proto::account_data::iapsubscriber_data::IapSubscriptionId;
            match iap {
                IapSubscriptionId::PurchaseToken(token) => token.randomize(&mut visitor.rng),
                IapSubscriptionId::OriginalTransactionId(id) => id.randomize(&mut visitor.rng),
            }
        }
    }
}

impl Visit<Scrambler> for proto::Recipient {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            id: _,
            destination,
            special_fields: _,
        } = self;

        if let Some(dest) = destination {
            use proto::recipient::Destination;
            match dest {
                Destination::Contact(dest) => dest.accept(visitor),
                Destination::Group(dest) => dest.accept(visitor),
                Destination::DistributionList(dest) => dest.accept(visitor),
                Destination::Self_(dest) => dest.accept(visitor),
                Destination::ReleaseNotes(dest) => dest.accept(visitor),
                Destination::CallLink(dest) => dest.accept(visitor),
            }
        }
    }
}

impl Visit<Scrambler> for proto::Contact {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            aci,
            pni,
            username,
            e164,
            blocked: _,
            visibility: _,
            profileKey,
            profileSharing: _,
            profileGivenName,
            profileFamilyName,
            hideStory: _,
            identityKey,
            identityState: _,
            registration,
            nickname,
            systemGivenName,
            systemFamilyName,
            systemNickname,
            note,
            special_fields: _,
        } = self;

        if let Some(aci) = aci {
            visitor.replace_service_id(aci);
        }
        if let Some(pni) = pni {
            visitor.replace_service_id(pni);
        }
        if let Some(username) = username {
            *username = visitor.next_username();
        };
        if let Some(e164) = e164 {
            visitor.replace_e164(e164);
        }
        profileKey.randomize(&mut visitor.rng);
        profileGivenName.randomize(&mut visitor.rng);
        profileFamilyName.randomize(&mut visitor.rng);
        if let Some(identity_key) = identityKey {
            if libsignal_protocol::PublicKey::deserialize(identity_key).is_ok() {
                *identity_key = libsignal_protocol::KeyPair::generate(&mut visitor.rng)
                    .public_key
                    .serialize()
                    .into_vec();
            } else {
                identity_key.randomize(&mut visitor.rng);
            }
        }

        if let Some(reg) = registration {
            use proto::contact::Registration;
            match reg {
                Registration::Registered(reg) => reg.accept(visitor),
                Registration::NotRegistered(reg) => reg.accept(visitor),
            }
        }

        nickname.accept(visitor);
        systemGivenName.randomize(&mut visitor.rng);
        systemFamilyName.randomize(&mut visitor.rng);
        systemNickname.randomize(&mut visitor.rng);
        note.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::contact::Registered {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Scrambler> for proto::contact::NotRegistered {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            unregisteredTimestamp: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::contact::Name {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            given,
            family,
            special_fields: _,
        } = self;
        given.randomize(&mut visitor.rng);
        family.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::Group {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            masterKey,
            whitelisted: _,
            hideStory: _,
            storySendMode: _,
            snapshot,
            blocked: _,
            special_fields: _,
        } = self;
        masterKey.randomize(&mut visitor.rng);
        if let Some(snapshot) = snapshot.as_mut() {
            snapshot.accept(visitor);
        }
    }
}

impl Visit<Scrambler> for proto::group::GroupSnapshot {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            title,
            description,
            avatarUrl,
            disappearingMessagesTimer,
            accessControl,
            version: _,
            members,
            membersPendingProfileKey,
            membersPendingAdminApproval,
            inviteLinkPassword,
            announcements_only: _,
            members_banned,
            special_fields: _,
        } = self;
        title.accept(visitor);
        description.accept(visitor);
        if !avatarUrl.is_empty() {
            *avatarUrl = "https://cdn.signal.org/groupAvatarUrl".into();
        }
        disappearingMessagesTimer.accept(visitor);
        accessControl.accept(visitor);
        members.accept(visitor);
        membersPendingProfileKey.accept(visitor);
        membersPendingAdminApproval.accept(visitor);
        inviteLinkPassword.randomize(&mut visitor.rng);
        members_banned.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::group::GroupAttributeBlob {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            content,
            special_fields: _,
        } = self;

        if let Some(content) = content {
            use proto::group::group_attribute_blob::Content;
            match content {
                Content::Title(title) => title.randomize(&mut visitor.rng),
                Content::Avatar(avatar) => avatar.randomize(&mut visitor.rng),
                Content::DisappearingMessagesDuration(_) => {}
                Content::DescriptionText(text) => text.randomize(&mut visitor.rng),
            }
        }
    }
}

impl Visit<Scrambler> for proto::group::AccessControl {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            attributes: _,
            members: _,
            addFromInviteLink: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::group::Member {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            userId,
            role: _,
            joinedAtVersion: _,
            special_fields: _,
        } = self;
        visitor.replace_service_id(userId);
    }
}

impl Visit<Scrambler> for proto::group::MemberPendingProfileKey {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            member,
            addedByUserId,
            timestamp: _,
            special_fields: _,
        } = self;
        member.accept(visitor);
        visitor.replace_service_id(addedByUserId);
    }
}

impl Visit<Scrambler> for proto::group::MemberPendingAdminApproval {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            userId,
            timestamp: _,
            special_fields: _,
        } = self;
        visitor.replace_service_id(userId);
    }
}

impl Visit<Scrambler> for proto::group::MemberBanned {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            userId,
            timestamp: _,
            special_fields: _,
        } = self;
        visitor.replace_service_id(userId);
    }
}

impl Visit<Scrambler> for proto::DistributionListItem {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            distributionId,
            item,
            special_fields: _,
        } = self;

        let is_my_story = distributionId[..] == MY_STORY_UUID.as_bytes()[..];
        if !is_my_story {
            visitor.replace_service_id(distributionId);
        }

        if let Some(item) = item {
            use proto::distribution_list_item::Item;
            match item {
                Item::DeletionTimestamp(_) => {}
                Item::DistributionList(proto::DistributionList {
                    name,
                    allowReplies: _,
                    privacyMode: _,
                    memberRecipientIds: _,
                    special_fields: _,
                }) => {
                    // We handle the sub-message directly so that we can choose whether to scramble the name or not.
                    if !is_my_story {
                        name.randomize(&mut visitor.rng);
                    }
                }
            }
        }
    }
}

impl Visit<Scrambler> for proto::Self_ {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Scrambler> for proto::ReleaseNotes {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Scrambler> for proto::CallLink {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            rootKey,
            adminKey,
            name,
            restrictions: _,
            expirationMs: _,
            special_fields: _,
        } = self;
        rootKey.randomize(&mut visitor.rng);
        adminKey.randomize(&mut visitor.rng);
        name.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::Chat {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            id: _,
            recipientId: _,
            archived: _,
            pinnedOrder: _,
            expirationTimerMs: _,
            muteUntilMs: _,
            markedUnread: _,
            dontNotifyForMentionsIfMuted: _,
            style,
            expireTimerVersion: _,
            special_fields: _,
        } = self;

        style.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::ChatItem {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            chatId: _,
            authorId: _,
            dateSent: _,
            expireStartDate: _,
            expiresInMs: _,
            revisions,
            sms: _,
            directionalDetails,
            item,
            special_fields: _,
        } = self;

        revisions.accept(visitor);

        if let Some(details) = directionalDetails {
            use proto::chat_item::DirectionalDetails;
            match details {
                DirectionalDetails::Incoming(details) => details.accept(visitor),
                DirectionalDetails::Outgoing(details) => details.accept(visitor),
                DirectionalDetails::Directionless(details) => details.accept(visitor),
            }
        }

        if let Some(item) = item {
            use proto::chat_item::Item;
            match item {
                Item::StandardMessage(item) => item.accept(visitor),
                Item::ContactMessage(item) => item.accept(visitor),
                Item::StickerMessage(item) => item.accept(visitor),
                Item::RemoteDeletedMessage(item) => item.accept(visitor),
                Item::UpdateMessage(item) => item.accept(visitor),
                Item::PaymentNotification(item) => item.accept(visitor),
                Item::GiftBadge(item) => item.accept(visitor),
                Item::ViewOnceMessage(item) => item.accept(visitor),
                Item::DirectStoryReplyMessage(item) => item.accept(visitor),
            }
        }
    }
}

impl Visit<Scrambler> for proto::chat_item::IncomingMessageDetails {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            dateReceived: _,
            dateServerSent: _,
            read: _,
            sealedSender: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::chat_item::OutgoingMessageDetails {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            sendStatus,
            special_fields: _,
        } = self;
        sendStatus.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::SendStatus {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            recipientId: _,
            timestamp: _,
            deliveryStatus,
            special_fields: _,
        } = self;

        if let Some(status) = deliveryStatus {
            use proto::send_status::DeliveryStatus;
            match status {
                DeliveryStatus::Pending(status) => status.accept(visitor),
                DeliveryStatus::Sent(status) => status.accept(visitor),
                DeliveryStatus::Delivered(status) => status.accept(visitor),
                DeliveryStatus::Read(status) => status.accept(visitor),
                DeliveryStatus::Viewed(status) => status.accept(visitor),
                DeliveryStatus::Skipped(status) => status.accept(visitor),
                DeliveryStatus::Failed(status) => status.accept(visitor),
            }
        }
    }
}

impl Visit<Scrambler> for proto::send_status::Pending {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Scrambler> for proto::send_status::Sent {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            sealedSender: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::send_status::Delivered {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            sealedSender: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::send_status::Read {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            sealedSender: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::send_status::Viewed {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            sealedSender: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::send_status::Skipped {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Scrambler> for proto::send_status::Failed {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            reason: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::chat_item::DirectionlessMessageDetails {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Scrambler> for proto::StandardMessage {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            quote,
            text,
            attachments,
            linkPreview,
            longText,
            reactions,
            special_fields: _,
        } = self;

        quote.accept(visitor);
        text.accept(visitor);
        attachments.accept(visitor);
        linkPreview.accept(visitor);
        longText.accept(visitor);
        reactions.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::Quote {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            targetSentTimestamp: _,
            authorId: _,
            text,
            attachments,
            type_: _,
            special_fields: _,
        } = self;

        text.accept(visitor);
        attachments.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::Text {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            body,
            bodyRanges,
            special_fields: _,
        } = self;

        // Use constant text input for better compression later.
        // But make sure we're at least as long as the original body.
        let mut new_body = if body.len() < REPLACEMENT_BODY_TEXT.len() {
            REPLACEMENT_BODY_TEXT[..body.len()].to_owned()
        } else {
            REPLACEMENT_BODY_TEXT.repeat(body.len().div_ceil(REPLACEMENT_BODY_TEXT.len()))
        };

        // Put the U+FFFCs used for mentions back into the body for more plausible ranges.
        // (Although if a message has mentions *and* a link preview, this might stomp on the
        // replacement URL in the body text. Oh well.)
        const MENTION_CHAR: char = '\u{FFFC}';
        const MENTION_CHAR_STR: &str = "\u{FFFC}";
        if !bodyRanges.is_empty() {
            for (index, c) in body.char_indices() {
                if c == MENTION_CHAR {
                    new_body
                        .replace_range(index..(index + MENTION_CHAR_STR.len()), MENTION_CHAR_STR);
                }
            }
        }

        *body = new_body;

        bodyRanges.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::BodyRange {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            start: _,
            length: _,
            associatedValue,
            special_fields: _,
        } = self;

        if let Some(value) = associatedValue {
            use proto::body_range::AssociatedValue;
            match value {
                AssociatedValue::MentionAci(aci) => visitor.replace_service_id(aci),
                AssociatedValue::Style(_) => {}
            }
        }
    }
}

impl Visit<Scrambler> for proto::quote::QuotedAttachment {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            contentType,
            fileName,
            thumbnail,
            special_fields: _,
        } = self;

        contentType.as_mut().map(scramble_content_type);
        fileName.randomize(&mut visitor.rng);
        thumbnail.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::MessageAttachment {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            pointer,
            flag: _,
            wasDownloaded: _,
            clientUuid,
            special_fields: _,
        } = self;
        pointer.accept(visitor);
        if let Some(uuid) = clientUuid {
            visitor.replace_service_id(uuid);
        }
    }
}

impl Visit<Scrambler> for proto::LinkPreview {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            url,
            title,
            image,
            description,
            date: _,
            special_fields: _,
        } = self;

        *url = REPLACEMENT_URL.into();
        title.randomize(&mut visitor.rng);
        image.accept(visitor);
        description.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::Reaction {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            emoji,
            authorId: _,
            sentTimestamp: _,
            sortOrder: _,
            special_fields: _,
        } = self;

        *emoji = REPLACEMENT_EMOJI.into();
    }
}

impl Visit<Scrambler> for proto::ContactMessage {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            contact,
            reactions,
            special_fields: _,
        } = self;
        contact.accept(visitor);
        reactions.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::ContactAttachment {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            name,
            number,
            email,
            address,
            avatar,
            organization,
            special_fields: _,
        } = self;
        name.accept(visitor);
        number.accept(visitor);
        email.accept(visitor);
        address.accept(visitor);
        avatar.accept(visitor);
        organization.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::contact_attachment::Name {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            givenName,
            familyName,
            prefix,
            suffix,
            middleName,
            nickname,
            special_fields: _,
        } = self;
        givenName.randomize(&mut visitor.rng);
        familyName.randomize(&mut visitor.rng);
        prefix.randomize(&mut visitor.rng);
        suffix.randomize(&mut visitor.rng);
        middleName.randomize(&mut visitor.rng);
        nickname.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::contact_attachment::Phone {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            value,
            type_: _,
            label,
            special_fields: _,
        } = self;

        // We could try harder to make this a valid number, but clients can't trust it anyway.
        value.randomize(&mut visitor.rng);
        label.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::contact_attachment::Email {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            value,
            type_: _,
            label,
            special_fields: _,
        } = self;

        // Similarly, we could try to make this a valid email, but clients can't trust this either.
        value.randomize(&mut visitor.rng);
        label.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::contact_attachment::PostalAddress {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            type_: _,
            label,
            street,
            pobox,
            neighborhood,
            city,
            region,
            postcode,
            country,
            special_fields: _,
        } = self;

        label.randomize(&mut visitor.rng);
        street.randomize(&mut visitor.rng);
        pobox.randomize(&mut visitor.rng);
        neighborhood.randomize(&mut visitor.rng);
        city.randomize(&mut visitor.rng);
        region.randomize(&mut visitor.rng);
        postcode.randomize(&mut visitor.rng);
        country.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::StickerMessage {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            sticker,
            reactions,
            special_fields: _,
        } = self;

        sticker.accept(visitor);
        reactions.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::Sticker {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            packId,
            packKey,
            stickerId: _,
            emoji,
            data,
            special_fields: _,
        } = self;
        packId.randomize(&mut visitor.rng);
        packKey.randomize(&mut visitor.rng);
        if let Some(emoji) = emoji {
            *emoji = REPLACEMENT_EMOJI.into();
        }
        data.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::RemoteDeletedMessage {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Scrambler> for proto::ChatUpdateMessage {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            update,
            special_fields: _,
        } = self;

        if let Some(update) = update {
            use proto::chat_update_message::Update;
            match update {
                Update::SimpleUpdate(update) => update.accept(visitor),
                Update::GroupChange(update) => update.accept(visitor),
                Update::ExpirationTimerChange(update) => update.accept(visitor),
                Update::ProfileChange(update) => update.accept(visitor),
                Update::ThreadMerge(update) => update.accept(visitor),
                Update::SessionSwitchover(update) => update.accept(visitor),
                Update::IndividualCall(update) => update.accept(visitor),
                Update::GroupCall(update) => update.accept(visitor),
                Update::LearnedProfileChange(update) => update.accept(visitor),
            }
        }
    }
}

impl Visit<Scrambler> for proto::SimpleChatUpdate {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            type_: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::GroupChangeChatUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updates,
            special_fields: _,
        } = self;
        updates.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::group_change_chat_update::Update {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            update,
            special_fields: _,
        } = self;

        use proto::group_change_chat_update::update::Update;
        if let Some(update) = update.as_mut() {
            match update {
                Update::GenericGroupUpdate(update) => update.accept(visitor),
                Update::GroupCreationUpdate(update) => update.accept(visitor),
                Update::GroupNameUpdate(update) => update.accept(visitor),
                Update::GroupAvatarUpdate(update) => update.accept(visitor),
                Update::GroupDescriptionUpdate(update) => update.accept(visitor),
                Update::GroupMembershipAccessLevelChangeUpdate(update) => update.accept(visitor),
                Update::GroupAttributesAccessLevelChangeUpdate(update) => update.accept(visitor),
                Update::GroupAnnouncementOnlyChangeUpdate(update) => update.accept(visitor),
                Update::GroupAdminStatusUpdate(update) => update.accept(visitor),
                Update::GroupMemberLeftUpdate(update) => update.accept(visitor),
                Update::GroupMemberRemovedUpdate(update) => update.accept(visitor),
                Update::SelfInvitedToGroupUpdate(update) => update.accept(visitor),
                Update::SelfInvitedOtherUserToGroupUpdate(update) => update.accept(visitor),
                Update::GroupUnknownInviteeUpdate(update) => update.accept(visitor),
                Update::GroupInvitationAcceptedUpdate(update) => update.accept(visitor),
                Update::GroupInvitationDeclinedUpdate(update) => update.accept(visitor),
                Update::GroupMemberJoinedUpdate(update) => update.accept(visitor),
                Update::GroupMemberAddedUpdate(update) => update.accept(visitor),
                Update::GroupSelfInvitationRevokedUpdate(update) => update.accept(visitor),
                Update::GroupInvitationRevokedUpdate(update) => update.accept(visitor),
                Update::GroupJoinRequestUpdate(update) => update.accept(visitor),
                Update::GroupJoinRequestApprovalUpdate(update) => update.accept(visitor),
                Update::GroupJoinRequestCanceledUpdate(update) => update.accept(visitor),
                Update::GroupInviteLinkResetUpdate(update) => update.accept(visitor),
                Update::GroupInviteLinkEnabledUpdate(update) => update.accept(visitor),
                Update::GroupInviteLinkAdminApprovalUpdate(update) => update.accept(visitor),
                Update::GroupInviteLinkDisabledUpdate(update) => update.accept(visitor),
                Update::GroupMemberJoinedByLinkUpdate(update) => update.accept(visitor),
                Update::GroupV2MigrationUpdate(update) => update.accept(visitor),
                Update::GroupV2MigrationSelfInvitedUpdate(update) => update.accept(visitor),
                Update::GroupV2MigrationInvitedMembersUpdate(update) => update.accept(visitor),
                Update::GroupV2MigrationDroppedMembersUpdate(update) => update.accept(visitor),
                Update::GroupSequenceOfRequestsAndCancelsUpdate(update) => update.accept(visitor),
                Update::GroupExpirationTimerUpdate(update) => update.accept(visitor),
            }
        }
    }
}

impl Visit<Scrambler> for proto::GenericGroupUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupCreationUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupNameUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            newGroupName,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
        newGroupName.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::GroupAvatarUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            wasRemoved: _,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupDescriptionUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            newDescription,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
        newDescription.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::GroupMembershipAccessLevelChangeUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            accessLevel: _,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupAttributesAccessLevelChangeUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            accessLevel: _,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupAnnouncementOnlyChangeUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            isAnnouncementOnly: _,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupAdminStatusUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            memberAci,
            wasAdminStatusGranted: _,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
        visitor.replace_service_id(memberAci);
    }
}

impl Visit<Scrambler> for proto::GroupMemberLeftUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            aci,
            special_fields: _,
        } = self;
        visitor.replace_service_id(aci);
    }
}

impl Visit<Scrambler> for proto::GroupMemberRemovedUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            removerAci,
            removedAci,
            special_fields: _,
        } = self;
        if let Some(remover) = removerAci {
            visitor.replace_service_id(remover);
        }
        visitor.replace_service_id(removedAci);
    }
}

impl Visit<Scrambler> for proto::SelfInvitedToGroupUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            inviterAci,
            special_fields: _,
        } = self;
        if let Some(inviter) = inviterAci {
            visitor.replace_service_id(inviter);
        }
    }
}

impl Visit<Scrambler> for proto::SelfInvitedOtherUserToGroupUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            inviteeServiceId,
            special_fields: _,
        } = self;
        visitor.replace_service_id(inviteeServiceId);
    }
}

impl Visit<Scrambler> for proto::GroupUnknownInviteeUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            inviterAci,
            inviteeCount: _,
            special_fields: _,
        } = self;
        if let Some(inviter) = inviterAci {
            visitor.replace_service_id(inviter);
        }
    }
}

impl Visit<Scrambler> for proto::GroupInvitationAcceptedUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            inviterAci,
            newMemberAci,
            special_fields: _,
        } = self;
        if let Some(inviter) = inviterAci {
            visitor.replace_service_id(inviter);
        }
        visitor.replace_service_id(newMemberAci);
    }
}

impl Visit<Scrambler> for proto::GroupInvitationDeclinedUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            inviterAci,
            inviteeAci,
            special_fields: _,
        } = self;
        if let Some(inviter) = inviterAci {
            visitor.replace_service_id(inviter);
        }
        if let Some(invitee) = inviteeAci {
            visitor.replace_service_id(invitee);
        }
    }
}

impl Visit<Scrambler> for proto::GroupMemberJoinedUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            newMemberAci,
            special_fields: _,
        } = self;
        visitor.replace_service_id(newMemberAci);
    }
}

impl Visit<Scrambler> for proto::GroupMemberAddedUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            newMemberAci,
            hadOpenInvitation: _,
            inviterAci,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
        visitor.replace_service_id(newMemberAci);
        if let Some(inviter) = inviterAci {
            visitor.replace_service_id(inviter);
        }
    }
}

impl Visit<Scrambler> for proto::GroupSelfInvitationRevokedUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            revokerAci,
            special_fields: _,
        } = self;
        if let Some(revoker) = revokerAci {
            visitor.replace_service_id(revoker);
        }
    }
}

impl Visit<Scrambler> for proto::GroupInvitationRevokedUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            invitees,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
        invitees.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::group_invitation_revoked_update::Invitee {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            inviterAci,
            inviteeAci,
            inviteePni,
            special_fields: _,
        } = self;
        if let Some(inviter) = inviterAci {
            visitor.replace_service_id(inviter);
        }
        if let Some(invitee) = inviteeAci {
            visitor.replace_service_id(invitee);
        }
        if let Some(invitee) = inviteePni {
            visitor.replace_service_id(invitee);
        }
    }
}

impl Visit<Scrambler> for proto::GroupJoinRequestUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            requestorAci,
            special_fields: _,
        } = self;
        visitor.replace_service_id(requestorAci);
    }
}

impl Visit<Scrambler> for proto::GroupJoinRequestApprovalUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            requestorAci,
            updaterAci,
            wasApproved: _,
            special_fields: _,
        } = self;
        visitor.replace_service_id(requestorAci);
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupJoinRequestCanceledUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            requestorAci,
            special_fields: _,
        } = self;
        visitor.replace_service_id(requestorAci);
    }
}

impl Visit<Scrambler> for proto::GroupInviteLinkResetUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupInviteLinkEnabledUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            linkRequiresAdminApproval: _,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupInviteLinkAdminApprovalUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            linkRequiresAdminApproval: _,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupInviteLinkDisabledUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            updaterAci,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::GroupMemberJoinedByLinkUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            newMemberAci,
            special_fields: _,
        } = self;
        visitor.replace_service_id(newMemberAci);
    }
}

impl Visit<Scrambler> for proto::GroupV2MigrationUpdate {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Scrambler> for proto::GroupV2MigrationSelfInvitedUpdate {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Scrambler> for proto::GroupV2MigrationInvitedMembersUpdate {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            invitedMembersCount: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::GroupV2MigrationDroppedMembersUpdate {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            droppedMembersCount: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::GroupSequenceOfRequestsAndCancelsUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            requestorAci,
            count: _,
            special_fields: _,
        } = self;
        visitor.replace_service_id(requestorAci);
    }
}

impl Visit<Scrambler> for proto::GroupExpirationTimerUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            expiresInMs: _,
            updaterAci,
            special_fields: _,
        } = self;
        if let Some(updater) = updaterAci {
            visitor.replace_service_id(updater);
        }
    }
}

impl Visit<Scrambler> for proto::ExpirationTimerChatUpdate {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            expiresInMs: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::ProfileChangeChatUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            previousName,
            newName,
            special_fields: _,
        } = self;
        previousName.randomize(&mut visitor.rng);
        newName.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::ThreadMergeChatUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            previousE164,
            special_fields: _,
        } = self;
        visitor.replace_e164(previousE164);
    }
}

impl Visit<Scrambler> for proto::SessionSwitchoverChatUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            e164,
            special_fields: _,
        } = self;
        visitor.replace_e164(e164);
    }
}

impl Visit<Scrambler> for proto::IndividualCall {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            callId: _,
            type_: _,
            direction: _,
            state: _,
            startedCallTimestamp: _,
            read: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::GroupCall {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            callId: _,
            state: _,
            ringerRecipientId: _,
            startedCallRecipientId: _,
            startedCallTimestamp: _,
            endedCallTimestamp: _,
            read: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::LearnedProfileChatUpdate {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            previousName,
            special_fields: _,
        } = self;

        if let Some(name) = previousName {
            use proto::learned_profile_chat_update::PreviousName;
            match name {
                PreviousName::E164(e164) => visitor.replace_e164(e164),
                PreviousName::Username(username) => *username = visitor.next_username(),
            }
        }
    }
}

impl Visit<Scrambler> for proto::PaymentNotification {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            amountMob,
            feeMob,
            note,
            transactionDetails,
            special_fields: _,
        } = self;

        if let Some(mob) = amountMob {
            *mob = "1.0".into();
        }
        if let Some(mob) = feeMob {
            *mob = "0.1".into();
        }
        note.randomize(&mut visitor.rng);
        transactionDetails.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::payment_notification::TransactionDetails {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            payment,
            special_fields: _,
        } = self;

        if let Some(payment) = payment {
            use proto::payment_notification::transaction_details::Payment;
            match payment {
                Payment::Transaction(transaction) => transaction.accept(visitor),
                Payment::FailedTransaction(transaction) => transaction.accept(visitor),
            }
        }
    }
}

impl Visit<Scrambler> for proto::payment_notification::transaction_details::Transaction {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            status: _,
            mobileCoinIdentification,
            timestamp: _,
            blockIndex,
            blockTimestamp: _,
            transaction,
            receipt,
            special_fields: _,
        } = self;

        mobileCoinIdentification.accept(visitor);
        blockIndex.randomize(&mut visitor.rng);
        transaction.randomize(&mut visitor.rng);
        receipt.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler>
    for proto::payment_notification::transaction_details::MobileCoinTxoIdentification
{
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            publicKey,
            keyImages,
            special_fields: _,
        } = self;
        publicKey.randomize(&mut visitor.rng);
        keyImages.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::payment_notification::transaction_details::FailedTransaction {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            reason: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::GiftBadge {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            receiptCredentialPresentation,
            state: _,
            special_fields: _,
        } = self;

        if let Ok(presentation) =
            zkgroup::deserialize::<ReceiptCredentialPresentation>(receiptCredentialPresentation)
        {
            // Create a new presentation for the same level and timestamp, but removing the serial
            // bytes. The timestamp means it's not *that* much more anonymous, but at least it's not
            // redeemable (it's also the wrong server params, of course). The other downside is that
            // it may not be the same credential version, since we're making a new one from scratch,
            // but that can't be helped unless we want to hardcode a parser for the serialized form.
            let mut entropy: [u8; zkgroup::RANDOMNESS_LEN] = [0; 32];
            entropy.randomize(&mut visitor.rng);

            let server_params = zkgroup::ServerSecretParams::generate(entropy);
            let server_public_params = server_params.get_public_params();
            let request_context = &server_public_params
                .create_receipt_credential_request_context(entropy, [b'r'; 16]);
            let request = request_context.get_request();
            let response = server_params.issue_receipt_credential(
                entropy,
                &request,
                presentation.get_receipt_expiration_time(),
                presentation.get_receipt_level(),
            );
            let credential = server_public_params
                .receive_receipt_credential(request_context, &response)
                .expect("valid request");
            *receiptCredentialPresentation = zkgroup::serialize(
                &server_public_params.create_receipt_credential_presentation(entropy, &credential),
            );
        } else if !receiptCredentialPresentation.is_empty() {
            // It's not valid anyway, just preserve the version and nothing else.
            let version_byte = receiptCredentialPresentation[0];
            receiptCredentialPresentation.randomize(&mut visitor.rng);
            receiptCredentialPresentation[0] = version_byte;
        }
    }
}

impl Visit<Scrambler> for proto::ViewOnceMessage {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            attachment,
            reactions,
            special_fields: _,
        } = self;
        attachment.accept(visitor);
        reactions.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::DirectStoryReplyMessage {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            reactions,
            reply,
            special_fields: _,
        } = self;
        reactions.accept(visitor);
        if let Some(reply) = reply {
            use proto::direct_story_reply_message::Reply;
            match reply {
                Reply::TextReply(text_reply) => text_reply.accept(visitor),
                Reply::Emoji(emoji) => *emoji = REPLACEMENT_EMOJI.into(),
            }
        }
    }
}

impl Visit<Scrambler> for proto::direct_story_reply_message::TextReply {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            text,
            longText,
            special_fields: _,
        } = self;
        text.accept(visitor);
        longText.accept(visitor);
    }
}

impl Visit<Scrambler> for proto::StickerPack {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            packId,
            packKey,
            special_fields: _,
        } = self;
        packId.randomize(&mut visitor.rng);
        packKey.randomize(&mut visitor.rng);
    }
}

impl Visit<Scrambler> for proto::AdHocCall {
    fn accept(&mut self, _visitor: &mut Scrambler) {
        let Self {
            callId: _,
            recipientId: _,
            state: _,
            callTimestamp: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Scrambler> for proto::NotificationProfile {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            name,
            emoji: _,
            color: _,
            createdAtMs: _,
            allowAllCalls: _,
            allowAllMentions: _,
            allowedMembers: _,
            scheduleEnabled: _,
            scheduleStartTime: _,
            scheduleEndTime: _,
            scheduleDaysEnabled: _,
            special_fields: _,
        } = self;

        name.randomize(&mut visitor.rng)
    }
}

impl Visit<Scrambler> for proto::ChatFolder {
    fn accept(&mut self, visitor: &mut Scrambler) {
        let Self {
            name,
            showOnlyUnread: _,
            showMutedChats: _,
            includeAllIndividualChats: _,
            includeAllGroupChats: _,
            folderType: _,
            includedRecipientIds: _,
            excludedRecipientIds: _,
            special_fields: _,
        } = self;

        name.randomize(&mut visitor.rng)
    }
}
