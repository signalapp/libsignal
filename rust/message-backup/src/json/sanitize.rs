//
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Sanitization applied to backup frames before they're exported to JSON.
//!
//! Every field of every backup message is destructured exhaustively by
//! [`Sanitizer`], so adding a field to the backup protos requires deciding
//! whether it should be included in the export. Fields bound to `_` are kept
//! as-is; sub-messages are recursed into.

use crate::proto::backup as proto;
use crate::visit::Visit;

/// Strips sensitive fields, such as keys, from backup messages.
pub(super) struct Sanitizer;

impl Visit<Sanitizer> for proto::BackupInfo {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            version: _,
            backupTimeMs: _,
            mediaRootBackupKey,
            currentAppVersion: _,
            firstAppVersion: _,
            debugInfo: _,
            special_fields: _,
        } = self;

        mediaRootBackupKey.clear();
    }
}

impl Visit<Sanitizer> for proto::Frame {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            item: item_field,
            special_fields: _,
        } = self;

        if let Some(item) = item_field {
            use proto::frame::Item;
            match item {
                Item::Account(x) => x.accept(visitor),
                Item::Recipient(x) => x.accept(visitor),
                Item::Chat(x) => x.accept(visitor),
                Item::ChatItem(x) => {
                    if x.expiresInMs.is_some() {
                        *item_field = None;
                        return;
                    }
                    x.accept(visitor)
                }
                Item::InstalledStickerPack(x) => x.accept(visitor),
                Item::HiddenStickerPack(x) => x.accept(visitor),
                Item::FavoriteStickerList(x) => x.accept(visitor),
                Item::AdHocCall(x) => x.accept(visitor),
                Item::NotificationProfile(x) => x.accept(visitor),
                Item::ChatFolder(x) => x.accept(visitor),
            }
        }
    }
}

impl Visit<Sanitizer> for proto::AccountData {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            profileKey,
            username: _,
            usernameLink,
            givenName: _,
            familyName: _,
            avatarUrlPath: _,
            donationSubscriberData,
            accountSettings,
            backupsSubscriberData,
            svrPin,
            androidSpecificSettings,
            bioText: _,
            bioEmoji: _,
            iosSpecificSettings,
            special_fields: _,
        } = self;

        usernameLink.accept(visitor);
        donationSubscriberData.accept(visitor);
        accountSettings.accept(visitor);
        backupsSubscriberData.accept(visitor);
        androidSpecificSettings.accept(visitor);
        iosSpecificSettings.accept(visitor);
        profileKey.clear();
        svrPin.clear();
    }
}

impl Visit<Sanitizer> for proto::account_data::UsernameLink {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            entropy,
            serverId: _,
            color: _,
            special_fields: _,
        } = self;

        entropy.clear();
    }
}

impl Visit<Sanitizer> for proto::account_data::AutoDownloadSettings {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            images: _,
            audio: _,
            video: _,
            documents: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::account_data::AccountSettings {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            readReceipts: _,
            sealedSenderIndicators: _,
            typingIndicators: _,
            linkPreviews: _,
            notDiscoverableByPhoneNumber: _,
            preferContactAvatars: _,
            universalExpireTimerSeconds: _,
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
            optimizeOnDeviceStorage: _,
            backupTier: _,
            defaultSentMediaQuality: _,
            autoDownloadSettings,
            screenLockTimeoutMinutes: _,
            pinReminders: _,
            appTheme: _,
            callsUseLessDataSetting: _,
            allowSealedSenderFromAnyone: _,
            allowAutomaticKeyVerification: _,
            hasSeenAdminDeleteEducationDialog: _,
            unreadBadgeType: _,
            includeMutedChatsInBadge: _,
            reactionNotifications: _,
            notifyForCallsIfMuted: _,
            notifyForMentionsIfMuted: _,
            notifyForRepliesIfMuted: _,
            showUnreadReminders: _,
            notifyWhenContactJoins: _,
            special_fields: _,
        } = self;

        defaultChatStyle.accept(visitor);
        customChatColors.accept(visitor);
        autoDownloadSettings.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::account_data::SubscriberData {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            subscriberId,
            currencyCode: _,
            manuallyCancelled: _,
            special_fields: _,
        } = self;

        subscriberId.clear();
    }
}

impl Visit<Sanitizer> for proto::account_data::IAPSubscriberData {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            subscriberId,
            iapSubscriptionId,
            special_fields: _,
        } = self;

        subscriberId.clear();
        if let Some(iap_subscription_id) = iapSubscriptionId {
            use proto::account_data::iapsubscriber_data::IapSubscriptionId;
            match iap_subscription_id {
                IapSubscriptionId::PurchaseToken(token) => token.clear(),
                IapSubscriptionId::OriginalTransactionId(id) => *id = 0,
            }
        }
    }
}

impl Visit<Sanitizer> for proto::account_data::AndroidSpecificSettings {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            useSystemEmoji: _,
            screenshotSecurity: _,
            navigationBarSize: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::account_data::IOSSpecificSettings {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            isSystemCallLogEnabled: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::Recipient {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            id: _,
            destination,
            special_fields: _,
        } = self;

        if let Some(destination) = destination {
            use proto::recipient::Destination;
            match destination {
                Destination::Contact(x) => x.accept(visitor),
                Destination::Group(x) => x.accept(visitor),
                Destination::DistributionList(x) => x.accept(visitor),
                Destination::Self_(x) => x.accept(visitor),
                Destination::ReleaseNotes(x) => x.accept(visitor),
                Destination::CallLink(x) => x.accept(visitor),
            }
        }
    }
}

impl Visit<Sanitizer> for proto::Contact {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            aci: _,
            pni: _,
            username: _,
            e164: _,
            blocked: _,
            visibility: _,
            registration,
            profileKey,
            profileSharing: _,
            profileGivenName: _,
            profileFamilyName: _,
            hideStory: _,
            identityKey: _,
            identityState: _,
            nickname,
            note: _,
            systemGivenName: _,
            systemFamilyName: _,
            systemNickname: _,
            avatarColor: _,
            keyTransparencyData: _,
            blockedAtTimestamp: _,
            sharedName,
            special_fields: _,
        } = self;

        if let Some(registration) = registration {
            use proto::contact::Registration;
            match registration {
                Registration::Registered(x) => x.accept(visitor),
                Registration::NotRegistered(x) => x.accept(visitor),
            }
        }
        nickname.accept(visitor);
        sharedName.accept(visitor);
        *profileKey = None;
    }
}

impl Visit<Sanitizer> for proto::contact::Registered {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Sanitizer> for proto::contact::NotRegistered {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            unregisteredTimestamp: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::contact::Name {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            given: _,
            family: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::Group {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            masterKey,
            whitelisted: _,
            hideStory: _,
            storySendMode: _,
            snapshot,
            blocked: _,
            avatarColor: _,
            blockedAtTimestamp: _,
            special_fields: _,
        } = self;

        snapshot.accept(visitor);
        masterKey.clear();
    }
}

impl Visit<Sanitizer> for proto::group::GroupSnapshot {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            title,
            description,
            avatarUrl: _,
            disappearingMessagesTimer,
            accessControl,
            version: _,
            members,
            membersPendingProfileKey,
            membersPendingAdminApproval,
            inviteLinkPassword,
            announcementsOnly: _,
            membersBanned,
            terminated: _,
            special_fields: _,
        } = self;

        title.accept(visitor);
        description.accept(visitor);
        disappearingMessagesTimer.accept(visitor);
        accessControl.accept(visitor);
        members.accept(visitor);
        membersPendingProfileKey.accept(visitor);
        membersPendingAdminApproval.accept(visitor);
        membersBanned.accept(visitor);
        inviteLinkPassword.clear();
    }
}

impl Visit<Sanitizer> for proto::group::GroupAttributeBlob {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            content: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::group::Member {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            userId: _,
            role: _,
            joinedAtVersion: _,
            labelEmoji: _,
            labelString: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::group::MemberPendingProfileKey {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            member,
            addedByUserId: _,
            timestamp: _,
            special_fields: _,
        } = self;

        member.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::group::MemberPendingAdminApproval {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            userId: _,
            timestamp: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::group::MemberBanned {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            userId: _,
            timestamp: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::group::AccessControl {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            attributes: _,
            members: _,
            addFromInviteLink: _,
            memberLabel: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::Self_ {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            avatarColor: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::ReleaseNotes {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Sanitizer> for proto::Chat {
    fn accept(&mut self, visitor: &mut Sanitizer) {
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
            notifyForCallsIfMuted: _,
            notifyForMentionsIfMuted: _,
            notifyForRepliesIfMuted: _,
            showUnreadReminders: _,
            special_fields: _,
        } = self;

        style.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::CallLink {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            rootKey,
            adminKey,
            name: _,
            restrictions: _,
            expirationMs: _,
            special_fields: _,
        } = self;

        rootKey.clear();
        *adminKey = None;
    }
}

impl Visit<Sanitizer> for proto::AdHocCall {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            callId: _,
            recipientId: _,
            state: _,
            callTimestamp: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::DistributionListItem {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            distributionId: _,
            item,
            special_fields: _,
        } = self;

        if let Some(item) = item {
            use proto::distribution_list_item::Item;
            match item {
                Item::DeletionTimestamp(_) => {}
                Item::DistributionList(x) => x.accept(visitor),
            }
        }
    }
}

impl Visit<Sanitizer> for proto::DistributionList {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            name: _,
            allowReplies: _,
            privacyMode: _,
            memberRecipientIds: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::ChatItem {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            chatId: _,
            authorId: _,
            dateSent: _,
            expireStartDate: _,
            // Disappearing chat items are dropped in the visitor for proto::Frame.
            expiresInMs: _,
            revisions,
            sms: _,
            directionalDetails,
            item,
            pinDetails,
            special_fields: _,
        } = self;

        revisions.retain(|item| item.expiresInMs.is_none());
        revisions.accept(visitor);

        if let Some(directional_details) = directionalDetails {
            use proto::chat_item::DirectionalDetails;
            match directional_details {
                DirectionalDetails::Incoming(x) => x.accept(visitor),
                DirectionalDetails::Outgoing(x) => x.accept(visitor),
                DirectionalDetails::Directionless(x) => x.accept(visitor),
            }
        }
        if let Some(item) = item {
            use proto::chat_item::Item;
            match item {
                Item::StandardMessage(x) => x.accept(visitor),
                Item::ContactMessage(x) => x.accept(visitor),
                Item::StickerMessage(x) => x.accept(visitor),
                Item::RemoteDeletedMessage(x) => x.accept(visitor),
                Item::UpdateMessage(x) => x.accept(visitor),
                Item::PaymentNotification(x) => x.accept(visitor),
                Item::GiftBadge(x) => x.accept(visitor),
                Item::ViewOnceMessage(x) => x.accept(visitor),
                Item::DirectStoryReplyMessage(x) => x.accept(visitor),
                Item::Poll(x) => x.accept(visitor),
                Item::AdminDeletedMessage(x) => x.accept(visitor),
            }
        }
        pinDetails.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::chat_item::IncomingMessageDetails {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            dateReceived: _,
            dateServerSent: _,
            read: _,
            sealedSender: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::chat_item::OutgoingMessageDetails {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            sendStatus,
            dateReceived: _,
            special_fields: _,
        } = self;

        sendStatus.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::chat_item::DirectionlessMessageDetails {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Sanitizer> for proto::chat_item::PinDetails {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            pinnedAtTimestamp: _,
            pinExpiry: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::SendStatus {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            recipientId: _,
            timestamp: _,
            deliveryStatus,
            special_fields: _,
        } = self;

        if let Some(delivery_status) = deliveryStatus {
            use proto::send_status::DeliveryStatus;
            match delivery_status {
                DeliveryStatus::Pending(x) => x.accept(visitor),
                DeliveryStatus::Sent(x) => x.accept(visitor),
                DeliveryStatus::Delivered(x) => x.accept(visitor),
                DeliveryStatus::Read(x) => x.accept(visitor),
                DeliveryStatus::Viewed(x) => x.accept(visitor),
                DeliveryStatus::Skipped(x) => x.accept(visitor),
                DeliveryStatus::Failed(x) => x.accept(visitor),
            }
        }
    }
}

impl Visit<Sanitizer> for proto::send_status::Pending {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Sanitizer> for proto::send_status::Sent {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            sealedSender: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::send_status::Delivered {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            sealedSender: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::send_status::Read {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            sealedSender: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::send_status::Viewed {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            sealedSender: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::send_status::Skipped {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Sanitizer> for proto::send_status::Failed {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            reason: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::Text {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            body: _,
            bodyRanges,
            special_fields: _,
        } = self;

        bodyRanges.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::StandardMessage {
    fn accept(&mut self, visitor: &mut Sanitizer) {
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

impl Visit<Sanitizer> for proto::ContactMessage {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            contact,
            reactions,
            special_fields: _,
        } = self;

        contact.accept(visitor);
        reactions.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::DirectStoryReplyMessage {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            reply,
            reactions,
            special_fields: _,
        } = self;

        if let Some(reply) = reply {
            use proto::direct_story_reply_message::Reply;
            match reply {
                Reply::TextReply(x) => x.accept(visitor),
                Reply::Emoji(_) => {}
            }
        }
        reactions.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::direct_story_reply_message::TextReply {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            text,
            longText,
            special_fields: _,
        } = self;

        text.accept(visitor);
        longText.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::PaymentNotification {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            amountMob: _,
            feeMob: _,
            note: _,
            transactionDetails,
            special_fields: _,
        } = self;

        transactionDetails.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::payment_notification::TransactionDetails {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            payment,
            special_fields: _,
        } = self;

        if let Some(payment) = payment {
            use proto::payment_notification::transaction_details::Payment;
            match payment {
                Payment::Transaction(x) => x.accept(visitor),
                Payment::FailedTransaction(x) => x.accept(visitor),
            }
        }
    }
}

impl Visit<Sanitizer>
    for proto::payment_notification::transaction_details::MobileCoinTxoIdentification
{
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            publicKey: _,
            keyImages: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::payment_notification::transaction_details::FailedTransaction {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            reason: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::payment_notification::transaction_details::Transaction {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            status: _,
            mobileCoinIdentification,
            timestamp: _,
            blockIndex: _,
            blockTimestamp: _,
            transaction,
            receipt,
            special_fields: _,
        } = self;

        mobileCoinIdentification.accept(visitor);
        *transaction = None;
        *receipt = None;
    }
}

impl Visit<Sanitizer> for proto::GiftBadge {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            receiptCredentialPresentation,
            state: _,
            special_fields: _,
        } = self;

        receiptCredentialPresentation.clear();
    }
}

impl Visit<Sanitizer> for proto::ViewOnceMessage {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            attachment,
            reactions,
            special_fields: _,
        } = self;

        attachment.clear();
        reactions.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::ContactAttachment {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            name,
            number,
            email,
            address,
            avatar,
            organization: _,
            aci: _,
            nickname,
            note: _,
            special_fields: _,
        } = self;

        name.accept(visitor);
        number.accept(visitor);
        email.accept(visitor);
        address.accept(visitor);
        avatar.accept(visitor);
        nickname.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::contact_attachment::Name {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            givenName: _,
            familyName: _,
            prefix: _,
            suffix: _,
            middleName: _,
            nickname: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::contact_attachment::SignalNickname {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            given: _,
            family: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::contact_attachment::Phone {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            value: _,
            type_: _,
            label: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::contact_attachment::Email {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            value: _,
            type_: _,
            label: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::contact_attachment::PostalAddress {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            type_: _,
            label: _,
            street: _,
            pobox: _,
            neighborhood: _,
            city: _,
            region: _,
            postcode: _,
            country: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::StickerMessage {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            sticker,
            reactions,
            special_fields: _,
        } = self;

        sticker.accept(visitor);
        reactions.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::RemoteDeletedMessage {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Sanitizer> for proto::Sticker {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            packId: _,
            packKey,
            stickerId: _,
            emoji: _,
            data,
            special_fields: _,
        } = self;

        data.accept(visitor);
        packKey.clear();
    }
}

impl Visit<Sanitizer> for proto::LinkPreview {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            url: _,
            title: _,
            image,
            description: _,
            date: _,
            special_fields: _,
        } = self;

        image.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::MessageAttachment {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            pointer,
            flag: _,
            wasDownloaded: _,
            clientUuid: _,
            special_fields: _,
        } = self;

        pointer.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::FilePointer {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            contentType: _,
            incrementalMac: _,
            incrementalMacChunkSize: _,
            fileName: _,
            width: _,
            height: _,
            caption: _,
            blurHash: _,
            locatorInfo,
            audioWaveform: _,
            audioDurationSeconds: _,
            special_fields: _,
        } = self;

        locatorInfo.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::file_pointer::LocatorInfo {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            key,
            integrityCheck: _,
            size: _,
            transitCdnKey: _,
            transitCdnNumber: _,
            transitTierUploadTimestamp: _,
            mediaTierCdnNumber: _,
            localKey,
            special_fields: _,
        } = self;

        key.clear();
        *localKey = None;
    }
}

impl Visit<Sanitizer> for proto::Quote {
    fn accept(&mut self, visitor: &mut Sanitizer) {
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

impl Visit<Sanitizer> for proto::quote::QuotedAttachment {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            contentType: _,
            fileName: _,
            thumbnail,
            special_fields: _,
        } = self;

        thumbnail.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::BodyRange {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            start: _,
            length: _,
            associatedValue: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::Reaction {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            emoji: _,
            authorId: _,
            sentTimestamp: _,
            sortOrder: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::Poll {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            question: _,
            allowMultiple: _,
            options,
            hasEnded: _,
            reactions,
            special_fields: _,
        } = self;

        options.accept(visitor);
        reactions.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::poll::PollOption {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            option: _,
            votes,
            special_fields: _,
        } = self;

        votes.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::poll::poll_option::PollVote {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            voterId: _,
            voteCount: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::AdminDeletedMessage {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            adminId: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::ChatUpdateMessage {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            update,
            special_fields: _,
        } = self;

        if let Some(update) = update {
            use proto::chat_update_message::Update;
            match update {
                Update::SimpleUpdate(x) => x.accept(visitor),
                Update::GroupChange(x) => x.accept(visitor),
                Update::ExpirationTimerChange(x) => x.accept(visitor),
                Update::ProfileChange(x) => x.accept(visitor),
                Update::ThreadMerge(x) => x.accept(visitor),
                Update::SessionSwitchover(x) => x.accept(visitor),
                Update::IndividualCall(x) => x.accept(visitor),
                Update::GroupCall(x) => x.accept(visitor),
                Update::LearnedProfileChange(x) => x.accept(visitor),
                Update::PollTerminate(x) => x.accept(visitor),
                Update::PinMessage(x) => x.accept(visitor),
            }
        }
    }
}

impl Visit<Sanitizer> for proto::IndividualCall {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
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

impl Visit<Sanitizer> for proto::GroupCall {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
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

impl Visit<Sanitizer> for proto::SimpleChatUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            type_: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::ExpirationTimerChatUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            expiresInMs: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::ProfileChangeChatUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            previousName: _,
            newName: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::LearnedProfileChatUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            previousName: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::ThreadMergeChatUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            previousE164: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::SessionSwitchoverChatUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            e164: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupChangeChatUpdate {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            updates,
            special_fields: _,
        } = self;

        updates.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::group_change_chat_update::Update {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            update,
            special_fields: _,
        } = self;

        if let Some(update) = update {
            use proto::group_change_chat_update::update::Update;
            match update {
                Update::GenericGroupUpdate(x) => x.accept(visitor),
                Update::GroupCreationUpdate(x) => x.accept(visitor),
                Update::GroupNameUpdate(x) => x.accept(visitor),
                Update::GroupAvatarUpdate(x) => x.accept(visitor),
                Update::GroupDescriptionUpdate(x) => x.accept(visitor),
                Update::GroupMembershipAccessLevelChangeUpdate(x) => x.accept(visitor),
                Update::GroupAttributesAccessLevelChangeUpdate(x) => x.accept(visitor),
                Update::GroupAnnouncementOnlyChangeUpdate(x) => x.accept(visitor),
                Update::GroupAdminStatusUpdate(x) => x.accept(visitor),
                Update::GroupMemberLeftUpdate(x) => x.accept(visitor),
                Update::GroupMemberRemovedUpdate(x) => x.accept(visitor),
                Update::SelfInvitedToGroupUpdate(x) => x.accept(visitor),
                Update::SelfInvitedOtherUserToGroupUpdate(x) => x.accept(visitor),
                Update::GroupUnknownInviteeUpdate(x) => x.accept(visitor),
                Update::GroupInvitationAcceptedUpdate(x) => x.accept(visitor),
                Update::GroupInvitationDeclinedUpdate(x) => x.accept(visitor),
                Update::GroupMemberJoinedUpdate(x) => x.accept(visitor),
                Update::GroupMemberAddedUpdate(x) => x.accept(visitor),
                Update::GroupSelfInvitationRevokedUpdate(x) => x.accept(visitor),
                Update::GroupInvitationRevokedUpdate(x) => x.accept(visitor),
                Update::GroupJoinRequestUpdate(x) => x.accept(visitor),
                Update::GroupJoinRequestApprovalUpdate(x) => x.accept(visitor),
                Update::GroupJoinRequestCanceledUpdate(x) => x.accept(visitor),
                Update::GroupInviteLinkResetUpdate(x) => x.accept(visitor),
                Update::GroupInviteLinkEnabledUpdate(x) => x.accept(visitor),
                Update::GroupInviteLinkAdminApprovalUpdate(x) => x.accept(visitor),
                Update::GroupInviteLinkDisabledUpdate(x) => x.accept(visitor),
                Update::GroupMemberJoinedByLinkUpdate(x) => x.accept(visitor),
                Update::GroupV2MigrationUpdate(x) => x.accept(visitor),
                Update::GroupV2MigrationSelfInvitedUpdate(x) => x.accept(visitor),
                Update::GroupV2MigrationInvitedMembersUpdate(x) => x.accept(visitor),
                Update::GroupV2MigrationDroppedMembersUpdate(x) => x.accept(visitor),
                Update::GroupSequenceOfRequestsAndCancelsUpdate(x) => x.accept(visitor),
                Update::GroupExpirationTimerUpdate(x) => x.accept(visitor),
                Update::GroupMemberLabelAccessLevelChangeUpdate(x) => x.accept(visitor),
                Update::GroupTerminateChangeUpdate(x) => x.accept(visitor),
            }
        }
    }
}

impl Visit<Sanitizer> for proto::GenericGroupUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupCreationUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupNameUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            newGroupName: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupAvatarUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            wasRemoved: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupDescriptionUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            newDescription: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupMembershipAccessLevelChangeUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            accessLevel: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupMemberLabelAccessLevelChangeUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            accessLevel: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupAttributesAccessLevelChangeUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            accessLevel: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupAnnouncementOnlyChangeUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            isAnnouncementOnly: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupAdminStatusUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            memberAci: _,
            wasAdminStatusGranted: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupMemberLeftUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            aci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupMemberRemovedUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            removerAci: _,
            removedAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::SelfInvitedToGroupUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            inviterAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::SelfInvitedOtherUserToGroupUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            inviteeServiceId: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupUnknownInviteeUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            inviterAci: _,
            inviteeCount: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupInvitationAcceptedUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            inviterAci: _,
            newMemberAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupInvitationDeclinedUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            inviterAci: _,
            inviteeAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupMemberJoinedUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            newMemberAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupMemberAddedUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            newMemberAci: _,
            hadOpenInvitation: _,
            inviterAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupSelfInvitationRevokedUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            revokerAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupInvitationRevokedUpdate {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            invitees,
            special_fields: _,
        } = self;

        invitees.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::group_invitation_revoked_update::Invitee {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            inviterAci: _,
            inviteeAci: _,
            inviteePni: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupJoinRequestUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            requestorAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupJoinRequestApprovalUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            requestorAci: _,
            updaterAci: _,
            wasApproved: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupJoinRequestCanceledUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            requestorAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupSequenceOfRequestsAndCancelsUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            requestorAci: _,
            count: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupInviteLinkResetUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupInviteLinkEnabledUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            linkRequiresAdminApproval: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupInviteLinkAdminApprovalUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            linkRequiresAdminApproval: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupInviteLinkDisabledUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupMemberJoinedByLinkUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            newMemberAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupV2MigrationUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupV2MigrationSelfInvitedUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupV2MigrationInvitedMembersUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            invitedMembersCount: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupV2MigrationDroppedMembersUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            droppedMembersCount: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupExpirationTimerUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            expiresInMs: _,
            updaterAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::GroupTerminateChangeUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            updaterAci: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::PollTerminateUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            targetSentTimestamp: _,
            question: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::PinMessageUpdate {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            targetSentTimestamp: _,
            authorId: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::StickerPack {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            packId: _,
            packKey,
            special_fields: _,
        } = self;

        packKey.clear();
    }
}

impl Visit<Sanitizer> for proto::FavoriteStickerList {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            favoriteSticker,
            special_fields: _,
        } = self;

        favoriteSticker.accept(visitor);
    }
}

impl Visit<Sanitizer> for proto::favorite_sticker_list::FavoriteSticker {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            packId: _,
            packKey,
            stickerId: _,
            favoritedAtTimestamp: _,
            special_fields: _,
        } = self;

        packKey.clear();
    }
}

impl Visit<Sanitizer> for proto::ChatStyle {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            wallpaper,
            bubbleColor,
            dimWallpaperInDarkMode: _,
            special_fields: _,
        } = self;

        if let Some(wallpaper) = wallpaper {
            use proto::chat_style::Wallpaper;
            match wallpaper {
                Wallpaper::WallpaperPreset(_) => {}
                Wallpaper::WallpaperPhoto(x) => x.accept(visitor),
            }
        }
        if let Some(bubble_color) = bubbleColor {
            use proto::chat_style::BubbleColor;
            match bubble_color {
                BubbleColor::AutoBubbleColor(x) => x.accept(visitor),
                BubbleColor::BubbleColorPreset(_) => {}
                BubbleColor::CustomColorId(_) => {}
            }
        }
    }
}

impl Visit<Sanitizer> for proto::chat_style::Gradient {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            angle: _,
            colors: _,
            positions: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::chat_style::CustomChatColor {
    fn accept(&mut self, visitor: &mut Sanitizer) {
        let Self {
            id: _,
            color,
            special_fields: _,
        } = self;

        if let Some(color) = color {
            use proto::chat_style::custom_chat_color::Color;
            match color {
                Color::Solid(_) => {}
                Color::Gradient(x) => x.accept(visitor),
            }
        }
    }
}

impl Visit<Sanitizer> for proto::chat_style::AutomaticBubbleColor {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self { special_fields: _ } = self;
    }
}

impl Visit<Sanitizer> for proto::NotificationProfile {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            name: _,
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
            id: _,
            special_fields: _,
        } = self;
    }
}

impl Visit<Sanitizer> for proto::ChatFolder {
    fn accept(&mut self, _visitor: &mut Sanitizer) {
        let Self {
            name: _,
            showOnlyUnread: _,
            showMutedChats: _,
            includeAllIndividualChats: _,
            includeAllGroupChats: _,
            folderType: _,
            includedRecipientIds: _,
            excludedRecipientIds: _,
            id: _,
            special_fields: _,
        } = self;
    }
}
