//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use futures::{StreamExt as _, TryStreamExt as _};
use libsignal_message_backup::export::{
    aes_cbc_encrypt, gzip_compress, hmac_checksum, pad_gzipped_bucketed,
};
use libsignal_message_backup::key::MessageBackupKey;
use libsignal_message_backup::proto::backup as proto;
use protobuf::Message as _;
use rand::rngs::OsRng;
use rand::RngCore as _;

/// Generates a compressed, encrypted, MAC'd backup with the given settings.
///
/// The backup is not very realistic, just `number_of_conversations` 1:1 conversations and
/// `number_of_messages` total messages in those conversations.
pub fn generate_backup(
    number_of_conversations: usize,
    number_of_messages: usize,
    message_backup_key: &MessageBackupKey,
) -> Vec<u8> {
    let iv = {
        let mut iv = [0; 16];
        OsRng.fill_bytes(&mut iv);
        iv
    };

    let uncompressed = generate_backup_contents(number_of_conversations, number_of_messages);

    let mut compressed_contents = gzip_compress(futures::io::BufReader::new(uncompressed));
    pad_gzipped_bucketed(&mut compressed_contents);
    aes_cbc_encrypt(&message_backup_key.aes_key, &iv, &mut compressed_contents);
    let hmac = hmac_checksum(&message_backup_key.hmac_key, &iv, &compressed_contents);
    compressed_contents.splice(0..0, iv);
    compressed_contents.extend(hmac);

    compressed_contents
}

fn generate_backup_contents(
    number_of_conversations: usize,
    number_of_messages: usize,
) -> impl futures::AsyncRead {
    let backup_info = futures::stream::once(std::future::ready(
        generate_backup_info()
            .write_length_delimited_to_bytes()
            .unwrap(),
    ));

    backup_info
        .chain(futures::stream::iter(
            generate_frames(number_of_conversations, number_of_messages)
                .map(|frame| frame.write_length_delimited_to_bytes().unwrap()),
        ))
        .map(Ok)
        .into_async_read()
}

pub fn generate_backup_info() -> proto::BackupInfo {
    proto::BackupInfo {
        version: 1,
        backupTimeMs: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap(),
        mediaRootBackupKey: vec![0; 32],
        ..Default::default()
    }
}

pub fn generate_frames(
    number_of_conversations: usize,
    number_of_messages: usize,
) -> impl Iterator<Item = proto::Frame> {
    let number_of_conversations = u64::try_from(number_of_conversations).unwrap();
    let number_of_messages = u64::try_from(number_of_messages).unwrap();

    fn frame(item: impl Into<proto::frame::Item>) -> proto::Frame {
        proto::Frame {
            item: Some(item.into()),
            ..Default::default()
        }
    }

    // Based on Desktop's similar test defaults,
    // https://github.com/signalapp/Signal-Desktop/blob/0bc6368c642a7ddf2456e994db1016034380f72d/ts/test-both/helpers/generateBackup.ts#L105
    let account_data = frame(proto::AccountData {
        profileKey: vec![1; 32],
        givenName: "Backup".into(),
        familyName: "Benchmark".into(),
        accountSettings: Some(proto::account_data::AccountSettings {
            displayBadgesOnProfile: true,
            hasSetMyStoriesPrivacy: true,
            hasSeenGroupStoryEducationSheet: true,
            hasCompletedUsernameOnboarding: true,
            phoneNumberSharingMode: proto::account_data::PhoneNumberSharingMode::EVERYBODY.into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    });

    let self_id = number_of_conversations + 1;
    let self_recipient = frame(proto::Recipient {
        id: self_id,
        destination: Some(proto::recipient::Destination::Self_(Default::default())),
        ..Default::default()
    });

    let recipient_frames = (1..=number_of_conversations).map(|id| {
        frame(proto::Recipient {
            id,
            destination: Some(
                proto::Contact {
                    aci: Some(uuid::Uuid::new_v4().into_bytes().into()),
                    visibility: proto::contact::Visibility::VISIBLE.into(),
                    profileKey: Some(vec![2; 32]),
                    profileSharing: true,
                    profileGivenName: Some(format!("Contact {id}")),
                    profileFamilyName: Some("Generated".into()),
                    registration: Some(
                        proto::contact::Registration::Registered(Default::default()),
                    ),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        })
    });

    let chat_frames = (1..=number_of_conversations).map(|id| {
        frame(proto::Chat {
            id,
            recipientId: id,
            expireTimerVersion: 1,
            ..Default::default()
        })
    });

    const START_OF_2024_IN_MILLIS: u64 = 1704067200000; // 2024-01-01T00:00:00Z
    let message_frames = (1..=number_of_messages).map(move |i| {
        let chat_id = i % number_of_conversations + 1; // skip the Self recipient
        let date_sent = START_OF_2024_IN_MILLIS + i * 1000;

        let is_incoming = (i % 2) == 0;
        let directional_details: proto::chat_item::DirectionalDetails = if is_incoming {
            proto::chat_item::IncomingMessageDetails {
                dateReceived: date_sent,
                dateServerSent: Some(date_sent),
                read: true,
                sealedSender: true,
                ..Default::default()
            }
            .into()
        } else {
            proto::chat_item::OutgoingMessageDetails {
                sendStatus: vec![proto::SendStatus {
                    recipientId: chat_id,
                    timestamp: date_sent,
                    deliveryStatus: Some(proto::send_status::DeliveryStatus::Delivered(
                        proto::send_status::Delivered {
                            sealedSender: true,
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .into()
        };

        let is_long_message = (i % 11) == 0;
        let body = if is_long_message {
            format!("A longer message ({i})\n").repeat(20)
        } else {
            format!("Message {i}")
        };

        frame(proto::ChatItem {
            chatId: chat_id,
            authorId: if is_incoming { chat_id } else { self_id },
            dateSent: date_sent,
            item: Some(
                proto::StandardMessage {
                    text: Some(proto::Text {
                        body,
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                }
                .into(),
            ),
            directionalDetails: Some(directional_details),
            ..Default::default()
        })
    });

    [account_data, self_recipient]
        .into_iter()
        .chain(recipient_frames)
        .chain(chat_frames)
        .chain(message_frames)
}
