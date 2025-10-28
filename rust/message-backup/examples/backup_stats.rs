//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::ready;

use clap::Parser;
use clap_stdin::FileOrStdin;
use futures::future::Either;
use futures::io::Cursor;
use libsignal_cli_utils::read_file;
use libsignal_message_backup::frame::{FramesReader, LimitedReaderFactory};
use libsignal_message_backup::parse::VarintDelimitedReader;

#[path = "../src/bin/support/mod.rs"]
mod support;
use libsignal_message_backup::proto;
use protobuf::Message;
use support::KeyArgs;

#[derive(Parser)]
/// Prints TSV stats about the frames in a backup file.
///
/// If no key is provided, the file is assumed to be unencrypted; this is usually not what you want!
struct CliArgs {
    /// the file to read from, or '-' to read from stdin
    input: FileOrStdin,

    #[command(flatten)]
    key_args: KeyArgs,
}

/// A [`Cursor`] that additionally reports its position to a shared atomic.
struct TrackingCursor<T> {
    inner: Cursor<T>,
    pos: Arc<AtomicU64>,
}

impl<T: AsRef<[u8]> + Unpin> futures::io::AsyncRead for TrackingCursor<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let count = ready!(std::pin::Pin::new(&mut self.inner).poll_read(cx, buf))?;
        self.pos
            .fetch_add(count.try_into().unwrap(), Ordering::SeqCst);
        std::task::Poll::Ready(Ok(count))
    }
}

impl<T: AsRef<[u8]> + Unpin> mediasan_common::AsyncSkip for TrackingCursor<T> {
    fn poll_skip(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        amount: u64,
    ) -> std::task::Poll<std::io::Result<()>> {
        ready!(std::pin::Pin::new(&mut self.inner).poll_skip(cx, amount))?;
        self.pos.fetch_add(amount, Ordering::SeqCst);
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_stream_position(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<u64>> {
        std::pin::Pin::new(&mut self.inner).poll_stream_position(cx)
    }

    fn poll_stream_len(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<u64>> {
        std::pin::Pin::new(&mut self.inner).poll_stream_len(cx)
    }
}

fn print_row(label: &str, count: u64, compressed_size: u64, raw_size: u64) {
    println!("{label}\t{count}\t{compressed_size}\t{raw_size}");
}

fn main() {
    let CliArgs { input, key_args } = CliArgs::parse();

    let key = key_args.into_key();

    eprintln!("reading from {:?}", input.filename());

    let contents = read_file(input);
    eprintln!("read {} bytes", contents.len());

    println!("frame\tcount\tcomp_size\traw_size");

    futures::executor::block_on(async {
        let position = Arc::<AtomicU64>::default();

        let reader = if let Some(key) = key {
            Either::Left(
                FramesReader::new(
                    &key,
                    LimitedReaderFactory::new([
                        // FramesReader consumes the first reader to validate the HMAC...
                        TrackingCursor {
                            inner: Cursor::new(&contents),
                            pos: Default::default(),
                        },
                        // ...then uses the second reader for the actual file contents.
                        TrackingCursor {
                            inner: Cursor::new(&contents),
                            pos: position.clone(),
                        },
                    ]),
                )
                .await
                .expect("valid HMAC"),
            )
        } else {
            Either::Right(TrackingCursor {
                inner: Cursor::new(&contents),
                pos: position.clone(),
            })
        };

        let mut reader = VarintDelimitedReader::new(reader);

        let start = position.load(Ordering::SeqCst);
        print_row("header", 1, start, start);

        let backup_info = reader
            .read_next()
            .await
            .expect("can read")
            .expect("not empty");
        let mut pos = position.load(Ordering::SeqCst);
        print_row(
            "BackupInfo",
            1,
            pos - start,
            backup_info.len().try_into().unwrap(),
        );

        let mut stats: HashMap<&'static str, (u64, u64, u64)> = HashMap::new();
        while let Some(frame) = reader.read_next().await.expect("can read") {
            let frame_end = position.load(Ordering::SeqCst);
            let frame_proto = proto::backup::Frame::parse_from_bytes(&frame).expect("valid proto");
            let key = match frame_proto.item.expect("not empty") {
                proto::backup::frame::Item::ChatItem(ci) => match ci.item.expect("not empty") {
                    proto::backup::chat_item::Item::StandardMessage(_) => {
                        "ChatItem.StandardMessage"
                    }
                    proto::backup::chat_item::Item::ContactMessage(_) => "ChatItem.ContactMessage",
                    proto::backup::chat_item::Item::StickerMessage(_) => "ChatItem.StickerMessage",
                    proto::backup::chat_item::Item::RemoteDeletedMessage(_) => {
                        "ChatItem.RemoteDeletedMessage"
                    }
                    proto::backup::chat_item::Item::UpdateMessage(_) => "ChatItem.UpdateMessage",
                    proto::backup::chat_item::Item::PaymentNotification(_) => {
                        "ChatItem.PaymentNotification"
                    }
                    proto::backup::chat_item::Item::GiftBadge(_) => "ChatItem.GiftBadge",
                    proto::backup::chat_item::Item::ViewOnceMessage(_) => {
                        "ChatItem.ViewOnceMessage"
                    }
                    proto::backup::chat_item::Item::DirectStoryReplyMessage(_) => {
                        "ChatItem.DirectStoryReplyMessage"
                    }
                    proto::backup::chat_item::Item::Poll(_) => "ChatItem.Poll",
                    _ => "ChatItem.unknown",
                },
                proto::backup::frame::Item::Recipient(r) => {
                    match r.destination.expect("not empty") {
                        proto::backup::recipient::Destination::Contact(_) => "Recipient.Contact",
                        proto::backup::recipient::Destination::Group(_) => "Recipient.Group",
                        proto::backup::recipient::Destination::DistributionList(_) => {
                            "Recipient.DistributionList"
                        }
                        proto::backup::recipient::Destination::Self_(_) => "Recipient.Self",
                        proto::backup::recipient::Destination::ReleaseNotes(_) => {
                            "Recipient.ReleaseNotes"
                        }
                        proto::backup::recipient::Destination::CallLink(_) => "Recipient.CallLink",
                        _ => "Recipient.unknown",
                    }
                }
                proto::backup::frame::Item::Account(_) => "Account",
                proto::backup::frame::Item::Chat(_) => "Chat",
                proto::backup::frame::Item::StickerPack(_) => "StickerPack",
                proto::backup::frame::Item::AdHocCall(_) => "AdHocCall",
                proto::backup::frame::Item::NotificationProfile(_) => "NotificationProfile",
                proto::backup::frame::Item::ChatFolder(_) => "ChatFolder",
                _ => "Unknown",
            };
            let (count, compressed_size, raw_size) = stats.entry(key).or_default();
            *count += 1;
            *compressed_size += frame_end - pos;
            *raw_size += u64::try_from(frame.len()).unwrap();
            pos = frame_end;
        }

        // This won't print the frames in the same order every time, but that's fine; the consumer
        // will almost certainly want to sort them anyway.
        for (k, (c, csz, rsz)) in stats {
            print_row(k, c, csz, rsz);
        }

        print_row(
            "padding",
            1,
            u64::try_from(contents.len()).unwrap() - pos,
            0,
        );
    });
}
