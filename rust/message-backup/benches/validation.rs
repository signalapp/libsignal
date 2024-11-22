//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use futures::io::{BufReader, Cursor};
use futures::AsyncRead;
use libsignal_account_keys::BackupKey;
use libsignal_core::Aci;
use libsignal_message_backup::backup::{CompletedBackup, PartialBackup, ValidateOnly};
use libsignal_message_backup::frame::{
    Aes256CbcReader, CursorFactory, FramesReader, MacReader, ReaderFactory, AES_IV_SIZE,
    AES_KEY_SIZE,
};
use libsignal_message_backup::key::MessageBackupKey;
use libsignal_message_backup::parse::VarintDelimitedReader;
use libsignal_message_backup::BackupReader;
use mediasan_common::AsyncSkip;
use protobuf::Message as _;
use sha2::Digest as _;

mod generation;
use generation::*;

const DEFAULT_ACI: Aci = Aci::from_uuid_bytes([0x11; 16]);
const DEFAULT_ACCOUNT_ENTROPY: &str =
    "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";

const NUMBER_OF_CONVERSATIONS: usize = 100;
const NUMBER_OF_MESSAGES: usize = 20_000;

/// An [`AsyncRead`] implementation that [yields][] for every callback.
///
/// Meant to be used with [`Cursor`] or similar to more closely approximate the best case of reading
/// from a file.
///
/// [yields]: std::thread::yield_now
struct YieldingReader<R>(R);

/// This could be done without Unpin, but we don't need to support that right now.
impl<R: AsyncRead + Unpin> AsyncRead for YieldingReader<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::thread::yield_now();
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

/// This could be done without Unpin, but we don't need to support that right now.
impl<R: AsyncSkip + Unpin> AsyncSkip for YieldingReader<R> {
    fn poll_skip(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        amount: u64,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::thread::yield_now();
        std::pin::Pin::new(&mut self.get_mut().0).poll_skip(cx, amount)
    }

    fn poll_stream_position(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<u64>> {
        // No yield for this, consider it internal state.
        std::pin::Pin::new(&mut self.get_mut().0).poll_stream_position(cx)
    }

    fn poll_stream_len(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<u64>> {
        // No yield for this, consider it internal state.
        std::pin::Pin::new(&mut self.get_mut().0).poll_stream_len(cx)
    }
}

impl<'a, B: AsRef<[u8]> + ?Sized> ReaderFactory for YieldingReader<CursorFactory<&'a B>> {
    type Reader = YieldingReader<Cursor<&'a B>>;

    fn make_reader(&mut self) -> futures::io::Result<Self::Reader> {
        Ok(YieldingReader(self.0.make_reader()?))
    }
}

fn cursor_without_appended_hash(backup: &[u8]) -> Cursor<&'_ [u8]> {
    Cursor::new(&backup[..backup.len() - sha2::Sha256::output_size()])
}

fn hmac_only(c: &mut Criterion) {
    let backup = generate_backup(NUMBER_OF_CONVERSATIONS, NUMBER_OF_MESSAGES);

    let backup_key =
        BackupKey::derive_from_account_entropy_pool(&DEFAULT_ACCOUNT_ENTROPY.parse().unwrap());
    let message_backup_key =
        MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&DEFAULT_ACI));

    fn process<R: AsyncRead + Unpin>(input: R, hmac_key: &[u8]) {
        let reader = MacReader::new_sha256(input, hmac_key);
        futures::executor::block_on(futures::io::copy(reader, &mut futures::io::sink()))
            .expect("success");
    }

    c.benchmark_group("MacReader")
        .bench_function("direct", |b| {
            b.iter(|| {
                process(
                    cursor_without_appended_hash(&backup),
                    &message_backup_key.hmac_key,
                )
            })
        })
        .bench_function("YieldingReader", |b| {
            b.iter(|| {
                process(
                    YieldingReader(cursor_without_appended_hash(&backup)),
                    &message_backup_key.hmac_key,
                )
            })
        });
}

fn decrypt_only(c: &mut Criterion) {
    let backup = generate_backup(NUMBER_OF_CONVERSATIONS, NUMBER_OF_MESSAGES);
    let iv = &backup[..AES_IV_SIZE].try_into().unwrap();

    let backup_key =
        BackupKey::derive_from_account_entropy_pool(&DEFAULT_ACCOUNT_ENTROPY.parse().unwrap());
    let message_backup_key =
        MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&DEFAULT_ACI));

    fn process<R: AsyncRead + Unpin>(
        input: R,
        aes_key: &[u8; AES_KEY_SIZE],
        iv: &[u8; AES_IV_SIZE],
    ) {
        let reader = Aes256CbcReader::new(aes_key, iv, input);
        futures::executor::block_on(futures::io::copy(reader, &mut futures::io::sink()))
            .expect("success");
    }

    c.benchmark_group("Aes256CbcReader")
        .bench_function("direct", |b| {
            b.iter(|| {
                process(
                    cursor_without_appended_hash(&backup),
                    &message_backup_key.aes_key,
                    iv,
                )
            })
        })
        .bench_function("YieldingReader", |b| {
            b.iter(|| {
                process(
                    YieldingReader(cursor_without_appended_hash(&backup)),
                    &message_backup_key.aes_key,
                    iv,
                )
            })
        });
}

fn decrypt_and_decompress_and_hmac(c: &mut Criterion) {
    let backup = generate_backup(NUMBER_OF_CONVERSATIONS, NUMBER_OF_MESSAGES);

    let backup_key =
        BackupKey::derive_from_account_entropy_pool(&DEFAULT_ACCOUNT_ENTROPY.parse().unwrap());
    let message_backup_key =
        MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&DEFAULT_ACI));

    fn process<R: ReaderFactory>(input: R, key: &MessageBackupKey)
    where
        R::Reader: Unpin,
    {
        futures::executor::block_on(async {
            let reader = FramesReader::new(key, input).await.expect("success");
            futures::io::copy(reader, &mut futures::io::sink())
                .await
                .expect("success");
        })
    }

    c.benchmark_group("FramesReader")
        .bench_function("direct", |b| {
            b.iter(|| process(CursorFactory::new(&backup), &message_backup_key))
        })
        .bench_function("YieldingReader", |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(&backup)),
                    &message_backup_key,
                )
            })
        });
}

fn decrypt_and_decompress_and_hmac_and_segment(c: &mut Criterion) {
    let backup = generate_backup(NUMBER_OF_CONVERSATIONS, NUMBER_OF_MESSAGES);

    let backup_key =
        BackupKey::derive_from_account_entropy_pool(&DEFAULT_ACCOUNT_ENTROPY.parse().unwrap());
    let message_backup_key =
        MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&DEFAULT_ACI));

    fn process<R: ReaderFactory, R2: AsyncRead + Unpin>(
        input: R,
        key: &MessageBackupKey,
        transform: impl FnOnce(FramesReader<R::Reader>) -> R2,
    ) where
        R::Reader: Unpin,
    {
        futures::executor::block_on(async move {
            let reader = FramesReader::new(key, input).await.expect("success");
            let mut stream = VarintDelimitedReader::new(transform(reader));
            while let Some(next) = stream.read_next().await.expect("valid") {
                black_box(next);
            }
        })
    }

    c.benchmark_group("FramesReader + VarintDelimitedReader")
        .bench_function("direct", |b| {
            b.iter(|| process(CursorFactory::new(&backup), &message_backup_key, |r| r))
        })
        .bench_function("direct + BufReader", |b| {
            b.iter(|| {
                process(
                    CursorFactory::new(&backup),
                    &message_backup_key,
                    BufReader::new,
                )
            })
        })
        .bench_function("YieldingReader", |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(&backup)),
                    &message_backup_key,
                    |r| r,
                )
            })
        })
        .bench_function("YieldingReader + BufReader", |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(&backup)),
                    &message_backup_key,
                    BufReader::new,
                )
            })
        });
}

fn decrypt_and_decompress_and_hmac_and_segment_and_parse(c: &mut Criterion) {
    let backup = generate_backup(NUMBER_OF_CONVERSATIONS, NUMBER_OF_MESSAGES);

    let backup_key =
        BackupKey::derive_from_account_entropy_pool(&DEFAULT_ACCOUNT_ENTROPY.parse().unwrap());
    let message_backup_key =
        MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&DEFAULT_ACI));

    fn process<R: ReaderFactory, R2: AsyncRead + Unpin>(
        input: R,
        key: &MessageBackupKey,
        transform: impl FnOnce(FramesReader<R::Reader>) -> R2,
    ) where
        R::Reader: Unpin,
    {
        futures::executor::block_on(async move {
            let reader = FramesReader::new(key, input).await.expect("success");
            let mut stream = VarintDelimitedReader::new(transform(reader));
            // Throw away the BackupInfo message.
            _ = stream
                .read_next()
                .await
                .expect("valid")
                .expect("contains BackupInfo message");
            while let Some(next) = stream.read_next().await.expect("valid") {
                black_box(
                    libsignal_message_backup::proto::backup::Frame::parse_from_bytes(&next)
                        .expect("valid"),
                );
            }
        })
    }

    c.benchmark_group("FramesReader + VarintDelimitedReader + Frame::parse")
        .bench_function("direct", |b| {
            b.iter(|| process(CursorFactory::new(&backup), &message_backup_key, |r| r))
        })
        .bench_function("direct + BufReader", |b| {
            b.iter(|| {
                process(
                    CursorFactory::new(&backup),
                    &message_backup_key,
                    BufReader::new,
                )
            })
        })
        .bench_function("YieldingReader", |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(&backup)),
                    &message_backup_key,
                    |r| r,
                )
            })
        })
        .bench_function("YieldingReader + BufReader", |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(&backup)),
                    &message_backup_key,
                    BufReader::new,
                )
            })
        });
}

fn decrypt_and_decompress_and_hmac_and_segment_and_parse_and_validate(c: &mut Criterion) {
    let backup = generate_backup(NUMBER_OF_CONVERSATIONS, NUMBER_OF_MESSAGES);

    let backup_key =
        BackupKey::derive_from_account_entropy_pool(&DEFAULT_ACCOUNT_ENTROPY.parse().unwrap());
    let message_backup_key =
        MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&DEFAULT_ACI));

    fn process<R: ReaderFactory, R2: AsyncRead + Unpin>(
        input: R,
        key: &MessageBackupKey,
        transform: impl FnOnce(FramesReader<R::Reader>) -> R2,
    ) where
        R::Reader: Unpin,
    {
        futures::executor::block_on(async move {
            let reader = FramesReader::new(key, input).await.expect("success");
            let mut stream = VarintDelimitedReader::new(transform(reader));
            let backup_info = stream
                .read_next()
                .await
                .expect("valid")
                .expect("contains BackupInfo message");
            let mut backup = PartialBackup::<ValidateOnly>::by_parsing(
                &backup_info,
                libsignal_message_backup::backup::Purpose::RemoteBackup,
                |_| (),
            )
            .expect("valid");
            while let Some(next) = stream.read_next().await.expect("valid") {
                backup.parse_and_add_frame(&next, |_| ()).expect("valid");
            }
            _ = CompletedBackup::try_from(backup).expect("valid");
        })
    }

    c.benchmark_group("FramesReader + VarintDelimitedReader + PartialBackup")
        .bench_function("direct", |b| {
            b.iter(|| process(CursorFactory::new(&backup), &message_backup_key, |r| r))
        })
        .bench_function("direct + BufReader", |b| {
            b.iter(|| {
                process(
                    CursorFactory::new(&backup),
                    &message_backup_key,
                    BufReader::new,
                )
            })
        })
        .bench_function("YieldingReader", |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(&backup)),
                    &message_backup_key,
                    |r| r,
                )
            })
        })
        .bench_function("YieldingReader + BufReader", |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(&backup)),
                    &message_backup_key,
                    BufReader::new,
                )
            })
        });
}

fn validate_using_full_backup_reader(c: &mut Criterion) {
    let backup = generate_backup(NUMBER_OF_CONVERSATIONS, NUMBER_OF_MESSAGES);

    let backup_key =
        BackupKey::derive_from_account_entropy_pool(&DEFAULT_ACCOUNT_ENTROPY.parse().unwrap());
    let message_backup_key =
        MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&DEFAULT_ACI));

    fn process<R: ReaderFactory>(input: R, key: &MessageBackupKey)
    where
        R::Reader: Unpin,
    {
        futures::executor::block_on(async {
            BackupReader::new_encrypted_compressed(
                key,
                input,
                libsignal_message_backup::backup::Purpose::RemoteBackup,
            )
            .await
            .expect("valid")
            .validate_all()
            .await
            .result
            .expect("valid");
        })
    }

    c.benchmark_group("BackupReader")
        .bench_function("direct", |b| {
            b.iter(|| process(CursorFactory::new(&backup), &message_backup_key))
        })
        .bench_function("YieldingReader", |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(&backup)),
                    &message_backup_key,
                )
            })
        });
}

criterion_group!(
    validation,
    hmac_only,
    decrypt_only,
    decrypt_and_decompress_and_hmac,
    decrypt_and_decompress_and_hmac_and_segment,
    decrypt_and_decompress_and_hmac_and_segment_and_parse,
    decrypt_and_decompress_and_hmac_and_segment_and_parse_and_validate,
    validate_using_full_backup_reader,
);
criterion_main!(validation);
