//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Benchmarks for the various steps of validating a backup.
//!
//! By default, the benchmarks are run on synthetic input (see the `generation` module), but most
//! (but not all) of them can be run on an externally-provided backup file as well. See the
//! `LIBSIGNAL_TESTING`-prefixed environment variables below.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
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

const CUSTOM_BACKUP_FILE_ENV_VAR: &str = "LIBSIGNAL_TESTING_BACKUP_FILE";
const CUSTOM_BACKUP_FILE_HMAC_KEY_ENV_VAR: &str = "LIBSIGNAL_TESTING_BACKUP_FILE_HMAC_KEY";
const CUSTOM_BACKUP_FILE_AES_KEY_ENV_VAR: &str = "LIBSIGNAL_TESTING_BACKUP_FILE_AES_KEY";

const DEFAULT_ACI: Aci = Aci::from_uuid_bytes([0x11; 16]);
const DEFAULT_ACCOUNT_ENTROPY: &str =
    "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
const MESSAGES_PER_CONVERSATION: usize = 200;

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

fn benchmark_multiple_backup_sizes(mut body: impl FnMut(usize, &[u8], &MessageBackupKey)) {
    if let Some(backup_file) = std::env::var_os(CUSTOM_BACKUP_FILE_ENV_VAR) {
        let mut message_backup_key = MessageBackupKey {
            hmac_key: [0; 32],
            aes_key: [0; AES_KEY_SIZE],
        };
        hex::decode_to_slice(
            std::env::var(CUSTOM_BACKUP_FILE_HMAC_KEY_ENV_VAR).expect("HMAC key provided"),
            &mut message_backup_key.hmac_key,
        )
        .expect("valid HMAC key");
        hex::decode_to_slice(
            std::env::var(CUSTOM_BACKUP_FILE_AES_KEY_ENV_VAR).expect("AES key provided"),
            &mut message_backup_key.aes_key,
        )
        .expect("valid AES key");

        let contents = std::fs::read(backup_file).expect("can read backup file");
        body(0, &contents, &message_backup_key);
        return;
    }

    let backup_key =
        BackupKey::derive_from_account_entropy_pool(&DEFAULT_ACCOUNT_ENTROPY.parse().unwrap());
    let message_backup_key =
        MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&DEFAULT_ACI));

    for size in [30, 100, 300] {
        let backup = generate_backup(size, MESSAGES_PER_CONVERSATION * size, &message_backup_key);
        body(size, &backup, &message_backup_key);
    }
}

fn hmac_only(c: &mut Criterion) {
    fn process<R: AsyncRead + Unpin>(input: R, hmac_key: &[u8]) {
        let reader = MacReader::new_sha256(input, hmac_key);
        futures::executor::block_on(futures::io::copy(reader, &mut futures::io::sink()))
            .expect("success");
    }

    let mut group = c.benchmark_group("MacReader");
    benchmark_multiple_backup_sizes(|size, backup, message_backup_key| {
        group.bench_function(BenchmarkId::new("direct", size), |b| {
            b.iter(|| {
                process(
                    cursor_without_appended_hash(backup),
                    &message_backup_key.hmac_key,
                )
            })
        });

        group.bench_function(BenchmarkId::new("YieldingReader", size), |b| {
            b.iter(|| {
                process(
                    YieldingReader(cursor_without_appended_hash(backup)),
                    &message_backup_key.hmac_key,
                )
            })
        });
    });
}

fn decrypt_only(c: &mut Criterion) {
    fn process<R: AsyncRead + Unpin>(
        input: R,
        aes_key: &[u8; AES_KEY_SIZE],
        iv: &[u8; AES_IV_SIZE],
    ) {
        let reader = Aes256CbcReader::new(aes_key, iv, input);
        futures::executor::block_on(futures::io::copy(reader, &mut futures::io::sink()))
            .expect("success");
    }

    let mut group = c.benchmark_group("Aes256CbcReader");
    benchmark_multiple_backup_sizes(|size, backup, message_backup_key| {
        let iv = backup[..AES_IV_SIZE].try_into().unwrap();

        group.bench_function(BenchmarkId::new("direct", size), |b| {
            b.iter(|| {
                process(
                    cursor_without_appended_hash(backup),
                    &message_backup_key.aes_key,
                    &iv,
                )
            })
        });
        group.bench_function(BenchmarkId::new("YieldingReader", size), |b| {
            b.iter(|| {
                process(
                    YieldingReader(cursor_without_appended_hash(backup)),
                    &message_backup_key.aes_key,
                    &iv,
                )
            })
        });
    });
}

fn decrypt_and_decompress_and_hmac(c: &mut Criterion) {
    fn process<R: ReaderFactory<Reader: Unpin>>(input: R, key: &MessageBackupKey) {
        futures::executor::block_on(async {
            let reader = FramesReader::new(key, input).await.expect("success");
            futures::io::copy(reader, &mut futures::io::sink())
                .await
                .expect("success");
        })
    }

    let mut group = c.benchmark_group("FramesReader");
    benchmark_multiple_backup_sizes(|size, backup, message_backup_key| {
        group.bench_function(BenchmarkId::new("direct", size), |b| {
            b.iter(|| process(CursorFactory::new(backup), message_backup_key))
        });
        group.bench_function(BenchmarkId::new("YieldingReader", size), |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(&backup)),
                    message_backup_key,
                )
            })
        });
    });
}

fn decrypt_and_decompress_and_hmac_and_segment(c: &mut Criterion) {
    fn process<R: ReaderFactory<Reader: Unpin>, R2: AsyncRead + Unpin>(
        input: R,
        key: &MessageBackupKey,
        transform: impl FnOnce(FramesReader<R::Reader>) -> R2,
    ) {
        futures::executor::block_on(async move {
            let reader = FramesReader::new(key, input).await.expect("success");
            let mut stream = VarintDelimitedReader::new(transform(reader));
            while let Some(next) = stream.read_next().await.expect("valid") {
                black_box(next);
            }
        })
    }

    let mut group = c.benchmark_group("FramesReader + VarintDelimitedReader");
    benchmark_multiple_backup_sizes(|size, backup, message_backup_key| {
        group.bench_function(BenchmarkId::new("direct", size), |b| {
            b.iter(|| process(CursorFactory::new(backup), message_backup_key, |r| r))
        });
        group.bench_function(BenchmarkId::new("direct + BufReader", size), |b| {
            b.iter(|| {
                process(
                    CursorFactory::new(backup),
                    message_backup_key,
                    BufReader::new,
                )
            })
        });
        group.bench_function(BenchmarkId::new("YieldingReader", size), |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(backup)),
                    message_backup_key,
                    |r| r,
                )
            })
        });
        group.bench_function(BenchmarkId::new("YieldingReader + BufReader", size), |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(backup)),
                    message_backup_key,
                    BufReader::new,
                )
            })
        });
    });
}

fn decrypt_and_decompress_and_hmac_and_segment_and_parse(c: &mut Criterion) {
    fn process<R: ReaderFactory<Reader: Unpin>, R2: AsyncRead + Unpin>(
        input: R,
        key: &MessageBackupKey,
        transform: impl FnOnce(FramesReader<R::Reader>) -> R2,
    ) {
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

    let mut group = c.benchmark_group("FramesReader + VarintDelimitedReader + Frame::parse");
    benchmark_multiple_backup_sizes(|size, backup, message_backup_key| {
        group.bench_function(BenchmarkId::new("direct", size), |b| {
            b.iter(|| process(CursorFactory::new(backup), message_backup_key, |r| r))
        });
        group.bench_function(BenchmarkId::new("direct + BufReader", size), |b| {
            b.iter(|| {
                process(
                    CursorFactory::new(backup),
                    message_backup_key,
                    BufReader::new,
                )
            })
        });
        group.bench_function(BenchmarkId::new("YieldingReader", size), |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(backup)),
                    message_backup_key,
                    |r| r,
                )
            })
        });
        group.bench_function(BenchmarkId::new("YieldingReader + BufReader", size), |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(backup)),
                    message_backup_key,
                    BufReader::new,
                )
            })
        });
    });
}

fn decrypt_and_decompress_and_hmac_and_segment_and_parse_and_validate(c: &mut Criterion) {
    fn process<R: ReaderFactory<Reader: Unpin>, R2: AsyncRead + Unpin>(
        input: R,
        key: &MessageBackupKey,
        transform: impl FnOnce(FramesReader<R::Reader>) -> R2,
    ) {
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

    let mut group = c.benchmark_group("FramesReader + VarintDelimitedReader + PartialBackup");
    benchmark_multiple_backup_sizes(|size, backup, message_backup_key| {
        group.bench_function(BenchmarkId::new("direct", size), |b| {
            b.iter(|| process(CursorFactory::new(backup), message_backup_key, |r| r))
        });
        group.bench_function(BenchmarkId::new("direct + BufReader", size), |b| {
            b.iter(|| {
                process(
                    CursorFactory::new(backup),
                    message_backup_key,
                    BufReader::new,
                )
            })
        });
        group.bench_function(BenchmarkId::new("YieldingReader", size), |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(backup)),
                    message_backup_key,
                    |r| r,
                )
            })
        });
        group.bench_function(BenchmarkId::new("YieldingReader + BufReader", size), |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(backup)),
                    message_backup_key,
                    BufReader::new,
                )
            })
        });
    });
}

fn validate_using_full_backup_reader(c: &mut Criterion) {
    fn process<R: ReaderFactory<Reader: Unpin>>(input: R, key: &MessageBackupKey) {
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

    let mut group = c.benchmark_group("BackupReader");
    benchmark_multiple_backup_sizes(|size, backup, message_backup_key| {
        group.bench_function(BenchmarkId::new("direct", size), |b| {
            b.iter(|| process(CursorFactory::new(backup), message_backup_key))
        });
        group.bench_function(BenchmarkId::new("YieldingReader", size), |b| {
            b.iter(|| {
                process(
                    YieldingReader(CursorFactory::new(backup)),
                    message_backup_key,
                )
            })
        });
    });
}

fn parse_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("Frame::parse");
    benchmark_multiple_backup_sizes(|size, _backup, _key| {
        if size == 0 {
            return;
        }

        let frames: Vec<Vec<u8>> = generate_frames(size, MESSAGES_PER_CONVERSATION * size)
            .map(|frame| frame.write_to_bytes().unwrap())
            .collect();

        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| {
                for next in &frames {
                    black_box(
                        libsignal_message_backup::proto::backup::Frame::parse_from_bytes(next)
                            .expect("valid"),
                    );
                }
            })
        });
    });
}

fn parse_and_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("PartialBackup");
    benchmark_multiple_backup_sizes(|size, _backup, _key| {
        if size == 0 {
            return;
        }

        let backup_info = generate_backup_info().write_to_bytes().unwrap();
        let frames: Vec<Vec<u8>> = generate_frames(size, MESSAGES_PER_CONVERSATION * size)
            .map(|frame| frame.write_to_bytes().unwrap())
            .collect();

        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| {
                let mut backup = PartialBackup::<ValidateOnly>::by_parsing(
                    &backup_info,
                    libsignal_message_backup::backup::Purpose::RemoteBackup,
                    |_| (),
                )
                .expect("valid");
                for next in &frames {
                    backup.parse_and_add_frame(next, |_| ()).expect("valid");
                }
                _ = CompletedBackup::try_from(backup).expect("valid");
            })
        });
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
    parse_only,
    parse_and_validate,
);
criterion_main!(validation);
