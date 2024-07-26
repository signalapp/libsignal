//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::{Read, Write};
use std::path::PathBuf;

use clap::Parser;
use libsignal_protocol::kem::*;

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum KeyType {
    Kyber,
    #[cfg(feature = "mlkem1024")]
    #[value(name = "mlkem")]
    MlKem,
}

impl From<KeyType> for libsignal_protocol::kem::KeyType {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Kyber => Self::Kyber1024,
            #[cfg(feature = "mlkem1024")]
            KeyType::MlKem => Self::MLKEM1024,
        }
    }
}

#[derive(clap::Subcommand)]
enum Command {
    /// Generates a new key pair.
    Generate {
        #[arg(short = 't')]
        key_ty: KeyType,
        #[arg(long = "secret")]
        secret_path: PathBuf,
        #[arg(long = "public")]
        public_path: PathBuf,
    },
    /// Writes a ciphertext to stdout.
    ///
    /// The plaintext will be logged on stderr.
    Encapsulate {
        #[arg(long = "public")]
        public_path: PathBuf,
    },
    /// Reads a ciphertext on stdin and verifies that it can be decapsulated.
    ///
    /// The plaintext will be logged on stderr.
    Decapsulate {
        #[arg(long = "secret")]
        secret_path: PathBuf,
    },
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Generate {
            key_ty,
            secret_path,
            public_path,
        } => {
            let key_pair = KeyPair::generate(key_ty.into());
            std::fs::write(secret_path, key_pair.secret_key.serialize())
                .expect("can write to file");
            std::fs::write(public_path, key_pair.public_key.serialize())
                .expect("can write to file");
        }
        Command::Encapsulate { public_path } => {
            let key_bytes = std::fs::read(public_path).expect("can read file");
            let key = PublicKey::deserialize(&key_bytes).expect("valid public key");
            let (ss, ciphertext) = key.encapsulate();
            log::info!("encapsulating shared secret {}", hex::encode(&ss));
            std::io::stdout()
                .write_all(&ciphertext)
                .expect("can write to stdout");
        }
        Command::Decapsulate { secret_path } => {
            let key_bytes = std::fs::read(secret_path).expect("can read file");
            let key = SecretKey::deserialize(&key_bytes).expect("valid secret key");
            let mut ciphertext_bytes = vec![];
            std::io::stdin()
                .read_to_end(&mut ciphertext_bytes)
                .expect("can read from stdin");
            let ss = key
                .decapsulate(&ciphertext_bytes.into_boxed_slice())
                .expect("valid ciphertext");
            log::info!("decapsulating shared secret {}", hex::encode(&ss));
        }
    }
}
