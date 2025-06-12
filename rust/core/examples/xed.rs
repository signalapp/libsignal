//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Read as _;

use clap::Parser;
use hex::FromHex as _;
use libsignal_core::curve::*;
use rand::TryRngCore as _;

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Generates a new key pair.
    ///
    /// The output is in the form libsignal expects, including a "type byte" prefix on the public
    /// key.
    Generate,
    /// Signs the contents of stdin, writing the hex-encoded signature to stdout.
    Sign {
        /// The private key, encoded as hex.
        // from_hex is *too* general; limiting it to `&str` helps clap out.
        #[arg(value_parser = |input: &str| Vec::from_hex(input))]
        // Using std::vec::Vec keeps clap from making this a variadic argument.
        key: std::vec::Vec<u8>,
    },
    /// Verifies the contents of stdin against the given signature.
    Verify {
        /// The public key, encoded as hex.
        #[arg(value_parser = |input: &str| Vec::from_hex(input))]
        key: std::vec::Vec<u8>,
        /// The signature, encoded as hex.
        #[arg(value_parser = |input: &str| Vec::from_hex(input))]
        signature: std::vec::Vec<u8>,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let mut rng = rand::rngs::OsRng.unwrap_err();

    match cli.command {
        Command::Generate => {
            let key_pair = KeyPair::generate(&mut rng);
            println!("private: {}", hex::encode(key_pair.private_key.serialize()));
            println!(" public: {}", hex::encode(key_pair.public_key.serialize()));
        }
        Command::Sign { key } => {
            let key = PrivateKey::deserialize(&key).expect("valid private key");
            let mut input = vec![];
            std::io::stdin()
                .read_to_end(&mut input)
                .expect("can read message");
            println!(
                "{}",
                hex::encode(key.calculate_signature(&input, &mut rng).expect("can sign"))
            );
        }
        Command::Verify { key, signature } => {
            let key = PublicKey::deserialize(&key).expect("valid public key");
            let mut input = vec![];
            std::io::stdin()
                .read_to_end(&mut input)
                .expect("can read message");
            if key.verify_signature(&input, &signature) {
                println!("valid!");
            } else {
                println!("not valid!");
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    std::process::ExitCode::SUCCESS
}
