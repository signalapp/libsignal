//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use base64::Engine as _;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use clap::Parser;
use rand::TryRngCore as _;

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Generates a new entropy / ciphertext pair.
    ///
    /// Does not validate the username.
    Generate { username: String },
    /// Decrypts a given ciphertext with the given entropy, both in base64url format.
    Decrypt {
        /// The entropy (normally distributed as part of a link).
        #[arg(value_parser = |input: &str| BASE64_URL_SAFE_NO_PAD.decode(input))]
        // Using std::vec::Vec keeps clap from making this a variadic argument.
        entropy: std::vec::Vec<u8>,

        /// The ciphertext (normally stored on the server, keyed by a UUID).
        #[arg(value_parser = |input: &str| BASE64_URL_SAFE_NO_PAD.decode(input))]
        // Using std::vec::Vec keeps clap from making this a variadic argument.
        ciphertext: std::vec::Vec<u8>,
    },
}

fn main() -> Result<(), usernames::UsernameLinkError> {
    let cli = Cli::parse();
    let mut rng = rand::rngs::OsRng.unwrap_err();

    match cli.command {
        Command::Generate { username } => {
            let (entropy, ciphertext) = usernames::create_for_username(&mut rng, username, None)?;
            println!("   entropy: {}", BASE64_URL_SAFE_NO_PAD.encode(entropy));
            println!("ciphertext: {}", BASE64_URL_SAFE_NO_PAD.encode(ciphertext));
        }
        Command::Decrypt {
            entropy,
            ciphertext,
        } => {
            let entropy = entropy.try_into().expect("entropy has wrong length");
            println!("{}", usernames::decrypt_username(&entropy, &ciphertext)?);
        }
    }

    Ok(())
}
