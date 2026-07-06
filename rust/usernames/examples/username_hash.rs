//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use base64::prelude::{BASE64_STANDARD, Engine as _};
use clap::Parser;

#[derive(Parser)]
#[command(about = "Turn your username into hash")]
struct Args {
    /// Full username (e.g. signal.42)
    username: String,
}

fn main() {
    let Args { username } = Args::parse();
    let username = usernames::Username::new(&username).expect("valid username");
    let hash = username.hash();
    println!("base64:\t{}", &BASE64_STANDARD.encode(hash));
}
