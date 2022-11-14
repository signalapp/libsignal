//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Read;

use rand::Rng;
use zkgroup::{ServerSecretParams, RANDOMNESS_LEN};

fn main() {
    let mut old_secret_base64 = String::new();
    std::io::stdin()
        .read_to_string(&mut old_secret_base64)
        .unwrap();
    let old_secret = base64::decode(old_secret_base64.trim_end()).unwrap();

    let mut rng = rand::thread_rng();
    let mut randomness = [0u8; RANDOMNESS_LEN];
    rng.fill(&mut randomness);

    let fresh_secret = ServerSecretParams::generate(randomness);
    let mut serialized_secret = bincode::serialize(&fresh_secret).unwrap();
    serialized_secret[..old_secret.len()].copy_from_slice(&old_secret);

    let new_secret: ServerSecretParams = bincode::deserialize(&serialized_secret).unwrap();
    let new_public = new_secret.get_public_params();
    let serialized_public = bincode::serialize(&new_public).unwrap();

    println!("server_secret: {}", base64::encode(&serialized_secret[..]));
    println!("server_public: {}", base64::encode(&serialized_public[..]));
}
