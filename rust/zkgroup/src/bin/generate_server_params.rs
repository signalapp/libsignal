//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Read;

use base64::prelude::{BASE64_STANDARD, Engine};
use rand::Rng;
use zkgroup::{RANDOMNESS_LEN, ServerSecretParams};

fn main() {
    let mut old_secret_base64 = String::new();
    std::io::stdin()
        .read_to_string(&mut old_secret_base64)
        .unwrap();
    let old_secret = BASE64_STANDARD
        .decode(old_secret_base64.trim_end())
        .unwrap();

    let mut rng = rand::rng();
    let mut randomness = [0u8; RANDOMNESS_LEN];
    rng.fill(&mut randomness);

    let fresh_secret = ServerSecretParams::generate(randomness);
    let mut serialized_secret = bincode::serialize(&fresh_secret).unwrap();
    serialized_secret[..old_secret.len()].copy_from_slice(&old_secret);

    let new_secret: ServerSecretParams = bincode::deserialize(&serialized_secret).unwrap();
    let new_public = new_secret.get_public_params();
    let serialized_public = bincode::serialize(&new_public).unwrap();

    let new_secret_endorsements = new_secret.get_endorsement_root_key_pair();
    let serialized_secret_endorsements = bincode::serialize(&new_secret_endorsements).unwrap();

    println!(
        "server_secret: {}",
        BASE64_STANDARD.encode(&serialized_secret[..])
    );
    println!(
        "server_public: {}",
        BASE64_STANDARD.encode(&serialized_public[..])
    );
    println!(
        "endorsements_secret: {}",
        BASE64_STANDARD.encode(&serialized_secret_endorsements[..])
    );
}
