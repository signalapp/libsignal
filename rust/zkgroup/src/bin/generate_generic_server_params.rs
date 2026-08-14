//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Generates a new GenericServerSecretParams and encodes it using base64 and
//! [`bincode::serialize`].

use base64::prelude::{BASE64_STANDARD, Engine};
use rand::Rng;
use zkgroup::RANDOMNESS_LEN;
use zkgroup::generic_server_params::{
    GenericServerSecretParams, GenericServerSecretParamsLegacy, GenericServerSecretParamsStandard,
};

fn main() {
    let mut rng = rand::rng();
    let mut randomness = [0u8; RANDOMNESS_LEN];
    rng.fill(&mut randomness);

    let secret_params: GenericServerSecretParams = match std::env::args().nth(1).as_deref() {
        Some("--legacy") => GenericServerSecretParamsLegacy::generate(randomness).into(),
        Some("--standard") => GenericServerSecretParamsStandard::generate(randomness).into(),
        _ => {
            eprintln!("must specify --legacy or --standard");
            std::process::exit(1);
        }
    };
    let serialized_secret = bincode::serialize(&secret_params).unwrap();
    let serialized_public = bincode::serialize(&secret_params.get_public_params()).unwrap();

    println!("secret: {}", BASE64_STANDARD.encode(&serialized_secret[..]));
    println!("public: {}", BASE64_STANDARD.encode(&serialized_public[..]));
}
