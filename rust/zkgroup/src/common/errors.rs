//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#[derive(Debug)]
pub enum ZkGroupError {
    BadArgs,                      // Bad arguments were passed to the function
    DecryptionFailure,            // Decryption failed
    MacVerificationFailure,       // MAC verification failed
    ProofVerificationFailure,     // Proof verification failed
    SignatureVerificationFailure, // Signature verification failed
    PointDecodeFailure,           // Lizard failed to decode; CAN HAPPEN
}
