//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(Debug, displaydoc::Display)]
pub enum ZkGroupError {
    /// Bad arguments were passed to the function
    BadArgs,
    /// Decryption failed
    DecryptionFailure,
    /// MAC verification failed
    MacVerificationFailure,
    /// Proof verification failed
    ProofVerificationFailure,
    /// Signature verification failed
    SignatureVerificationFailure,
}
