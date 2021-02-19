//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(Debug)]
pub enum PokshoError {
    BadArgs,                          // Bad arguments were passed to the function
    BadArgsWrongNumberOfScalarArgs,   // Bad arguments were passed to the function
    BadArgsWrongNumberOfPointArgs,    // Bad arguments were passed to the function
    BadArgsMissingScalarArg,          // Bad arguments were passed to the function
    BadArgsMissingPointArg,           // Bad arguments were passed to the function
    VerificationFailure,              // Proof verification failed
    ProofCreationVerificationFailure, // Proof verification failed during proof creation, indicating bad inputs or faulty computation
}
