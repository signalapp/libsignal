//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(displaydoc::Display, Debug)]
pub enum UsernameError {
    /// Name cannot be empty
    CannotBeEmpty,
    /// Name cannot start with a digit
    CannotStartWithDigit,
    /// Username must contain a '.'
    MissingSeparator,
    /// Invalid discriminator
    BadDiscriminator,
    /// Nickname contains disallowed character
    BadNicknameCharacter,
    /// Nickname is too short
    NicknameTooShort,
    /// Nickname is too long
    NicknameTooLong,
    /// Username could not be verified
    ProofVerificationFailure,
}

#[derive(displaydoc::Display, Debug)]
pub enum UsernameLinkError {
    /// The combined length of all input data is too long
    InputDataTooLong,
    /// Invalid size of the entropy data
    InvalidEntropyDataLength,
    /// Username link data size is too short: must contain IV, ciphertext, and HMAC
    UsernameLinkDataTooShort,
    /// HMAC on username link doesn't match the one calculated with the given entropy input
    HmacMismatch,
    /// Ciphertext in the username link can't be decrypted
    BadCiphertext,
    /// Data decrypted from the username link is of invalid structure
    InvalidDecryptedDataStructure,
}
