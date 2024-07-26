//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(displaydoc::Display, Debug, thiserror::Error, PartialEq, Eq)]
pub enum UsernameError {
    /// Username must contain a '.'
    MissingSeparator,
    /// Name cannot be empty
    NicknameCannotBeEmpty,
    /// Name cannot start with a digit
    NicknameCannotStartWithDigit,
    /// Nickname contains disallowed character
    BadNicknameCharacter,
    /// Nickname is too short
    NicknameTooShort,
    /// Nickname is too long
    NicknameTooLong,
    /// Discriminator cannot be empty
    DiscriminatorCannotBeEmpty,
    /// Discriminator cannot be zero
    DiscriminatorCannotBeZero,
    /// Discriminator cannot be a single digit
    DiscriminatorCannotBeSingleDigit,
    /// Discriminator cannot have leading zeros unless it would otherwise be a single digit
    DiscriminatorCannotHaveLeadingZeros,
    /// Discriminator must only be made up of digits
    BadDiscriminatorCharacter,
    /// Value is too large to be a username discriminator
    DiscriminatorTooLarge,
}

#[derive(displaydoc::Display, Debug, thiserror::Error)]
/// Username could not be verified
pub struct ProofVerificationFailure;

#[derive(displaydoc::Display, Debug, thiserror::Error)]
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
