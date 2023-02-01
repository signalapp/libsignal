//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(Debug, displaydoc::Display)]
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
