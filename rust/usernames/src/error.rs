//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(Debug)]
pub enum UsernameError {
    BadUsernameFormat,
    BadDiscriminator,
    BadNicknameCharacter,
    NicknameTooShort,
    NicknameTooLong,
    ProofVerificationFailure,
}
