//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use displaydoc::Display;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Display, Error)]
pub enum Error {
    /// invalid argument: {0}
    InvalidArgument(String),
}
