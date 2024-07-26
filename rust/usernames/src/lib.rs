//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub use error::{ProofVerificationFailure, UsernameError};
pub use username::*;

pub mod constants;
mod error;
mod proto;
mod username;
mod username_links;

pub use error::UsernameLinkError;
pub use username_links::{create_for_username, decrypt_username};
