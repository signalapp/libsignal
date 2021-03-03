//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

pub mod args;
pub mod errors;
pub mod proof;
pub mod scalar;
pub mod shoapi;
pub mod shohmacsha256;
pub mod shosha256;
pub mod sign;
mod simple_types;
pub mod statement;

pub use args::{PointArgs, ScalarArgs};
pub use errors::PokshoError;
pub use proof::Proof;
pub use scalar::{scalar_from_slice_canonical, scalar_from_slice_wide};
pub use shoapi::ShoApi;
pub use shohmacsha256::ShoHmacSha256;
pub use shosha256::ShoSha256;
pub use sign::{sign, verify_signature};
pub use statement::Statement;
