//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod encrypted_stream;
mod waker;
pub use encrypted_stream::{Authorization, EncryptedStream};

mod handshake;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SendError {
    /// {0}
    Noise(#[from] snow::Error),
    /// {0}
    Io(#[from] std::io::Error),
}

impl From<SendError> for std::io::Error {
    fn from(value: SendError) -> Self {
        match value {
            SendError::Noise(e) => {
                std::io::Error::new(std::io::ErrorKind::Other, format!("noise error: {e}"))
            }
            SendError::Io(e) => e,
        }
    }
}
