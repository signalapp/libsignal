//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::error::{Error, Result};
use ::polyval::universal_hash::{NewUniversalHash, UniversalHash};

#[derive(Clone)]
pub struct PolyvalSoft {
    polyval: ::polyval::Polyval,
}

impl PolyvalSoft {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(Error::InvalidKeySize);
        }

        Ok(Self {
            polyval: polyval::Polyval::new(key.into()),
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        assert_eq!(data.len() % 16, 0);
        self.polyval.update(data.into());
        Ok(())
    }

    pub fn update_padded(&mut self, data: &[u8]) -> Result<()> {
        self.polyval.update_padded(data);
        Ok(())
    }

    pub fn finalize(self) -> Result<[u8; 16]> {
        Ok(self.polyval.finalize().into_bytes().into())
    }
}
