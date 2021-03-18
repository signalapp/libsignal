//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::polyval::Polyval;
use crate::{Error, Result};

#[derive(Clone)]
pub struct Ghash {
    polyval: Polyval,
}

/*
* Specializing this for exactly == 16 results in much better codegen
*/
fn reverse_bytes_16(c: &[u8]) -> [u8; 16] {
    assert!(c.len() == 16);
    let mut z = [0u8; 16];
    z[0..16].copy_from_slice(&c[0..16]); // trailing 0s
    z.reverse();
    z
}

fn reverse_bytes(c: &[u8]) -> [u8; 16] {
    if c.len() == 16 {
        return reverse_bytes_16(c);
    }

    assert!(c.len() < 16);
    let mut z = [0u8; 16];
    z[0..c.len()].copy_from_slice(&c[0..c.len()]); // trailing 0s
    z.reverse();
    z
}

impl Ghash {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(Error::InvalidKeySize);
        }
        let polyval = Polyval::new(&Polyval::mulx(&reverse_bytes_16(key)))?;
        Ok(Self { polyval })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        if data.len() % 16 != 0 {
            return Err(Error::InvalidInputSize);
        }

        for c in data.chunks_exact(16) {
            self.polyval.update(&reverse_bytes_16(c))?;
        }
        Ok(())
    }

    pub fn update_padded(&mut self, data: &[u8]) -> Result<()> {
        for c in data.chunks(16) {
            self.polyval.update(&reverse_bytes(c))?;
        }
        Ok(())
    }

    pub fn finalize(self) -> Result<[u8; 16]> {
        Ok(reverse_bytes_16(&self.polyval.finalize()?))
    }
}

#[test]
fn ghash_test() -> Result<()> {
    // RFC 8452 Appendix A
    let h = hex::decode("25629347589242761d31f826ba4b757b").expect("valid hex");
    let input1 = hex::decode("4f4f95668c83dfb6401762bb2d01a262").expect("valid hex");
    let input2 = hex::decode("d1a24ddd2721d006bbe45f20d3c9f362").expect("valid hex");
    let mut ghash = Ghash::new(&h)?;
    ghash.update(&input1)?;
    ghash.update(&input2)?;

    let result = ghash.finalize()?;

    assert_eq!(hex::encode(&result), "bd9b3997046731fb96251b91f9c99d7a");

    Ok(())
}
