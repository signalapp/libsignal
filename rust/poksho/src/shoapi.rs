//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub trait ShoApi {
    fn shohash(label: &[u8], input: &[u8], outlen: usize) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut sho = Self::new(label);
        sho.absorb_and_ratchet(input);
        sho.squeeze_and_ratchet(outlen)
    }

    fn absorb_and_ratchet(&mut self, input: &[u8]) {
        self.absorb(input);
        self.ratchet();
    }

    fn new(label: &[u8]) -> Self
    where
        Self: Sized;

    fn absorb(&mut self, input: &[u8]);

    fn ratchet(&mut self);

    // unimplemented; make this more generic later
    // pub fn squeeze(&mut self, _outlen: usize) -> Vec<u8>;

    fn squeeze_and_ratchet(&mut self, outlen: usize) -> Vec<u8>;
}
