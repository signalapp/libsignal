//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::pin::Pin;

use futures::{ready, AsyncRead};
use hmac::digest::generic_array::GenericArray;
use hmac::Mac;

/// [`AsyncRead`]er that computes an HMAC of the produced contents.
#[derive(Clone, Debug)]
pub struct MacReader<R, M> {
    reader: R,
    mac: M,
}

impl<R, M> MacReader<R, M> {
    pub fn new(reader: R, mac: M) -> Self {
        Self { reader, mac }
    }

    pub fn finalize(self) -> GenericArray<u8, M::OutputSize>
    where
        M: Mac,
    {
        self.mac.finalize().into_bytes()
    }
}

impl<R: AsyncRead + Unpin, M: Mac + Unpin> AsyncRead for MacReader<R, M> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<futures::io::Result<usize>> {
        let Self { reader, mac } = self.get_mut();
        let num_read = ready!(Pin::new(reader).poll_read(cx, buf))?;

        mac.update(&buf[..num_read]);

        std::task::Poll::Ready(Ok(num_read))
    }
}

#[cfg(test)]
mod test {
    use futures::io::Cursor;
    use futures::FutureExt as _;
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;

    use super::*;
    use crate::frame::HMAC_LEN;

    #[test]
    fn mac_read() {
        const HMAC_KEY: [u8; HMAC_LEN] = [1; 32];

        let bytes = [b"asdf"; 32]
            .into_iter()
            .flatten()
            .copied()
            .collect::<Vec<u8>>();

        fn make_mac() -> Hmac<Sha256> {
            Hmac::<Sha256>::new_from_slice(&HMAC_KEY).expect("any length is valid")
        }

        let expected_hmac = {
            let mut mac = make_mac();
            mac.update(&bytes);
            mac.finalize().into_bytes()
        };

        let reader_hmac = {
            let mut reader = MacReader::new(Cursor::new(bytes), make_mac());
            futures::io::copy(&mut reader, &mut futures::io::sink())
                .now_or_never()
                .expect("future finished")
                .expect("success");
            reader.finalize()
        };

        assert_eq!(expected_hmac, reader_hmac);
    }
}
