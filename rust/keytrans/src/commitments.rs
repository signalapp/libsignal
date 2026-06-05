//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use hmac::{Hmac, Mac as _};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const FIXED_KEY: &[u8] = &[
    0xd8, 0x21, 0xf8, 0x79, 0xd, 0x97, 0x70, 0x97, 0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
];

#[derive(Clone, Copy, Debug, displaydoc::Display, Eq, PartialEq)]
pub enum Error {
    /// search key is too large to be encoded
    SearchKeyTooLarge,
    /// data is too large to be encoded
    DataTooLarge,
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

pub fn commit(search_key: &[u8], data: &[u8], nonce: &[u8; 16]) -> Result<Vec<u8>> {
    // The expected search_key inputs to this function are: an ACI, an E164,
    // or a username. None should reach 2^16 bound.
    let key_len: u16 = search_key
        .len()
        .try_into()
        .map_err(|_| Error::SearchKeyTooLarge)?;
    // The expected data inputs to this function are: an ACI, or
    // a serialized public key. Neither should reach 2^32 bound.
    let data_len: u32 = data.len().try_into().map_err(|_| Error::DataTooLarge)?;

    let mut mac = HmacSha256::new_from_slice(FIXED_KEY).expect("can create hmac from fixed key");
    mac.update(nonce);
    mac.update(&key_len.to_be_bytes());
    mac.update(search_key);
    mac.update(&data_len.to_be_bytes());
    mac.update(data);

    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn verify(search_key: &[u8], commitment: &[u8], data: &[u8], nonce: &[u8; 16]) -> Result<bool> {
    // No concern about timing attacks here, as commitments are public.
    Ok(commit(search_key, data, nonce)? == commitment)
}

#[cfg(test)]
mod test {
    use const_str::hex;
    use test_case::test_case;

    use super::*;

    #[test_case(&[], &[], &hex!("edc3f59798cd87f2f48ec8836e2b6ef425cde9ab121ffdefc93d769db7cebabf") ; "empty")]
    #[test_case(b"foo", b"bar", &hex!("25df431e884358826fe66f96d65702580104240abd63fa741d9ea3f32914bbf5") ; "case_1")]
    #[test_case(b"foo1", b"bar", &hex!("6c31a163a7660d1467fc1c997bd78b0a70b8921ca76b7eb0c6ca077f1e5e121e") ; "case_2")]
    #[test_case(b"foo", b"bar1", &hex!("5de6c6c9ed4bf48122f6c851c80e6eacbf885947f02f974cdc794b14c8e975f1") ; "case_3")]
    fn test_commit(key: &[u8], data: &[u8], expected: &[u8]) {
        let got = commit(key, data, &[0u8; 16]).expect("valid input sizes");
        assert_eq!(got, expected);
    }

    #[test]
    fn oversized_search_key_is_rejected() {
        let search_key = vec![0u8; usize::from(u16::MAX) + 1];

        assert_eq!(
            commit(&search_key, b"data", &[0u8; 16]),
            Err(Error::SearchKeyTooLarge)
        );
        assert_eq!(
            verify(&search_key, b"commitment", b"data", &[0u8; 16]),
            Err(Error::SearchKeyTooLarge)
        );
    }
}
