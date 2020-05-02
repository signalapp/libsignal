use arrayref::array_ref;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub use super::kdf::HKDF;

pub struct MessageKeys {
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; 16],
    counter: u32,
}

impl MessageKeys {
    pub fn derive_keys(input_key_material: &[u8], kdf: HKDF, counter: u32) -> Self {
        let okm = kdf.derive_secrets(input_key_material, b"WhisperMessageKeys", 80);
        MessageKeys {
            cipher_key: *array_ref![okm, 0, 32],
            mac_key: *array_ref![okm, 32, 32],
            iv: *array_ref![okm, 64, 16],
            counter,
        }
    }

    #[inline]
    pub fn cipher_key(&self) -> &[u8; 32] {
        &self.cipher_key
    }

    #[inline]
    pub fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }

    #[inline]
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    #[inline]
    pub fn counter(&self) -> u32 {
        self.counter
    }
}
pub struct ChainKey {
    kdf: HKDF,
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    const MESSAGE_KEY_SEED: [u8; 1] = [0x01u8];
    const CHAIN_KEY_SEED: [u8; 1] = [0x02u8];

    pub fn new(kdf: HKDF, key: [u8; 32], index: u32) -> Self {
        Self { kdf, key, index }
    }

    #[inline]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    #[inline]
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn next_chain_key(&self) -> Self {
        Self {
            kdf: self.kdf,
            key: self.calculate_base_material(Self::CHAIN_KEY_SEED),
            index: self.index + 1,
        }
    }

    pub fn message_keys(&self) -> MessageKeys {
        MessageKeys::derive_keys(
            &self.calculate_base_material(Self::MESSAGE_KEY_SEED),
            self.kdf,
            self.index,
        )
    }

    fn calculate_base_material(&self, seed: [u8; 1]) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_varkey(&self.key).expect("hmac key should be able to be any size");
        mac.input(&seed);
        mac.result().code().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_key_derivation_v2() {
        let seed = [
            0x8au8, 0xb7, 0x2d, 0x6f, 0x4c, 0xc5, 0xac, 0x0d, 0x38, 0x7e, 0xaf, 0x46, 0x33, 0x78,
            0xdd, 0xb2, 0x8e, 0xdd, 0x07, 0x38, 0x5b, 0x1c, 0xb0, 0x12, 0x50, 0xc7, 0x15, 0x98,
            0x2e, 0x7a, 0xd4, 0x8f,
        ];
        let message_key = [
            0x02u8, 0xa9, 0xaa, 0x6c, 0x7d, 0xbd, 0x64, 0xf9, 0xd3, 0xaa, 0x92, 0xf9, 0x2a, 0x27,
            0x7b, 0xf5, 0x46, 0x09, 0xda, 0xdf, 0x0b, 0x00, 0x82, 0x8a, 0xcf, 0xc6, 0x1e, 0x3c,
            0x72, 0x4b, 0x84, 0xa7,
        ];
        let mac_key = [
            0xbfu8, 0xbe, 0x5e, 0xfb, 0x60, 0x30, 0x30, 0x52, 0x67, 0x42, 0xe3, 0xee, 0x89, 0xc7,
            0x02, 0x4e, 0x88, 0x4e, 0x44, 0x0f, 0x1f, 0xf3, 0x76, 0xbb, 0x23, 0x17, 0xb2, 0xd6,
            0x4d, 0xeb, 0x7c, 0x83,
        ];
        let next_chain_key = [
            0x28u8, 0xe8, 0xf8, 0xfe, 0xe5, 0x4b, 0x80, 0x1e, 0xef, 0x7c, 0x5c, 0xfb, 0x2f, 0x17,
            0xf3, 0x2c, 0x7b, 0x33, 0x44, 0x85, 0xbb, 0xb7, 0x0f, 0xac, 0x6e, 0xc1, 0x03, 0x42,
            0xa2, 0x46, 0xd1, 0x5d,
        ];

        let chain_key = ChainKey::new(HKDF::new(2).expect("HKDF v2 should exist"), seed, 0);
        assert_eq!(&seed, chain_key.key());
        assert_eq!(&message_key, chain_key.message_keys().cipher_key());
        assert_eq!(&mac_key, chain_key.message_keys().mac_key());
        assert_eq!(&next_chain_key, chain_key.next_chain_key().key());
        assert_eq!(0, chain_key.index());
        assert_eq!(0, chain_key.message_keys().counter());
        assert_eq!(1, chain_key.next_chain_key().index());
        assert_eq!(1, chain_key.next_chain_key().message_keys().counter());
    }

    #[test]
    fn test_chain_key_derivation_v3() {
        let seed = [
            0x8au8, 0xb7, 0x2d, 0x6f, 0x4c, 0xc5, 0xac, 0x0d, 0x38, 0x7e, 0xaf, 0x46, 0x33, 0x78,
            0xdd, 0xb2, 0x8e, 0xdd, 0x07, 0x38, 0x5b, 0x1c, 0xb0, 0x12, 0x50, 0xc7, 0x15, 0x98,
            0x2e, 0x7a, 0xd4, 0x8f,
        ];
        let message_key = [
            0xbfu8, 0x51, 0xe9, 0xd7, 0x5e, 0x0e, 0x31, 0x03, 0x10, 0x51, 0xf8, 0x2a, 0x24, 0x91,
            0xff, 0xc0, 0x84, 0xfa, 0x29, 0x8b, 0x77, 0x93, 0xbd, 0x9d, 0xb6, 0x20, 0x05, 0x6f,
            0xeb, 0xf4, 0x52, 0x17,
        ];
        let mac_key = [
            0xc6u8, 0xc7, 0x7d, 0x6a, 0x73, 0xa3, 0x54, 0x33, 0x7a, 0x56, 0x43, 0x5e, 0x34, 0x60,
            0x7d, 0xfe, 0x48, 0xe3, 0xac, 0xe1, 0x4e, 0x77, 0x31, 0x4d, 0xc6, 0xab, 0xc1, 0x72,
            0xe7, 0xa7, 0x03, 0x0b,
        ];
        let next_chain_key = [
            0x28u8, 0xe8, 0xf8, 0xfe, 0xe5, 0x4b, 0x80, 0x1e, 0xef, 0x7c, 0x5c, 0xfb, 0x2f, 0x17,
            0xf3, 0x2c, 0x7b, 0x33, 0x44, 0x85, 0xbb, 0xb7, 0x0f, 0xac, 0x6e, 0xc1, 0x03, 0x42,
            0xa2, 0x46, 0xd1, 0x5d,
        ];

        let chain_key = ChainKey::new(HKDF::new(3).expect("HKDF v3 should exist"), seed, 0);
        assert_eq!(&seed, chain_key.key());
        assert_eq!(&message_key, chain_key.message_keys().cipher_key());
        assert_eq!(&mac_key, chain_key.message_keys().mac_key());
        assert_eq!(&next_chain_key, chain_key.next_chain_key().key());
        assert_eq!(0, chain_key.index());
        assert_eq!(0, chain_key.message_keys().counter());
        assert_eq!(1, chain_key.next_chain_key().index());
        assert_eq!(1, chain_key.next_chain_key().message_keys().counter());
    }
}
