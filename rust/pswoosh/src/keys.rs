use crate::sys_a::{A, AT};

pub struct SwooshKeyPair{
    pub private_key: [u8; crate::SECRETKEY_BYTES],
    pub public_key: [u8; crate::PUBLICKEY_BYTES],
}

impl SwooshKeyPair {
    pub fn generate(is_alice: bool) -> Self{
        
        let (private_key, public_key) = if is_alice{
            crate::pswoosh_keygen(&A, true)
        } else{
            crate::pswoosh_keygen(&AT, false)
        };

        Self {
            private_key,
            public_key,
        }
        
    }
}

mod tests {
    use crate::keys::SwooshKeyPair;

    #[test]
    fn test_key_generation() {
        let alice_keypair = SwooshKeyPair::generate(true);
        let bob_keypair = SwooshKeyPair::generate(false);

        assert_eq!(alice_keypair.public_key.len(), crate::PUBLICKEY_BYTES);
        assert_eq!(bob_keypair.public_key.len(), crate::PUBLICKEY_BYTES);
        assert_eq!(alice_keypair.private_key.len(), crate::SECRETKEY_BYTES);
        assert_eq!(bob_keypair.private_key.len(), crate::SECRETKEY_BYTES);
    }
}