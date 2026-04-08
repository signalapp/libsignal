# Extraction notes

`signal-crypto` depends on `libsignal-core`. We extract both in a single Charon+Aeneas run, with `signal-crypto` as the target crate and `libsignal-core` as a transparent dependency (`--include libsignal_core`).

## Public functions — signal-crypto

Depends on: `libsignal-core`, `aes`, `cbc`, `ctr`, `ghash`, `hmac`, `sha1`, `sha2`, `hkdf`, `hpke-rs`, `subtle`

### Error

- `Error` enum: `UnknownAlgorithm`, `InvalidKeySize`, `InvalidNonceSize`, `InvalidInputSize`, `InvalidTag`

### CryptographicMac

- `new(algo: &str, key: &[u8]) -> Result<Self>` — opaque (calls hmac)
- `update(&mut self, input: &[u8])` — opaque (calls hmac)
- `update_and_get(&mut self, input: &[u8]) -> &mut Self`
- `finalize(&mut self) -> Vec<u8>` — opaque (calls hmac)

### CryptographicHash

- `new(algo: &str) -> Result<Self>` — opaque (calls sha1/sha2)
- `update(&mut self, input: &[u8])` — opaque (calls sha1/sha2)
- `finalize(&mut self) -> Vec<u8>` — opaque (calls sha1/sha2)

### aes_cbc

- `aes_256_cbc_encrypt(ptext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, EncryptionError>` — opaque
- `aes_256_cbc_decrypt(ctext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, DecryptionError>` — opaque

### Aes256Ctr32

- `NONCE_SIZE: usize` (associated constant)
- `new(aes256: Aes256, nonce: &[u8], init_ctr: u32) -> Result<Self>` — opaque
- `from_key(key: &[u8], nonce: &[u8], init_ctr: u32) -> Result<Self>` — opaque
- `process(&mut self, buf: &mut [u8])` — opaque

### aes_gcm (module-level)

- `TAG_SIZE: usize = 16`
- `NONCE_SIZE: usize = 12`

### Aes256GcmEncryption

- `TAG_SIZE: usize` (associated constant)
- `NONCE_SIZE: usize` (associated constant)
- `new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<Self>`
- `encrypt(&mut self, buf: &mut [u8])`
- `compute_tag(self) -> [u8; TAG_SIZE]`

### Aes256GcmDecryption

- `TAG_SIZE: usize` (associated constant)
- `NONCE_SIZE: usize` (associated constant)
- `new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<Self>`
- `decrypt(&mut self, buf: &mut [u8])`
- `verify_tag(self, tag: &[u8]) -> Result<()>`

### HPKE (excluded)

Excluded entirely — complex external crypto provider (`hpke-rs`).

- `SimpleHpkeSender` trait
- `SimpleHpkeReceiver` trait
- `SignalHpkeCiphertextType` enum

## Public functions — libsignal-core

Depends on: `curve25519-dalek`, `x25519-dalek`, `sha2`, `uuid`, `zerocopy`, `derive_more`, `rand`

### E164

- `new(number: NonZeroU64) -> Self`
- `to_be_bytes(&self) -> [u8; 8]`
- `from_be_bytes(bytes: [u8; 8]) -> Option<Self>`

### SpecificServiceId

- `from_uuid_bytes(bytes: [u8; 16]) -> Self`
- `service_id_binary(&self) -> Vec<u8>`
- `service_id_fixed_width_binary(&self) -> ServiceIdFixedWidthBinaryBytes`
- ~~`service_id_string(&self) -> String`~~ — excluded (uses `format!`)
- `parse_from_service_id_binary(bytes: &[u8]) -> Option<Self>`
- `parse_from_service_id_fixed_width_binary(bytes: &ServiceIdFixedWidthBinaryBytes) -> Option<Self>`
- ~~`parse_from_service_id_string(input: &str) -> Option<Self>`~~ — excluded (uses `str::Pattern` GAT)

### ServiceId

- `kind(&self) -> ServiceIdKind`
- `service_id_binary(&self) -> Vec<u8>`
- `service_id_fixed_width_binary(&self) -> ServiceIdFixedWidthBinaryBytes`
- ~~`service_id_string(&self) -> String`~~ — excluded (uses `format!`)
- `parse_from_service_id_binary(bytes: &[u8]) -> Option<Self>`
- `parse_from_service_id_fixed_width_binary(bytes: &ServiceIdFixedWidthBinaryBytes) -> Option<Self>`
- ~~`parse_from_service_id_string(input: &str) -> Option<Self>`~~ — excluded (uses `str::Pattern` GAT)
- `raw_uuid(self) -> Uuid`
- ~~`to_protocol_address(&self, device_id: DeviceId) -> ProtocolAddress`~~ — excluded (calls `service_id_string`)

### DeviceId

- `new(id: u8) -> Result<Self, InvalidDeviceId>`
- `new_nonzero(id: NonZeroU8) -> Result<Self, InvalidDeviceId>`

### ProtocolAddress

- `new(name: String, device_id: DeviceId) -> Self`
- `name(&self) -> &str`
- `device_id(&self) -> DeviceId`

### PublicKey

- `deserialize(value: &[u8]) -> Result<Self, CurveError>` — opaque (uses `log::warn!`)
- `public_key_bytes(&self) -> &[u8]`
- `from_djb_public_key_bytes(bytes: &[u8]) -> Result<Self, CurveError>`
- `serialize(&self) -> Box<[u8]>`
- `verify_signature(&self, message: &[u8], signature: &[u8]) -> bool`
- `verify_signature_for_multipart_message(&self, message: &[&[u8]], signature: &[u8]) -> bool` — opaque (calls curve25519)
- `key_type(&self) -> KeyType`
- `is_canonical(&self) -> bool`

### PrivateKey

- `deserialize(value: &[u8]) -> Result<Self, CurveError>` — opaque (calls `scalar::clamp_integer`)
- `serialize(&self) -> Vec<u8>`
- `public_key(&self) -> Result<PublicKey, CurveError>` — opaque (calls curve25519)
- `key_type(&self) -> KeyType`
- `calculate_signature(...)` — opaque (calls curve25519)
- `calculate_signature_for_multipart_message(...)` — opaque (calls curve25519)
- `calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>, CurveError>` — opaque (calls curve25519)

### KeyPair

- `generate(csprng: &mut R) -> Self` — opaque (calls curve25519)
- `new(public_key: PublicKey, private_key: PrivateKey) -> Self`
- `from_public_and_private(public_key: &[u8], private_key: &[u8]) -> Result<Self, CurveError>`
- `calculate_signature(...)` — opaque (calls curve25519)
- `calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>, CurveError>` — opaque (calls curve25519)

### curve25519 (submodule — excluded)

Excluded entirely — Charon panics on `simplify_constants` pass due to array constant in `calculate_signature`.

Contains:
- `AGREEMENT_LENGTH: usize = 32`
- `PRIVATE_KEY_LENGTH: usize = 32`
- `PUBLIC_KEY_LENGTH: usize = 32`
- `SIGNATURE_LENGTH: usize = 64`
- `PrivateKey::new`, `calculate_agreement`, `calculate_signature`, `verify_signature`, `derive_public_key_bytes`, `private_key_bytes`

### Free functions

- `try_scoped(f: impl FnOnce() -> Result<T, E>) -> Result<T, E>`
- `derive_arrays(derive: impl FnOnce(&mut [u8])) -> ([u8; N1], [u8; N2], [u8; N3])` — opaque (uses zerocopy)
- `try_derive_arrays(derive: impl FnOnce(&mut [u8]) -> Result<(), E>) -> Result<(...), E>` — opaque (uses zerocopy)
- `VERSION: &str`

## Source modifications

### libsignal-core (`rust/core/`)

- `src/lib.rs` — added `#![feature(register_tool)]`, `#![register_tool(charon)]`, `#[charon::opaque]` on `derive_arrays`/`try_derive_arrays`
- `src/e164.rs` — tuple struct → named field (`E164(x)` → `E164 { inner: x }`), `#[charon::opaque]` on `from_str`, `cfg_attr` on `derive_more::Into`
- `src/address.rs` — tuple structs → named fields (`SpecificServiceId`, `DeviceId`), `#[charon::opaque]` on `service_id_string`/`parse_from_service_id_string`, `cfg(not(feature="extraction"))` on `rand::Distribution` impl
- `src/curve.rs` — `#[charon::opaque]` on functions calling curve25519 internals
- `src/curve/curve25519.rs` — `#[charon::opaque]` on `calculate_signature`/`verify_signature`
- `Cargo.toml` — added `extraction` feature

### signal-crypto (`rust/crypto/`)

- `src/lib.rs` — added `#![feature(register_tool)]`, `#![register_tool(charon)]`
- `src/aes_ctr.rs` — tuple struct → named field, `#[charon::opaque]` on struct and methods
- `src/aes_gcm.rs` — `#[charon::opaque]` on `GcmGhash` struct and methods, `cfg_attr` on `Clone` derives
- `src/aes_cbc.rs` — `#[charon::opaque]` on encrypt/decrypt functions
- `src/hash.rs` — `#[charon::opaque]` on enums and methods, `cfg_attr` on `Clone` derives
- `src/hpke.rs` — `#[charon::opaque]` on trait impl methods
- `Cargo.toml` — added `extraction` feature

### Workspace root

- `Cargo.toml` — added `exclude = [".aeneas"]`

## Known warnings

### `inout::inout::InOut` — region parameter warning

Aeneas warns: "Found an unknown type declaration with region parameters: as we can not know whether the regions are used in mutable borrows or not the extracted code may be incorrect."

`InOut<'inp, 'out, T>` is from the RustCrypto `inout` crate, used by the `cipher` crate for in-place block cipher operations. It appears in the LLBC because `ctr::Ctr32BE<Aes256>` (wrapped by our `Aes256Ctr32`) implements `cipher::BlockBackend`, whose `proc_block` method signature references `InOut`.

Currently all functions that use `InOut` are opaque, so the warning is harmless — Aeneas never needs to model its borrow semantics. It cannot be excluded from the LLBC without breaking the cipher trait chain.

When we later want transparent functions that use `InOut`, this will need to be resolved upstream in Aeneas (either by supporting region analysis for foreign types, or by allowing manual annotation of region usage).
