# Design: Post-Quantum Hybrid KEM for HPKE

**Date:** 2026-04-01
**Status:** Approved for implementation
**Crate:** `signal-crypto` (`rust/crypto`)

---

## 1. Context and Motivation

### Purpose

To close the one remaining gap in libsignal's post-quantum hardening: one-shot HPKE encryption. Session-based messaging is already protected by PQXDH and SPQR. However, the HPKE layer (`SimpleHpkeSender` / `SimpleHpkeReceiver`) uses a purely classical X25519 KEM. Any ciphertext produced today — for key backups, server-side key encryption, or similar app-layer uses — can be stored by an adversary and decrypted in the future once a sufficiently powerful quantum computer breaks X25519. This is the "harvest now, decrypt later" threat.

### Expected Outcome

After this change, data encrypted via `HybridHpkePublicKey::seal` is protected by both ML-KEM 1024 (NIST FIPS 203) and X25519. A quantum adversary breaking X25519 gains nothing; an adversary finding a weakness in ML-KEM 1024 is still stopped by X25519. The security guarantee holds as long as at least one of the two KEMs remains secure. All existing callers using the X25519-only path are unaffected.

### Example

```rust
// Receiver generates a hybrid key pair (e.g., during device registration)
let hybrid_priv = HybridHpkePrivateKey::generate(&mut rng);
let hybrid_pub  = hybrid_priv.public_key();

// Sender encrypts a key backup blob to the receiver's public key
let ciphertext = hybrid_pub
    .seal(b"backup-context-v1", b"", &backup_plaintext)
    .expect("encryption succeeds");

// Receiver decrypts (now or years later) — quantum-safe
let recovered = hybrid_priv
    .open(b"backup-context-v1", b"", &ciphertext)
    .expect("decryption succeeds");

assert_eq!(backup_plaintext, recovered.as_slice());
```

### What is already post-quantum hardened

The libsignal Rust implementation already provides strong PQC coverage for session-based messaging:

- **PQXDH** — Session root key is derived from `HKDF-SHA-256(0xFF×32 ‖ ss_x25519_dh1 ‖ ss_x25519_dh2 ‖ ss_x25519_dh3 ‖ ss_kyber1024)` with domain label `"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"`. Both X25519 and Kyber1024 shared secrets feed the root key, satisfying the hybrid combiner property.
- **SPQR** — Signal's Sparse Post-Quantum Ratchet (`spqr v1.5.1`) provides ongoing PQC forward secrecy in the Double Ratchet.
- **ML-KEM 1024 KEM infrastructure** — `libcrux-ml-kem` is a workspace dependency; `kem/mlkem1024.rs` in the protocol crate implements encaps/decaps for FIPS 203.

### The remaining gap: HPKE

`rust/crypto/src/hpke.rs` exposes `SimpleHpkeSender` / `SimpleHpkeReceiver` for one-shot, stateless public-key encryption. It is used by the app layer for operations such as key backups and server-side key encryption — data that may require decades of confidentiality.

Currently only one cipher suite exists:

```rust
pub enum SignalHpkeCiphertextType {
    Base_X25519_HkdfSha256_Aes256Gcm = 1,
}
```

This is a purely classical X25519-based KEM. A quantum adversary who harvests ciphertext today and breaks X25519 in the future can decrypt it. This design closes that gap.

---

## 2. Design Goals

- Post-quantum confidentiality for one-shot HPKE-encrypted data (hybrid KEM).
- Full alignment with NIST FIPS 203 (ML-KEM 1024).
- No new architectural patterns — reuse the same primitives (`libcrux-ml-kem`, `libsignal_core::curve`, `hkdf`, `signal-crypto` AES-256-GCM) already established by PQXDH.
- Full backward compatibility — `Base_X25519_HkdfSha256_Aes256Gcm = 1` is unchanged.
- Hybrid combiner property: security holds as long as at least one of ML-KEM or X25519 is secure.
- Compliance with NIST FIPS 203, SP 800-186, SP 800-56C, SP 800-227.

---

## 3. NIST Compliance

| Component | Choice | NIST reference |
|---|---|---|
| PQC KEM | ML-KEM 1024 | FIPS 203 (final, Aug 2024), Category 5 |
| Classical KEM | X25519 | SP 800-186 approved |
| Hybrid combination | `HKDF(ss_mlkem ‖ ss_x25519)` | SP 800-227 hybrid key establishment |
| KDF (primary) | HKDF-SHA-256 | SP 800-56C, ~128-bit quantum security |
| KDF (optional upgrade) | HKDF-SHA-512 | SP 800-56C, ~256-bit quantum security — see Section 9 |
| AEAD | AES-256-GCM | FIPS 197, ~128-bit quantum security |

ML-KEM 1024 is the FIPS 203 final standard. The existing session layer defaults to the pre-standard `Kyber1024` (`key type 0x08`). This design uses `ML-KEM 1024` (`key type 0x0A`) directly, making the HPKE layer more NIST-aligned than the current session default.

---

## 4. New Cipher Suite

```rust
pub enum SignalHpkeCiphertextType {
    Base_X25519_HkdfSha256_Aes256Gcm = 1,            // existing, unchanged
    Hybrid_MlKem1024_X25519_HkdfSha256_Aes256Gcm = 2, // new
}
```

The type byte is included in every ciphertext at byte 0, so the receiver can dispatch to the correct decryption path without any out-of-band negotiation.

---

## 5. New Key Types

The existing `SimpleHpkeSender` / `SimpleHpkeReceiver` are implemented on `libsignal_core::curve::PublicKey` / `PrivateKey` (X25519 only). Hybrid encryption requires a combined key.

```rust
/// A public key for hybrid ML-KEM 1024 + X25519 HPKE encryption.
/// Holds one X25519 public key and one ML-KEM 1024 public key.
pub struct HybridHpkePublicKey {
    x25519: libsignal_core::curve::PublicKey,
    mlkem:  libcrux_ml_kem::mlkem1024::MlKem1024PublicKey,
}

/// A private key for hybrid ML-KEM 1024 + X25519 HPKE decryption.
pub struct HybridHpkePrivateKey {
    x25519: libsignal_core::curve::PrivateKey,
    mlkem:  libcrux_ml_kem::mlkem1024::MlKem1024PrivateKey,
}
```

Note: `signal-crypto` cannot depend on `libsignal-protocol` (circular dependency: protocol → signal-crypto). The `kem::PublicKey` / `kem::SecretKey` types from the protocol crate cannot be used here. Instead we use `libcrux-ml-kem` types directly — the same underlying crate that the protocol crate's `kem/mlkem1024.rs` wraps.

`SimpleHpkeSender` is implemented for `HybridHpkePublicKey`.
`SimpleHpkeReceiver` is implemented for `HybridHpkePrivateKey`.

The existing impls on `PublicKey` / `PrivateKey` are untouched.

---

## 6. Wire Format

```
[ type_byte (1 B) | mlkem_ciphertext (1568 B) | x25519_enc (32 B) | aead_ciphertext ]
```

- `type_byte` = `0x02` (`Hybrid_MlKem1024_X25519_HkdfSha256_Aes256Gcm`)
- `mlkem_ciphertext` — ML-KEM 1024 encapsulation output, fixed 1568 bytes (FIPS 203 §7.2)
- `x25519_enc` — ephemeral X25519 public key (encapsulated secret), fixed 32 bytes
- `aead_ciphertext` — AES-256-GCM ciphertext + 16-byte tag

Total overhead vs plaintext: 1 + 1568 + 32 + 16 = **1617 bytes**.

---

## 7. Encryption (Sender / Seal)

```
// Step 1: ML-KEM 1024 encapsulation
(mlkem_ct, ss_mlkem) = mlkem1024::encapsulate(recipient_mlkem_pubkey, rng)

// Step 2: X25519 key agreement (ephemeral)
eph_keypair = X25519::generate(rng)
ss_x25519   = eph_keypair.private_key.calculate_agreement(recipient_x25519_pubkey)
x25519_enc  = eph_keypair.public_key.bytes()

// Step 3: Combine shared secrets — hybrid combiner via HKDF-SHA-256
ikm         = ss_mlkem || ss_x25519
label       = b"Signal-Hybrid-MlKem1024-X25519-HkdfSha256-Aes256Gcm v1"
// info for AEAD key:   label bytes || 0x00 || info_param bytes
// info for AEAD nonce: label bytes || 0x01 || info_param bytes
// The 0x00/0x01 domain separator byte ensures key and nonce are derived
// from independent HKDF outputs even if info_param is empty.
aead_key    = HKDF-SHA-256(salt=[], ikm, info=label || [0x00] || info_param, length=32)
aead_nonce  = HKDF-SHA-256(salt=[], ikm, info=label || [0x01] || info_param, length=12)

// Step 4: AES-256-GCM encrypt
ciphertext  = AES-256-GCM-Seal(key=aead_key, nonce=aead_nonce, aad=aad_param, msg=plaintext)

// Step 5: Assemble wire format
output = [0x02] || mlkem_ct || x25519_enc || ciphertext
```

The HKDF `info` parameter binds the ciphertext to its intended context, preventing cross-context attacks. Domain label is fixed and version-tagged.

---

## 8. Decryption (Receiver / Open)

```
// Step 1: Parse wire format
type_byte   = ciphertext[0]          // must be 0x02
mlkem_ct    = ciphertext[1..1569]
x25519_enc  = ciphertext[1569..1601]
aead_ct     = ciphertext[1601..]

// Step 2: ML-KEM 1024 decapsulation
ss_mlkem    = mlkem1024::decapsulate(sk_mlkem, mlkem_ct)

// Step 3: X25519 key agreement
ss_x25519   = sk_x25519.calculate_agreement(x25519_enc)

// Step 4: Re-derive AEAD key and nonce (same as sender)
ikm         = ss_mlkem || ss_x25519
aead_key    = HKDF-SHA-256(salt=[], ikm, info=label || [0x00] || info_param, length=32)
aead_nonce  = HKDF-SHA-256(salt=[], ikm, info=label || [0x01] || info_param, length=12)

// Step 5: AES-256-GCM decrypt (authenticates aad and tag)
plaintext   = AES-256-GCM-Open(key=aead_key, nonce=aead_nonce, aad=aad_param, ct=aead_ct)
```

---

## 9. HKDF-SHA-512 Variant (Implemented, Optional Use)

HKDF-SHA-256 provides ~128-bit post-quantum security, which is NIST-acceptable. HKDF-SHA-512 raises this to ~256-bit — matching the full security level of ML-KEM 1024 (Category 5) end-to-end. Both variants are implemented in this effort. The choice of which to use is left to the caller.

```rust
pub enum SignalHpkeCiphertextType {
    Base_X25519_HkdfSha256_Aes256Gcm = 1,              // existing, unchanged
    Hybrid_MlKem1024_X25519_HkdfSha256_Aes256Gcm = 2,  // new: ~128-bit PQ security
    Hybrid_MlKem1024_X25519_HkdfSha512_Aes256Gcm = 3,  // new: ~256-bit PQ security
}
```

**Domain label for variant 3:**
```
b"Signal-Hybrid-MlKem1024-X25519-HkdfSha512-Aes256Gcm v1"
```

The implementation difference between variant 2 and variant 3 is a single substitution: `sha2::Sha256` → `sha2::Sha512` in the KDF step. Wire format, KEM logic, and AEAD are identical.

`SimpleHpkeSender` and `SimpleHpkeReceiver` are implemented for `HybridHpkePublicKey` / `HybridHpkePrivateKey` for both variants. The caller selects the cipher suite at construction time; the type byte in the wire format ensures the receiver always decrypts with the matching variant regardless of which was chosen at encryption time.

**Guidance for callers:**
- Use variant 2 (`HkdfSha256`) when consistency with the rest of the codebase is a priority.
- Use variant 3 (`HkdfSha512`) when end-to-end security headroom matching ML-KEM 1024 Category 5 is required.

---

## 10. Cryptographic Library Dependencies

**We implement no cryptographic primitives ourselves.** Every component delegates to an established, externally maintained library:

| Primitive | Library | Version | Notes |
|---|---|---|---|
| ML-KEM 1024 | `libcrux-ml-kem` | 0.0.8 | Cryspen; formally verified using the HAX proof framework; already a workspace dependency used by PQXDH |
| X25519 | `libsignal_core::curve` | workspace | Signal's own vetted X25519 implementation; same as used everywhere in the protocol layer |
| HKDF-SHA-256 | `hkdf` (RustCrypto) | 0.12 | Industry-standard Rust crypto; already a workspace dependency |
| AES-256-GCM | `signal-crypto` (this crate) | workspace | `Aes256GcmEncryption` / `Aes256GcmDecryption`, already in use in the existing HPKE path |

The following change to `rust/crypto/Cargo.toml` is required:

```toml
libcrux-ml-kem = { workspace = true, features = ["mlkem1024"] }
```

`libcrux-ml-kem` is already a workspace dependency (protocol crate uses it). Adding it to `signal-crypto` introduces no new third-party code — it is the same audited crate at the same pinned version.

---

## 11. What Does NOT Change

- `hpke_rs` and its `CryptoProvider` — untouched; the new variant bypasses `hpke_rs` for the KEM step and uses direct primitives instead.
- `Base_X25519_HkdfSha256_Aes256Gcm = 1` — all existing callers continue to work.
- The Double Ratchet, PQXDH, SPQR — no changes anywhere in the protocol layer.
- Sealed sender — uses its own separate X25519 scheme, not affected.
- Any app-level code — `SimpleHpkeSender` and `SimpleHpkeReceiver` traits are implemented on the new key types; apps opt in by constructing a `HybridHpkePublicKey`.

---

## 12. Testing

Tests live in `rust/crypto/src/hpke.rs` (unit) and `rust/crypto/tests/` (integration).

### Round-trip correctness
- **Happy path** — generate a `HybridHpkePrivateKey`, derive the corresponding `HybridHpkePublicKey`, seal a known plaintext, open it, assert byte-for-byte equality.
- **Non-empty AAD** — repeat with a non-empty `aad` byte slice; assert decryption succeeds.
- **Non-empty info** — repeat with a non-empty `info` byte slice; assert decryption succeeds.
- **Empty plaintext** — seal and open a zero-length message; assert empty vec returned.

### Authentication failures (all must return an error, never garbage plaintext)
- **Wrong private key** — open with a freshly generated key; assert `HpkeError::OpenError`.
- **Tampered AEAD ciphertext** — flip one bit anywhere in the AEAD portion; assert `HpkeError::OpenError`.
- **Tampered ML-KEM ciphertext** — flip one bit in the `mlkem_ct` region; assert error (ML-KEM decapsulation produces a random decoy key, so the AEAD tag will not verify).
- **Tampered X25519 enc** — replace `x25519_enc` with random bytes; assert error.
- **Tampered AAD** — open with a different `aad`; assert `HpkeError::OpenError`.
- **Tampered info** — open with a different `info`; assert error.

### Wire format validation
- **Too short: empty input** — `open(&[])` must return `HpkeError::InvalidInput`.
- **Too short: truncated before mlkem boundary** — input of 5 bytes; assert `HpkeError::InvalidInput`.
- **Too short: truncated before x25519 boundary** — input of `1 + 1568` bytes (missing x25519 enc); assert `HpkeError::InvalidInput`.
- **Too short: no AEAD ciphertext** — input of `1 + 1568 + 32` bytes (0 ciphertext bytes, no tag); assert `HpkeError::InvalidInput`.
- **Wire format sizes** — assert sealed output byte length equals `1 + 1568 + 32 + plaintext.len() + 16` for a known plaintext length.

### Type-byte dispatch
- **Wrong type byte** — feed a `Base_X25519_HkdfSha256_Aes256Gcm` ciphertext to `HybridHpkePrivateKey::open`; assert error (wrong key type).
- **Unknown type byte** — prepend `0xFF` and attempt open; assert `HpkeError::UnknownMode` or equivalent.
- **Cross-type: hybrid ciphertext to X25519 receiver** — feed a hybrid ciphertext to `PrivateKey::open`; assert error.

### Hybrid combiner property (cryptographic correctness)
- **ML-KEM contribution is load-bearing** — encrypt, then re-derive AEAD key using only `ss_x25519` (zeroing `ss_mlkem`); assert the derived key differs from the real one.
- **X25519 contribution is load-bearing** — encrypt, then re-derive AEAD key using only `ss_mlkem` (zeroing `ss_x25519`); assert the derived key differs from the real one.
- **HKDF domain separation: key ≠ nonce** — for the same IKM, assert `aead_key` (info `label||[0x00]||info`) is not equal to `aead_nonce` (info `label||[0x01]||info`).

### ML-KEM library correctness (delegation verification)
- **NIST FIPS 203 known-answer test** — use one of the published NIST KAT vectors for ML-KEM 1024 to verify `libcrux-ml-kem` encaps/decaps produce the expected shared secret. Purpose: confirm the library is wired correctly, not that we trust our own implementation.

### Integration: existing path unaffected
- **X25519 round-trip unchanged** — run the existing `basic` test in `hpke.rs`; assert it still passes without modification.
- **Type byte `0x01` still dispatches to X25519** — assert `PublicKey::seal` produces a ciphertext starting with `0x01`.

---

## 13. Out of Scope

- ML-DSA / CRYSTALS-Dilithium for identity key signatures — separate initiative.
- Migrating the session-layer default from `Kyber1024` to `ML-KEM 1024` — separate initiative (requires protocol version negotiation).
