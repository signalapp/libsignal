v0.108.0

- Provisioning: public keys are now represented by a `ProvisioningPublicKey` type rather than raw bytes.
  - To use `encryptProvisionMessage`, callers must now first construct a `ProvisioningPublicKey`.
  - Malformed public keys yield an error in `encryptProvisionMessage`, and not in the `ProvisioningPublicKey` constructor.
  - `encryptProvisionMessage` now returns an invalid-key error on malformed public keys. Specifically, it now returns `InvalidKeyException` in Java, `SignalError.invalidKey` in Swift, and a generic error in TypeScript.
- Protocol: `IdentityKeyStore` has a new `recordReceivedIdentity` method, called instead of `saveIdentity` when a message is decrypted on an archived session, with the identity key the message was decrypted under. It defaults to doing nothing.
- Java: Username hashes are now represented by a dedicated `UsernameHash` type instead of raw `byte[]`.
