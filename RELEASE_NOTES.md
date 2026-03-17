v0.89.0

- Node: Implementing `IdentityKeyStore.getIdentityKeyPair()` can avoid rederivation of the public key from the existing `IdentityKeyStore.getIdentityKey()` requirement. In the future, the PrivateKey-only `getIdentityKey()` will be removed.
- Node: Update all uses of `Uint8Array` and `Buffer` to use `ArrayBuffer`
