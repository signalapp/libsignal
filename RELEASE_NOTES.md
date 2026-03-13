v0.88.4

- Node: Implementing `IdentityKeyStore.getIdentityKeyPair()` can avoid rederivation of the public key from the existing `IdentityKeyStore.getIdentityKey()` requirement. In the future, the PrivateKey-only `getIdentityKey()` will be removed.
