v0.78.0

## SVR-B

- Operations have been consistently renamed to `store` and `restore`.
- `restore` now returns an object containing both the BackupForwardSecrecyToken for decryption, and "secret data" to be used in the first `store` after restoration.

## Other changes
