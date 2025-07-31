v0.78.0

## SVR-B

- Operations have been consistently renamed to `store` and `restore`.
- `restore` now returns an object containing both the BackupForwardSecrecyToken for decryption, and "secret data" to be used in the first `store` after restoration.

## Other changes

- Rust: `SessionRecord::has_usable_sender_chain` now takes an additional parameter to specify which criteria make a session "usable" beyond simply *having* a sender chain. The previous behavior can be requested by using `SessionUsabilityRequirements::NotStale`.
