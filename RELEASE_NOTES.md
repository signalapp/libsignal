v0.106.1

- Swift: LibSignalClient is now distributed using Swift Package Manager instead
  of CocoaPods. See swift/README.md for more information.
- Rust: New `message_decrypt_prekey_at`, which takes the current time. With it,
  an incoming session wins the simultaneous-initiation tiebreak when our own
  unacknowledged session is too old to send on.


