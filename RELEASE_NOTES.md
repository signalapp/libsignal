v0.95.0

- zkgroup: Add AvatarUploadCredential, an anonymous credential used to rate-limit avatar uploads.

- Java: `SessionCipher.getRemoteRegistrationId()` and `SessionCipher.getSessionVersion()` now throw `NoSessionException` instead of `IllegalStateException` when no session exists.
- Swift: `SessionRecord.getRegistrationId` will throw a `.sessionNotFound(_:)` now instead of `.invalidState(_:)` if the current session is not found.

- Several new requests have been added to UnauthBackupsService; however, they are only usable when an H2 connection is guaranteed, and should not be adopted otherwise.

- node: Implement a full-service SVR2 client API

- Rust: `SignalProtocolError::InvalidMessage` now has a `String` description instead of just `&'static str`.
