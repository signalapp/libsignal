v0.101.0

- zkgroup: Update the implementation of GenericServerSecretParams and GenericServerPublicParams.
  - These types no longer implement `serde::Deserialize`. If you were using zkgroup's bincode-based serialization, you should switch to `TryFrom<&[u8]>` instead.
  - The call link credentials, CallLinkAuthCredential and CreateCallLinkCredential, track which version of GenericServerSecretParams they were issued from. A temporary helper method `verify_against_appropriate_params` has been added to both of their presentation types to allow a verifying server to pass both old and new params and have them chosen based on the credential's version indicator.
  - The other credentials issued from GenericServerSecretParams, BackupAuthCredential and AvatarUploadCredential, were not directly affected by this change, and support both old and new param versions.
  - ServerSecretParams and ServerPublicParams continue to use the old key behavior for compatibility.
  - If you were using zkcredential directly, consider regenerating your keys; if you need a migration period, you can use `zkcredential::credentials::LegacyMode` to continue with the old behavior.

- Update boring-rs dependency to v5.2.0 (includes a BoringSSL update as well).

- Typed APIs:
  - `submitCallQualitySurvey()`
  - `AuthUsernamesService.confirmUsername()`
