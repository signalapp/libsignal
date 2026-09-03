v0.102.0

- All libsignal-net-chat APIs that have both WebSocket and gRPC implementations will default to gRPC. This was already the case in practice for all three Signal clients due to remote configs *except* for `UnauthBackupsService.getUploadForm` and `getMediaUploadForm` (controlled by `grpc.BackupsAnonymousGetUploadForm`). This does not affect APIs that only have one implementation (a few older ones that are WebSocket-only still, and all the new ones that are gRPC-only).
- New typed APIs:
  - `AuthAccountsService.deleteAccount()`
  - `checkSVRCredentials()`
  - `getCurrencyConversions()`
  - `AuthKeysService.getPreKeyCount()`
  - `createLoginReceiptCredential()`
- MSRV bumped to 1.93.1
- registration: Add support for registration without E.164
- libsignal builds off stable Rust by default
