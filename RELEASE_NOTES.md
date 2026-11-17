v0.108.1

- backups: Support `deleteData` on GroupMemberRemovedUpdate and GroupTerminateChangeUpdate.

- Typed APIs
  - UnauthKeysService.getPreKeys()
  - AuthRemoteConfigurationService.getBadges()
  - Added `getProfile()` (unauth) (Not yet bridged to clients)
  - Added `AuthAccountsService.setZkCredentialKey()`
  - Added `extendAvatarTtl()` (bridged to clients)
  - Added `deleteAvatar()` (bridged to clients)
  - Added `getAvatarUploadForm()` (bridged to clients)
  - Added `getAvatarUploadFormLegacy()` (bridged to clients)
  - Added `getAvatarCredential()` (bridged to clients)

