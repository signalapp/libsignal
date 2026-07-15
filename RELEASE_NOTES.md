v0.97.4

- Typed APIs
  - AuthAccountsService.setRegistrationLock()
  - AuthAccountsService.clearRegistrationLock()
  - AuthAccountsService.setDiscoverableByPhoneNumber()
  - UnauthBackupsService.copyBackupMedia()

- node: Add full-er service SVR2 APIs that performs necessary crypto operations inside libsignal.
- Add `SvrKey`, which provides derivations for registration lock, registration recovery, storage service, and logging keys.
