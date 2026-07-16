v0.97.4

- Typed APIs
  - AuthAccountsService.setRegistrationLock()
  - AuthAccountsService.clearRegistrationLock()
  - AuthAccountsService.setDiscoverableByPhoneNumber()
  - AuthAccountsService.setRegistrationRecoveryPassword()
  - UnauthBackupsService.copyBackupMedia()

- node: Add full-er service SVR2 APIs that performs necessary crypto operations inside libsignal.
- Add `SvrKey`, which provides derivations for registration lock, registration recovery, storage service, and logging keys.

- Update to nightly-2026-07-15 rust toolchain to address miscompile https://github.com/rust-lang/rust/issues/159035
