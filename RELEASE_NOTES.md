v0.96.4

- node: Expose the registration session state as an optional `sessionState` payload on some errors.

- node, swift: Expose DonationPermit.expiration

- RegistrationService now refreshes its cached session state from failed verification requests, so the session state stays current even after a request fails.

- Expose and document several APIs on UnauthBackupsService originally added in libsignal v0.94.4. These APIs require an H2 connection (the normal behavior when using libsignal now) and will fail without one.

- SVR2: update production to 2026Q2

- SVRB: update production to 2026Q2

- Add reserveUsernameHash() typed API
