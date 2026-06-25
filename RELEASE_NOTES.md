v0.96.4

- node: Expose the registration session state as an optional `sessionState` payload on some errors.
- RegistrationService now refreshes its cached session state from failed verification requests, so the session state stays current even after a request fails.
- SVR2: update production to 2026Q2
- SVRB: update production to 2026Q2
