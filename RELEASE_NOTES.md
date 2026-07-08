v0.96.5

- Add AuthUsernameService.setUsernameLink() typed API
- Add AuthDeviceService.getDevices() typed API
- Add AuthDeviceService.clearPushToken() typed API
- Enforce a minimum TCB level for all SGX attestations.
- RegistrationService now also refreshes its cached session state from rate-limited (429) server responses.
- Update to JDK21, following Android. It is now the _required_ version to build libsignal for Java! However, since it
  has been out for some time this change should not be a problem in practice.
