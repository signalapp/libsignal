v0.96.5

- Add AuthUsernameService.setUsernameLink() typed API
- Add AuthDeviceService.getDevices() typed API
- Add AuthDeviceService.setPushToken() typed API (Java and Swift only)
- Add AuthDeviceService.clearPushToken() typed API
- Enforce a minimum TCB level for all SGX attestations.
- RegistrationService now also refreshes its cached session state from rate-limited (429) server responses.
- Update to JDK21, following Android. It is now the _required_ version to build libsignal for Java! However, since it
  has been out for some time this change should not be a problem in practice.
- ChatConnection: server alerts may be delivered (via the callback in ChatConnectionListener) slightly later than before; previously they were guaranteed to be delivered as part of the `start` call (Java and Swift) or `connect` operation (Node). They will still be delivered before any messages.
