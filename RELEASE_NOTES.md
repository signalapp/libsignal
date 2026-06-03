v0.94.4

- Internal: libsignal now uses Android Gradle Plugin 9.1.1

- zkgroup: Add AvatarUploadCredential, an anonymous credential used to rate-limit avatar uploads.

- Several new requests have been added to UnauthBackupsService; however, they are only usable when an H2 connection is guaranteed, and should not be adopted otherwise.
