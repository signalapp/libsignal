v0.79.1

- The first "Typed API" service interface for chat-server, UnauthUsernamesService, has been added to libsignal's app layer.

- The libsignal-net remote config option `chatRequestConnectionCheckTimeoutMillis` controls a new check: if a chat request hasn't been responded to in this amount of time, libsignal will check if the connection is using the preferred network interface, and close it early if not.

- Java: `CertificateValidator.validate(SenderCertificate, long)` is once again `open` for testing.

- backups: Validate quote body length

- MSRV has been increased to 1.85
