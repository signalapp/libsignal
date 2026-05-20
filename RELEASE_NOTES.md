v0.94.2

- backups: Remove key transparency data field from AccountData message.

- Internal: libsignal now uses v0.22 of the `jni` crate. On Android, the `rustls-platform-verifier` dependency continues to use v0.21 alongside v0.22; this will be resolved in a future update.
