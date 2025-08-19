v0.79.0

- Rust: libsignal-protocol's fingerprint-related operations have a dedicated error type now, FingerprintError, rather than reusing SignalProtocolError.

- backups: validate presence of `OutgoingMessageDetails.dateReceived`, remove deprecated BackupLocator/AttachmentLocator/LocalLocator
