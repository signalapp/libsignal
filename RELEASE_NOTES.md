v0.68.0

- Swift: Allow UnidentifiedSenderMessageContent to be constructed from a message type and opaque bytes. (Contributed by @saman3d!)

- net: Add a client for the registration verification service. This is currently
  only available via the Node bindings.

- Java: InputStreams created by MessageBackup.validate() are now correctly closed when the operation is complete.

- Node: The InputStream abstraction now has an optional close() method, which will be called by MessageBackup.validate() on any created streams when the operation is complete. If your InputStream already has a close() method, this may be a breaking change for you.

- backups: Enforce that messages with expiration timers < 24 hours are not included in Remote Backups.

- backups: Add support for LocalLocator for local backups