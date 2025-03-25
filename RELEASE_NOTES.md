v0.67.7

- Swift: Allow UnidentifiedSenderMessageContent to be constructed from a message type and opaque bytes. (Contributed by @saman3d!)

- net: Add a client for the registration verification service. This is currently
  only available via the Node bindings.

- Java: InputStreams created by MessageBackup.validate() are now correctly closed when the operation is complete.
