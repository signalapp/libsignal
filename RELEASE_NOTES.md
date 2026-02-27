v0.88.0

- java: KeyTransparencyClient now returns RequestResult types

- Java: `SealedSessionCipher.encrypt(SignalProtocolAddress, SenderCertificate, byte[])` now throws `NoSessionException` instead of `AssertionError` when there's no usable 1:1 session with the given recipient. `encrypt(SignalProtocolAddress, UnidentifiedSenderMessageContent)` is not affected.

- Add "grpc.MessagesAnonymousSendMultiRecipientMessage" remote config, and the implementation backing it.
