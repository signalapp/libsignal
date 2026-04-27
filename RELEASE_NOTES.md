v0.93.0

- Check identity key and service id to determine a self-message: `processPreKeyMessage()` and `signalDecrypt()` both
  require the local address

- Exposed `UnauthMessagesService.sendMessage`, `AuthMessagesService.sendMessage`, and `AuthMessagesService.sendSyncMessage` for 1:1 sealed and unsealed sends. The gRPC implementation will be used if `grpc.MessagesAnonymousSendSingleRecipientMessage` (unauth) or `grpc.MessagesSendMessage` (both auth) is set.
