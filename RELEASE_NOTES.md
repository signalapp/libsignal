v0.72.0

- Swift: `sealedSenderEncrypt(message:for:from:sessionStore:identityStore:context:)` and `sealedSenderDecrypt(message:from:trustRoot:timestamp:sessionStore:identityStore:preKeyStore:signedPreKeyStore:context:)` have been removed. The former was a simple wrapper around `sealedSenderEncrypt(_:for:identityStore:context:)` for 1:1 messages that didn't expose all the features of UnidentifiedSenderMessageContent, and the latter was never updated to support PQXDH messages. The Signal iOS app does not use either function. If you were using `sealedSenderDecrypt`, switch to `UnidentifiedSenderMessageContent.init(message:identityStore:context:)`, and make sure to validate the resulting sender certificate and check for a self-send yourself before attempting to decrypt the inner message.

- The iOS minimum deployment target has been bumped to iOS 15.
