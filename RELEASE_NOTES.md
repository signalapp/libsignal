v0.85.0

- Incremental MAC validation now checks up front that the digest list is at least structurally valid (a concatenation of digests of the correct length). This was already being checked implicitly, but produced an obtuse error.

    - Java: IncrementalMacInputStream's constructor can now throw InvalidMacException (instead of an AssertionError)
    - Swift: ValidatingMacContext's initializer will now throw .verificationFailed (instead of .internalError)
    - Node: ValidatingWritable's constructor will now throw IncrementalMacVerificationFailed (instead of a plain Error)
    - Rust: Incremental::validating now specifically takes an iterator over borrowed arrays (or GenericArrays)

- Backups: The consolidated away wifiAutoDownloadSettings is now treated as unknown.

- Typed APIs: `UnauthMessagesService.sendMultiRecipientMessage` has been added to libsignal's app layer.
