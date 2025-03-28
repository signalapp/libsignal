v0.68.1

- Swift: GroupIdentifier is now CustomStringConvertible (to its hex bytes)

- Swift: `[UInt8]` and `Data` both now have a `toHex()` method backed by the Rust `hex` crate.
