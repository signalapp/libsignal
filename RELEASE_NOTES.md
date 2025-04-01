v0.68.1

- Swift: GroupIdentifier is now CustomStringConvertible (to its hex bytes)

- Swift: `[UInt8]` and `Data` both now have a `toHex()` method backed by the Rust `hex` crate.

- backups: Release notes can now be included in a chat folder.

- net: Fix a bug where DNS-over-HTTPs lookups wouldn't attempt to make IPv4 and IPv6 connections
  to the nameserver in parallel.
