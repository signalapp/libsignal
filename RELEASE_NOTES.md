v0.106.1

- Swift: LibSignalClient is now distributed using Swift Package Manager instead
  of CocoaPods. See swift/README.md for more information.
- protocol: Session records that hold more archived sessions than the limit
  (such as records written before Tahini) are now trimmed when they are loaded,
  rather than the next time a session is archived.


