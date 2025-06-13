v0.75.0

- X3DH handling has been removed from libsignal; X3DH PreKey messages will now be rejected as invalid. (Note for Rust clients: they are rejected as InvalidMessage rather than LegacyCiphertextVersion because that is more practical for the official Signal apps.) PQXDH will be required going forward and the Rust-level PreKeyBundle and related types have been updated to reflect this. There are no further API changes for the app languages.

- Node: All APIs now use Uint8Array instead of Buffer. This is a breaking change if you were relying on any of the APIs added to Buffer on top of Uint8Array, including the diverging behavior of `slice()` and `toString()`.

- Require that device IDs in protocol addresses be in the range [1, 127]. This is a breaking change.

- Require Swift 6.0 to build LibSignalClient.

- Swift: use `Data` instead of `[UInt8]` as the type of buffers in arguments and return types.

- Java: remove Curve.kt from the public API.

- Java: port several classes to Kotlin; these changes are Java-compatible but might require changes in consuming Kotlin code.

- Android: acknowledgments for testing APIs are now shipped as `assets/acknowledgments/libsignal-testing.md`, feel free to strip them out in your build if you are also removing `libsignal_jni_testing.so`.

- iOS: the name of the acknowledgments file has changed from `acknowledgments.plist` to `acknowledgments-ios.plist`.
