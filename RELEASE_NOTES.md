v0.75.0

- Node: All APIs now use Uint8Array instead of Buffer. This is a breaking change if you were relying on any of the APIs added to Buffer on top of Uint8Array, including the diverging behavior of `slice()` and `toString()`.

- Require that device IDs in protocol addresses be in the range [1, 127]. This is a breaking change.

- Require Swift 6.0 to build LibSignalClient.

- Java: remove Curve.kt from the public API.

- Java: port several classes to Kotlin; these changes are Java-compatible but might require changes in consuming Kotlin code.

- Android: acknowledgments for testing APIs are now shipped as `assets/acknowledgments/libsignal-testing.md`, feel free to strip them out in your build if you are also removing `libsignal_jni_testing.so`.

- iOS: the name of the acknowledgments file has changed from `acknowledgments.plist` to `acknowledgments-ios.plist`.

