# Overview

libsignal-client contains platform-agnostic APIs useful for Signal client apps, exposed as a Java,
Swift, or TypeScript library. The underlying implementations are written in Rust:

- libsignal-protocol: Implements the Signal protocol, including the [Double Ratchet algorithm][]. A
  replacement for [libsignal-protocol-java][] and [libsignal-metadata-java][].
- signal-crypto: Cryptographic primitives such as AES-GCM-SIV. We use [RustCrypto][]'s where we can
  but sometimes have differing needs.
- device-transfer: Support logic for Signal's device-to-device transfer feature.
- poksho: Utilities for implementing zero-knowledge proofs; stands for "proof-of-knowledge, stateful-hash-object". See [zkgroup][].

This repository is used by the Signal client apps ([Android][], [iOS][], and [Desktop][]). Use
outside of Signal is unsupported. In particular, the products of this repository are the Java,
Swift, and TypeScript libraries that wrap the underlying Rust implementations. Those underlying
implementations are subject to change without notice, as are the JNI, C, and Node add-on "bridge"
layers.

[Double Ratchet algorithm]: https://signal.org/docs/
[libsignal-protocol-java]: https://github.com/signalapp/libsignal-protocol-java
[libsignal-metadata-java]: https://github.com/signalapp/libsignal-metadata-java
[RustCrypto]: https://github.com/RustCrypto
[zkgroup]: https://github.com/signalapp/zkgroup
[Android]: https://github.com/signalapp/Signal-Android
[iOS]: https://github.com/signalapp/Signal-iOS
[Desktop]: https://github.com/signalapp/Signal-Desktop


# Building

To build anything in this repository you must have [Rust](https://rust-lang.org) installed.
The build currently uses a specific version of the Rust nightly compiler, which
will be downloaded automatically by cargo. To build and test the basic protocol
libraries:

```shell
$ cargo build
...
$ cargo test
...
```

## Java/Android

To build for Android you must install several additional packages including a JDK,
the Android NDK/SDK, and add the Android targets to the Rust compiler, using

```rustup target add armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android```

as well as the Cargo NDK tool using

```cargo install --version=1.0.0 cargo-ndk```

To build the Java/Android ``jar`` and ``aar``, and run the tests:

```shell
$ cd java
$ ./gradlew test
```

Alternately, a build system using Docker is available:

```shell
$ cd java
$ make java_test
```

Local Java testing is also supported with `gradlew test` if none of the `ANDROID_*` environment
variables are set.

When exposing new APIs to Java, you will need to run `rust/bridge/jni/bin/gen_java_decl.py` in
addition to rebuilding.


## Swift

To learn about the Swift build process see [``swift/README.md``](swift/)


## Node

You'll need Node installed to build. If you have [nvm][], you can run `nvm use` to select an
appropriate version automatically.

We use [`yarn`](https://classic.yarnpkg.com/) as our package manager. The Rust library will automatically be built when you run `yarn install`.

```shell
$ nvm use
$ yarn install
$ yarn tsc
$ yarn test
```

When testing changes locally, you can use `yarn build` to do an incremental rebuild of the Rust library.

When exposing new APIs to Node, you will need to run `rust/bridge/node/bin/gen_ts_decl.py` in
addition to rebuilding.

[nvm]: https://github.com/nvm-sh/nvm


# Contributions

Signal does accept external contributions to this project. However unless the change is
simple and easily understood, for example fixing a bug or portability issue, adding a new
test, or improving performance, first open an issue to discuss your intended change as not
all changes can be accepted.

Contributions that will not be used directly by one of Signal's official client apps may still be
considered, but only if they do not pose an undue maintenance burden or conflict with the goals of
the project.

Signing a [CLA (Contributor License Agreement)](https://signal.org/cla/) is required for all contributions.

# Legal things
## Cryptography Notice

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on
the import, possession, use, and/or re-export to another country, of encryption software.  BEFORE using any encryption
software, please check your country's laws, regulations and policies concerning the import, possession, or use, and
re-export of encryption software, to see if this is permitted.  See <http://www.wassenaar.org/> for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as
Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing
cryptographic functions with asymmetric algorithms.  The form and manner of this distribution makes it eligible for
export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export
Administration Regulations, Section 740.13) for both object code and source code.

## License

Copyright 2020-2021 Signal Messenger, LLC

Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
