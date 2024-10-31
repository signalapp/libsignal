# Overview

libsignal contains platform-agnostic APIs used by the official Signal clients and servers, exposed
as a Java, Swift, or TypeScript library. The underlying implementations are written in Rust:

- libsignal-protocol: Implements the Signal protocol, including the [Double Ratchet algorithm][]. A
  replacement for [libsignal-protocol-java][] and [libsignal-metadata-java][].
- signal-crypto: Cryptographic primitives such as AES-GCM. We use [RustCrypto][]'s where we can
  but sometimes have differing needs.
- device-transfer: Support logic for Signal's device-to-device transfer feature.
- attest: Functionality for remote attestation of [SGX enclaves][] and server-side [HSMs][].
- zkgroup: Functionality for [zero-knowledge groups][] and related features available in Signal.
- zkcredential: An abstraction for the sort of zero-knowledge credentials used by zkgroup, based on the paper "[The Signal Private Group System][]" by Chase, Perrin, and Zaverucha.
- poksho: Utilities for implementing zero-knowledge proofs (such as those used by zkgroup); stands for "proof-of-knowledge, stateful-hash-object".
- account-keys: Functionality for consistently using [PINs][] as passwords in Signal's Secure Value Recovery system, as well as other account-wide key operations.
- usernames: Functionality for username generation, hashing, and proofs.
- media: Utilities for manipulating media.

This repository is used by the Signal client apps ([Android][], [iOS][], and [Desktop][]) as well as
server-side. Use outside of Signal is unsupported. In particular, the products of this repository
are the Java, Swift, and TypeScript libraries that wrap the underlying Rust implementations. All
APIs and implementations are subject to change without notice, as are the JNI, C, and Node add-on
"bridge" layers. However, backwards-incompatible changes to the Java, Swift, TypeScript, and
non-bridge Rust APIs will be reflected in the version number on a best-effort basis, including
increases to the minimum supported tools versions.

[Double Ratchet algorithm]: https://signal.org/docs/
[libsignal-protocol-java]: https://github.com/signalapp/libsignal-protocol-java
[libsignal-metadata-java]: https://github.com/signalapp/libsignal-metadata-java
[RustCrypto]: https://github.com/RustCrypto
[Noise protocol]: http://noiseprotocol.org/
[SGX enclaves]: https://www.intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions.html
[HSMs]: https://en.wikipedia.org/wiki/Hardware_security_module
[zero-knowledge groups]: https://signal.org/blog/signal-private-group-system/
[The Signal Private Group System]: https://eprint.iacr.org/2019/1416.pdf
[PINs]: https://signal.org/blog/signal-pins/
[Android]: https://github.com/signalapp/Signal-Android
[iOS]: https://github.com/signalapp/Signal-iOS
[Desktop]: https://github.com/signalapp/Signal-Desktop


# Building

### Toolchain Installation

To build anything in this repository you must have [Rust](https://rust-lang.org) installed,
as well as Clang, libclang, [CMake](https://cmake.org), Make, protoc, and git.

#### Linux/Debian

On a Debian-like system, you can get these extra dependencies through `apt`:

```shell
$ apt-get install clang libclang-dev cmake make protobuf-compiler git
```

#### macOS

On macOS, we have a best-effort maintained script to set up the Rust toolchain you can run by:

```shell
$ bin/mac_setup.sh
```

## Rust

### First Build and Test

The build currently uses a specific version of the Rust nightly compiler, which
will be downloaded automatically by cargo. To build and test the basic protocol
libraries:

```shell
$ cargo build
...
$ cargo test
...
```

### Additional Rust Tools

The basic tools above should get you set up for most libsignal Rust development. 

Eventually, you may find that you need some additional Rust tools like `cbindgen` to modify the bridges to the 
client libraries or `taplo` for code formatting. 

You should always install any Rust tools you need that may affect the build from cargo rather than from your system
package manager (e.g. `apt` or `brew`). Package managers sometimes contain outdated versions of these tools that can break
the build with incompatibility issues (especially cbindgen).

To install the main Rust extra dependencies matching the versions we use, you can run the following commands: 

```shell
$ cargo +stable install cbindgen cargo-fuzz
$ cargo +stable install --version "$(cat ../acknowledgments/cargo-about-version)" --locked cargo-about
$ cargo +stable install --version "$(cat ../.taplo-cli-version)" --locked taplo-cli
```

## Java/Android

To build for Android you must install several additional packages including a JDK,
the Android NDK/SDK, and add the Android targets to the Rust compiler, using

```rustup target add armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android```

To build the Java/Android ``jar`` and ``aar``, and run the tests:

```shell
$ cd java
$ ./gradlew test
$ ./gradlew build # if you need AAR outputs
```

You can pass `-P debugLevelLogs` to Gradle to build without filtering out debug- and verbose-level
logs from Rust.

Alternately, a build system using Docker is available:

```shell
$ cd java
$ make
```

When exposing new APIs to Java, you will need to run `rust/bridge/jni/bin/gen_java_decl.py` in
addition to rebuilding. This requires installing the `cbindgen` Rust tool, as detailed above. 

### Maven Central

Signal publishes Java packages on [Maven Central](https://central.sonatype.org) for its own use,
under the names org.signal:libsignal-server, org.signal:libsignal-client, and
org.signal:libsignal-android. libsignal-client and libsignal-server contain native libraries for
Debian-flavored x86_64 Linux as well as Windows (x86_64) and macOS (x86_64 and arm64).
libsignal-android contains native libraries for armeabi-v7a, arm64-v8a, x86, and x86_64 Android.

When building for Android you need *both* libsignal-android and libsignal-client, but the Windows
and macOS libraries in libsignal-client won't automatically be excluded from your final app. You can
explicitly exclude them using `packagingOptions`:

```
android {
  // ...
  packagingOptions {
    resources {
      excludes += setOf("libsignal_jni*.dylib", "signal_jni*.dll")
    }
  }
  // ...
}
```

You can additionally exclude `libsignal_jni_testing.so` if you do not plan to use any of the APIs
intended for client testing.


## Swift

To learn about the Swift build process see [``swift/README.md``](swift/)


## Node

You'll need Node installed to build. If you have [nvm][], you can run `nvm use` to select an
appropriate version automatically.

We use `npm` as our package manager, and `node-gyp` to control building the Rust library.

```shell
$ cd node
$ nvm use
$ npm install
$ npx node-gyp rebuild  # clean->configure->build
$ npm run tsc
$ npm run test
```

When testing changes locally, you can use `npm run build` to do an incremental rebuild of the Rust library. Alternately, `npm run build-with-debug-level-logs` will rebuild without filtering out debug- and verbose-level logs.

When exposing new APIs to Node, you will need to run `rust/bridge/node/bin/gen_ts_decl.py` in
addition to rebuilding.

[nvm]: https://github.com/nvm-sh/nvm

### NPM

Signal publishes the NPM package `@signalapp/libsignal-client` for its own use, including native
libraries for Windows, macOS, and Debian-flavored Linux. Both x64 and arm64 builds are included for
all three platforms, but the arm64 builds for Windows and Linux are considered experimental, since
there are no official builds of Signal for those architectures.


# Contributions

Signal does accept external contributions to this project. However unless the change is
simple and easily understood, for example fixing a bug or portability issue, adding a new
test, or improving performance, first open an issue to discuss your intended change as not
all changes can be accepted.

Contributions that will not be used directly by one of Signal's official client apps may still be
considered, but only if they do not pose an undue maintenance burden or conflict with the goals of
the project.

Signing a [CLA (Contributor License Agreement)](https://signal.org/cla/) is required for all contributions.

## Code Formatting and Acknowledgments

You can run the styler on the entire project by running:

```shell
just format-all
```

You can run more extensive tests as well as linters and clippy by running:

```shell
just check-pre-commit
```

When making a PR that adjusts dependencies, you'll need to regenerate our acknowledgments files. See [``acknowledgments/README.md``](acknowledgments/).

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

Copyright 2020-2024 Signal Messenger, LLC

Licensed under the GNU AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
