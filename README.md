# Overview

libsignal-client is an implementation of the Signal client in Rust.

Work in progress.  Subject to change without notice, use outside Signal not yet recommended.

# Building

To build anything in this repository you must have Rust installed. The build currently
uses a specific version of the Rust nightly compiler, which will be downloaded
automatically by cargo. To build and test the basic protocol libraries:

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

## Swift

To learn about the Swift build process see ``swift/README.md``

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

Copyright 2020 Signal Messenger, LLC

Licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
