v0.86.0

- Java artifacts are now published to GitHub Package Registry rather than Maven Central. See the instructions for [Gradle][] and [Maven][]. (No authentication should be necessary.)

- java: Remove protocol.util.Pair in favor of kotlin.Pair

- Node: export libsignal-net remote config keys as an array.

- The deprecated overloads of `KyberPreKeyStore.markKyberPreKeyUsed` have been removed in Java and Swift. (TypeScript does not have overloads.) They were originally marked deprecated in v0.81.0.

- Android: The min SDK version is now 23.

- Bump minimum macOS version to 12


[Gradle]: https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-gradle-registry#using-a-published-package
[Maven]: https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry#installing-a-package
