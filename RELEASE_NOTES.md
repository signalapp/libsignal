v0.87.0

- Expose accountExists() API to client libraries

- Expose "grpc.AccountsAnonymousLookupUsernameHash" remote config key. When enabled, the typed chat API `lookUpUsernameHash` will use gRPC instead of the default websocket-based implementation. This has no effect if "useH2ForUnauthChat" is unset, or if an H2 connection cannot be established for some other reason.

- Updated Kotlin and Android Gradle Plugin versions.

- Remove PublicKey ordered comparsion

