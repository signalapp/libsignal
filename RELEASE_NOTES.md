v0.87.2

- Expose "grpc.AccountsAnonymousLookupUsernameLink" remote config key. When enabled, the typed chat API `lookUpUsernameLink` will use gRPC instead of the default websocket-based implementation. This has no effect if "useH2ForUnauthChat" is unset, or if an H2 connection cannot be established for some other reason.

- Panic on integer overflow, even in release mode

- keytrans: Include search key and distinguished tree last update time in stored account data
