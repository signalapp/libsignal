v0.67.0

- Net: expose old and new CDSI connect logic.
- Net: support uppercase scheme for proxy URL.
- Net: retire an old SVR2 enclave.
- Net: expose synchronous API for sending ChatConnection response.
- Net: improve the handling of Chat errors and the associated messages and error
       codes. This is a breaking change for Swift: a request that times out now
       produces a `SignalError.requestTimeoutError(_:)` instead of
       `SignalError.connectionTimeoutError(_:)`.
