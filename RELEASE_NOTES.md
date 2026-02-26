v0.87.5

- SPQR: upgrade to v1.5.0.

- iOS: 5xx responses to typed chat APIs are now treated as retryable `ioError`s rather than `networkProtocolError`s.

- Log hashes of TLS certs on verification failure

- Treat HTTP/2 transport errors disinct from gRPC status

- backup: Support iOS specific settings in account data.
