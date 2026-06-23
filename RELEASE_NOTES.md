v0.96.3

- node: Generate attestation for published packages

- Add setDeviceName() typed API

- protocol: Fix encoded type byte for ML-KEM-1024 keys and ciphertexts (previously they were misidentified as Kyber-1024, which is wire-compatible but with a different interpretation). Fortunately ML-KEM-1024 is not currently used by Signal in this way, so there will be no actual keys or ciphertexts with the "wrong" value on real devices.
