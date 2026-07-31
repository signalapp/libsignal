v0.99.3

- zkgroup: AuthCredentialWithPni can now be issued *without* a PNI; instead, a structurally valid "false PNI" will be derived from the ACI and a server-provided salt, which the encrypted presentation will not distinguish from a user with a real PNI.
