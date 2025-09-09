v0.80.1

- Sealed sender SenderCertificates can now use a `bytes` representation for the sender, and may avoid embedding their signing ServerCertificate in favor of referencing a "known" certificate baked into libsignal. See sealed_sender.proto and the `KNOWN_SERVER_CERTIFICATES` list in the source for more details.
