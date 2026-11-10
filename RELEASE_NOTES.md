v0.107.0

- BackupJsonExporter.export_frames now sanitizes certain information, such as some keys, as a defense-in-depth measure.
  It also now returns (per-frame) validator errors if a disappearing message or view-once attachment is included.

- SVRB: resurrect support for Nitro enclaves (no enclaves yet trusted)

- Java: `GroupCipher.decrypt` now throws InvalidVersionException and InvalidKeyException, and `SessionCipher.decrypt(PreKeySignalMessage)` now throws InvalidVersionException, instead of wrapping them in an AssertionError.
  Callers will need to handle or declare the new checked exceptions.
