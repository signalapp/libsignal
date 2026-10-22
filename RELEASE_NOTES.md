v0.106.0

- protocol: Session management now uses Tahini instead of Sesame. Archived
  sessions are never made active again, a tiebreaker is used to pick an active
  session in common race conditions, and conversations that keep switching back
  and forth between sessions are detected and settled. There are no wire format
  changes. Session records gain new fields but are readable by earlier libsignal
  versions.
- protocol: Each session record now keeps at most 3 archived sessions
  (previously 40). Records with more are trimmed the next time a new session is
  archived.
- Rust: `process_prekey` is no longer public and `message_decrypt_prekey` now
  returns a `PreKeyDecryptResult` instead of a `Vec<u8>`. There is a new export:
  `initiate_session`. Java, Swift, and Typescript APIs are unchanged.


