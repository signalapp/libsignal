v0.98.1

- Add a new post-connect callback to ChatConnectionListener to report the server's current clock time (as a Signal timestamp, "milliseconds since the Unix epoch").
  - Java: `onServerTimestamp`
  - Node: `onServerTimestamp`
  - Swift: `chatConnection(_:reportedServerTimestamp:)`
- New typed APIs:
  - UnauthBackupsService.deleteBackupMedia()
