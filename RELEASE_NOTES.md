v0.101.1

- Typescript targets ES2025
- backups: Add support for new notification settings
- gRPC-level errors are treated as transport errors if there is no more specific classification. (Previously they were "unexpected, likely-indicates-a-bug" errors.)
