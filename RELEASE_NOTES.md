v0.89.2

- Expose getUploadForm() to clients (for attachments)

- A 508 response when connecting to a Signal service will result in backoff for reconnect attempts on all routes, not just the one that reached the server.

- Ensure outstanding gRPC requests are cancelled when a connection is disconnected or dropped.

- Protocol: Update the `spqr` dependency to v1.5.1
