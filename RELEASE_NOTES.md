v0.89.2

- A 508 response when connecting to a Signal service will result in backoff for reconnect attempts on all routes, not just the one that reached the server.

- Protocol: Update the `spqr` dependency to v1.5.1

- Expose getUploadForm() to clients (for attachments)

