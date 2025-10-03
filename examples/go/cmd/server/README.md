# Signal Demo HTTP Server

This example exposes a minimal HTTP API that demonstrates how the Go bindings interact with the in-memory Signal helper types inside the repo. The server keeps a lightweight database in memory, so it is best used for local/testing purposes.

## What It Does

- Handles user registration and login with short-lived session tokens.
- Stores pre-key bundles per `{user, device}` so peers can establish secure sessions.
- Queues encrypted messages for offline delivery and lets clients drain their inbox.
- Logs every request (including request bodies) to help troubleshoot API calls.

The storage layer lives entirely in `main.go` and is intentionally simple: a
`memoryStore` struct holds users, bundles, queues, and sessions guarded by a RW
mutex.

## Prerequisites

1. Build the Rust `signal-c-binding` shim in release mode (produces the static
   archive consumed by the Go example):
   ```bash
   cargo build -p signal-c-binding --release
   ```
2. Run Go commands with an explicit build cache inside the repository to avoid
   `$HOME` permissions issues when running in sandboxes:
   ```bash
   export GOCACHE=$(pwd)/examples/go/.gocache
   ```

## Running the Server

```bash
GOCACHE=$(pwd)/examples/go/.gocache go run ./examples/go/cmd/server --listen :8080
```

The `--listen` flag is optional; it defaults to `:8080`. On startup the server
prints each HTTP request twice: once with the method/path/body and once after
the handler finishes with latency information.

## API Overview

| Method | Path                           | Purpose                                    |
| ------ | ------------------------------ | ------------------------------------------ |
| POST   | `/v1/register`                 | Create a new `{name, password}` account.   |
| POST   | `/v1/login`                    | Issue an `X-Session-Token` for a device.   |
| POST   | `/v1/devices/{name}/{id}/bundle` | Upload the caller's pre-key bundle.        |
| GET    | `/v1/devices/{name}/{id}/bundle` | Fetch a bundle to start a session.         |
| POST   | `/v1/messages`                 | Queue an encrypted message for a peer.     |
| GET    | `/v1/messages/{name}/{id}`     | Drain pending messages for a device.       |

Protected endpoints require the `X-Session-Token` header returned by `/v1/login`.
Handlers respond with JSON payloads and standard HTTP status codes.

## Typical Flow

1. Client registers a username/password via `/v1/register`.
2. Client logs in on a device, receiving a session token and publishing its
   bundle through `/v1/devices/.../bundle`.
3. When sending, the client fetches the peer's bundle (if necessary), encrypts
   the message locally, and POSTs the ciphertext to `/v1/messages`.
4. The recipient periodically calls `/v1/messages/{name}/{id}` to retrieve and
   decrypt queued messages.

Refer to `examples/go/cmd/client/README.md` (or run the CLI) for a convenient
way to drive these endpoints interactively.
