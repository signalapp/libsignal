# Signal Demo CLI Client

This command-line client drives the demo HTTP server in
`examples/go/cmd/server`. It manages registration, login, bundle uploads, and
encrypted messaging using the Go FFI wrappers for the Signal protocol.

## Prerequisites

1. Build the Rust `signal-c-binding` shim so the Go bindings can link against
   it:
   ```bash
   cargo build -p signal-c-binding --release
   ```
2. Export a build cache inside the repository (optional but avoids sandbox
   issues):
   ```bash
   export GOCACHE=$(pwd)/examples/go/.gocache
   ```
3. Start the demo server in another terminal:
   ```bash
   $GOCACHE go run ./examples/go/cmd/server --listen :8080
   ```

## Running the Client

Launch the interactive CLI (it defaults to `http://localhost:8080`):

```bash
$GOCACHE go run ./examples/go/cmd/client --server http://localhost:8080
```

Multiple instances can run simultaneously—start one per user/device.

## Top-Level Menu

After startup you can choose:

- `register` – create a username/password.
- `login` – authenticate, choose a device ID (1–127), and publish your bundle.
- `exit` – quit the program.

## Session Commands

Successful login drops you into a `session>` prompt. Available commands:

- `send <user> <device> <message>` – ensure the peer bundle is fetched, then
  encrypt and queue the message for that specific device.
- `sendall <user> <message>` – broadcast to every known device for the peer
  (devices are learned from previous exchanges).
- `refresh` – pull pending ciphertexts from the server, decrypt them locally,
  and print `[peer/device] message` lines.
- `logout` – close the session and return to the main menu.

Use two terminals to log in as different users and experiment with encrypted
round-trips through the server.
