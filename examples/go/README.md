# Go FFI Example

This directory contains Go helpers that exercise the `signal-c-binding` shim:

- `go run ./examples/go` keeps the original in-process demo.
- `go run ./examples/go/cmd/server` starts a small HTTP server with registration, login, pre-key storage, and message queues.
- `go run ./examples/go/cmd/client` is an interactive CLI you can run for each user/device to register, log in, and exchange messages through the server.

## Prerequisites

1. Build the Rust shim (outputs `libsignal_c_binding.a` in `target/release`):
   ```bash
   cargo build -p signal-c-binding --release
   ```
2. Run the Go example with an in-repo build cache to avoid `$HOME` permission issues:
   ```bash
   GOCACHE=$(pwd)/examples/go/.gocache go run ./examples/go
   ```

The program prints the ciphertext type/size and the decrypted plaintext once the round-trip succeeds.

## Running the HTTP server demo

1. In one terminal start the server (it listens on `:8080` by default):
   ```bash
   GOCACHE=$(pwd)/examples/go/.gocache go run ./examples/go/cmd/server
   ```
2. In two additional terminals run the interactive clients, one per user/device. For example:
   ```bash
   # Terminal 2 – register & log in Alice/device 1
   GOCACHE=$(pwd)/examples/go/.gocache go run ./examples/go/cmd/client \
     --server http://localhost:8080

   # Terminal 3 – register & log in Bob/device 1
   GOCACHE=$(pwd)/examples/go/.gocache go run ./examples/go/cmd/client \
     --server http://localhost:8080
   ```

Once running, every client instance offers a small menu:

- `1` register – choose a username/password pair.
- `2` login – authenticate, pick a device ID (1–127), and publish your bundle.
- `3` exit.

After logging in the prompt switches to `session>` with the following commands:

- `send <user> <device> <message>` – fetch that peer/device bundle if needed, establish a session, and push an encrypted Signal message through the server.
- `sendall <user> <message>` – send the plaintext to every device of that peer the client has discovered so far (devices learned from prior messages or sends).
- `refresh` – pull pending ciphertexts for the logged-in device, decrypt them, and print `[peer] message` lines.
- `logout` – tear down the local session and return to the top-level menu.

Run two client instances side-by-side, register/login with different users, and use `send`/`refresh` to watch the two-way Signal conversation flow through the shared server.
