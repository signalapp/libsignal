# signal-c-binding

Minimal C-facing shim around libsignal core types for Go experiments.

## Build

```
cargo build -p signal-c-binding --release
```

## Header generation

```
cbindgen --crate signal-c-binding --output signal_c_binding.h
```

## Exposed helpers

- `signalgo_identity_keypair_generate` / `signalgo_identity_keypair_free`
- `signalgo_protocol_store_new` to construct an in-memory Signal store
- `signalgo_store_generate_prekey_bundle` to create and retain EC/PQ pre-keys
- `signalgo_store_process_prekey_bundle` to initialise a session from a remote bundle
- `signalgo_store_encrypt_message`, `signalgo_store_decrypt_signal_message`, `signalgo_store_decrypt_prekey_message`
- `signalgo_buffer_free` to release byte buffers returned by Rust

## Example cgo usage

```go
// #cgo CFLAGS: -I${SRCDIR}/..
// #cgo LDFLAGS: -L${SRCDIR}/../target/release -lsignal_c_binding -ldl -lpthread
// #include "signal_c_binding.h"
import "C"

// Wrap the raw pointers returned from the Rust API in Go types and add
// finalizers that call the corresponding `signalgo_*_free` routines.
```

Adjust the `cbindgen` invocation if you need a different profile. Use the generated static library (`target/release/libsignal_c_binding.a`) with cgo by adding it to `#cgo LDFLAGS` and including the header from `signal_c_binding.h`.
