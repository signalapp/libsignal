# Copilot Instructions for libsignal

## Quick Reference

### Build Commands
- **Rust only**: `cargo build` (builds all default workspace members)
- **Single Rust crate**: `cargo build -p CRATE_NAME`
- **Java/Android**: `cd java && ./gradlew build`
- **Swift**: `cd swift && swift build` (requires `swift/build_ffi.sh` first)
- **Node/TypeScript**: `cd node && npm run build`

### Test Commands
- **Rust (all)**: `cargo test --workspace --all-features`
- **Rust (single crate)**: `cargo test -p CRATE_NAME`
- **Java**: `cd java && ./gradlew test`
- **Swift**: `cd swift && swift test` (requires `swift/build_ffi.sh` first)
- **Node**: `cd node && npm run test`

### Linting & Formatting
- **Check all formatting**: `just check-format-all` (Rust, Java, Swift, TypeScript)
- **Auto-format all**: `just format-all`
- **Format individual languages**:
  - Rust: `cargo fmt`
  - Java: `cd java && ./gradlew spotlessApply`
  - Swift: `cd swift && swift format --in-place --parallel --recursive .`
  - TypeScript: `cd node && npm run format`

### Bridge Code Generation
Generate API declarations when modifying bridged functions:
- **All bridges**: `just generate-bridge`
- **Java only**: `just generate-jni` (requires `cbindgen` installed)
- **Swift only**: `just generate-ffi`
- **TypeScript only**: `just generate-node`

After running these, rebuild the affected language library and test.

## Architecture Overview

libsignal is a **multi-language crypto library** with Rust implementations exposed to Java, Swift, and TypeScript through language-specific bindings.

### Core Organization

- **rust/**: Core Rust crates (protocol, crypto, attestation, etc.)
  - Implemented as individual workspace members (see `Cargo.toml` for list)
  - Default members are those exposed to app languages
  - Bridge crates (`rust/bridge/`) are internal and NOT part of the public API

- **rust/bridge/**: Language-specific binding layer
  - `shared/`: Common bridging infrastructure (`#[bridge_fn]` macros, type conversions)
  - `ffi/`: C interface (used by Swift)
  - `jni/`: Java/Kotlin interface via JNI
  - `node/`: TypeScript/Node.js interface via N-API

- **java/**, **swift/**, **node/**: App language implementations
  - Each wraps the corresponding Rust bridge
  - Published as Maven packages (Java), CocoaPods (Swift), and NPM (Node)

### Data Flow Example

User code → TypeScript API → Node bridge (type conversion) → Rust bridge fn → Core Rust crate → Result → Node bridge (conversion) → TypeScript API

## Key Conventions

### Bridge Functions

Use the `#[bridge_fn]` macro in `rust/bridge/shared/src/` to expose Rust functions:

```rust
#[bridge_fn]
pub fn some_function(input: String) -> Result<String, SignalError> {
    // Implementation
}
```

- Function names must be unique across all bridges
- Use `#[bridge_io]` for async functions
- Return types must implement `ResultTypeInfo` for each language
- Parameter types must implement `ArgTypeInfo` for each language

After modifying bridge signatures, run `just generate-bridge` to regenerate API declarations.

### Type Conversions

When adding new types to bridge APIs:

1. Implement `ArgTypeInfo` (for input parameters) and `ResultTypeInfo` (for return values) in `rust/bridge/shared/types/`
2. Add the type to the `ffi_arg_type!`, `jni_arg_type!`, and `node_arg_type!` macros
3. Use **fully qualified names** for non-std, non-libsignal types in signatures (except `uuid::Uuid` which has a convention exemption)

### Error Handling

- Prefer `expect()` over `unwrap()` for error messages that explain why panic shouldn't happen
- Errors are caught and reported to apps as recoverable errors
- Panics are trapped and converted to appropriate language-native errors

### Logging

**User data must never appear in logs** (including error stringifications at default log levels):

- ❌ Don't log unencrypted usernames, identity keys, or PINs
- ✓ Ephemeral public keys, ServiceIds, and ProtocolAddresses are safe (fixed formats)
- Debug/verbose logs are stripped at compile time in release builds, so they can be less restrictive

Only use "error" level for actual bugs; network failures should be "warning".

### No Multi-Version Crates

Avoid including multiple versions of the same crate in final builds (code size concern). This is checked in CI by `bin/verify_duplicate_crates`.

### Async Patterns

Prefer `tokio::select!` over `futures::select!` because it doesn't require `FusedFuture` and is less error-prone in loops.

### Dependency Management

- Install Rust tools from cargo, not system package managers (they may be outdated and break the build)
- Avoid `cargo add` or fix up `Cargo.toml` afterwards—dependency lists are organized and `cargo add` doesn't respect that
- Version pinning: workspace uses nightly; stable support is maintained with MSRV checked in CI

### Testing Philosophy

Every change should have tests (or justify why it doesn't). Missing tests for language-specific paths have caused bugs; all three app languages need coverage even though primary testing is in Rust.

## Workspace Structure

**Default members** (these are the public APIs):
- `rust/crypto`, `rust/protocol`, `rust/zkgroup`, `rust/zkcredential`, `rust/poksho`
- `rust/attest`, `rust/usernames`, `rust/device-transfer`, `rust/account-keys`
- `rust/message-backup`, `rust/media`

**Bridge members** (internal only):
- `rust/bridge/ffi`, `rust/bridge/jni`, `rust/bridge/node`

Other workspace members like `rust/net` are infrastructure crates.

## Pre-Commit Checks

Before pushing, run:

```shell
just check-pre-commit
```

This runs all formatters, clippy, tests, and additional validation. Use `just --list` to see individual recipes.

## Platform-Specific Notes

- **macOS setup**: Run `bin/mac_setup.sh` to install Rust toolchain dependencies
- **ARM64 profiling**: Compile with `RUSTFLAGS="--cfg aes_armv8"` for hardware AES support in the `aes` crate
- **Android testing**: See TESTING.md for setting up `adb-run-test`
- **iOS Simulator**: See TESTING.md for configuring `CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUNNER`

## Documentation

- High-level architecture: See `rust/bridge/README.md`
- Detailed testing setups: See `TESTING.md`
- Code priorities and style: See `CODING_GUIDELINES.md`
- Release process: See `RELEASE.md`
