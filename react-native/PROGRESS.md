copilot --resume=7666deb5-9272-4b7e-bdf6-3d4b2cd68dd1

# React Native libsignal — Implementation Progress

This document tracks the implementation progress of React Native bindings for
libsignal. It's maintained to facilitate session handoffs and to document
technical decisions.

## Current Status: **Android AAR Builds Successfully — Needs Runtime Testing** ✅

The Android native module builds end-to-end:
- Rust FFI library (`libsignal_ffi.so`) cross-compiled for arm64-v8a and x86_64
- C++ JSI module compiles and links with React Native 0.84
- Gradle produces a 17MB AAR (`react-native-libsignal-release.aar`)
- All 12 host FFI integration tests pass
- 438 function bindings generated (413 sync + 25 async)

**Next session**: Create a React Native test app and run it on the Android emulator.
The devcontainer has been updated with emulator + system image + X11 deps.
Rebuild the devcontainer first, then proceed with creating the test app.

---

## Completed Work

### 1. Rust FFI Library (.so) — ✅ Done
- Built `libsignal_ffi.so` for `arm64-v8a` and `x86_64` using `cargo ndk`
- Added `cdylib` crate-type to `rust/bridge/ffi/Cargo.toml`
- Debug builds are ~320MB; release builds need `--release` flag (expect ~5-10MB)
- Build script: `react-native/scripts/build_android.sh`

### 2. C++ Header Compatibility — ✅ Done
- `signal_ffi.h` (from `swift/Sources/SignalFfi/`) uses C-style enum/typedef
  patterns that are invalid in C++
- Created `signal_ffi_cpp.h` via sed transformation during build
- Three enums affected: `SignalFfiPublicKeyType`, `SignalChallengeOption`,
  `SignalSvr2CredentialsResult`
- Transformation: `enum X { ... }; typedef uint8_t X;` → `enum X : uint8_t { ... };`

### 3. JSI TurboModule Infrastructure — ✅ Done
- `LibsignalTurboModule.h/cpp`: HostObject-based JSI module
- `NativePointer` class wraps FFI handles with automatic destructor cleanup
- Type conversion functions: `jsiToBuffer`, `bufferToJsi`, `jsiToString`,
  `jsiToServiceId`, `jsiToSliceOfBuffers`, `jsiToSliceOfPointers<T>`, etc.
- Error handling: every FFI call checks for `SignalFfiError*` and throws JSI error

### 4. Code Generation (`gen_jsi_bindings.py`) — ✅ Done
- Parses `signal_ffi.h` to generate C++ JSI wrappers
- Handles: primitives, buffers, strings, fixed-size arrays, owned buffers,
  native pointers (wrapped in HostObject), service IDs
- Skips: destroy/clone/free functions, callback structs, error inspection,
  testing-only functions, unconvertible parameter types
- Output: 419 sync + 25 async functions, 132 skipped
- 162 functions couldn't be matched to JS names from `node/ts/Native.ts`
  (uses generated camelCase names instead — may cause runtime mismatches)

### 5. Android Platform Files — ✅ Done
- `android/build.gradle`: Android library with CMake + prefab
- `android/CMakeLists.txt`: Links against libsignal_ffi.so and ReactAndroid
- `android/src/main/java/.../LibsignalModule.java`: JNI bridge
- `android/src/main/java/.../LibsignalPackage.java`: React Native package
- `android/src/main/cpp/jni_install.cpp`: JNI_OnLoad entry point

### 6. Test Infrastructure — ✅ Done
- `tests/CMakeLists.txt`: Two targets (host FFI tests + JSI compilation check)
- `tests/test_ffi_host.cpp`: 8 integration tests covering key ops, crypto, etc.
- `scripts/run_tests.sh`: Automated test runner script
- All tests pass; JSI bindings compile cleanly

### 7. Android NDK Cross-Compilation Verification — ✅ Done
- Both `.cpp` files compile with `aarch64-linux-android21-clang++`
- Linked into a standalone `.so` (15MB) with `--allow-shlib-undefined`
  for JSI/ReactAndroid symbols (resolved at app load time)

### 8. Android Gradle/AAR Build — ✅ Done
- Full `./gradlew assembleRelease` succeeds
- Produces `react-native-libsignal-release.aar` (17MB)
- Contains both arm64-v8a and x86_64 native libraries
- `liblibsignal-react-native.so` is 1.2MB per architecture
- `libsignal_ffi.so` is 13MB (arm64) / 15MB (x86_64) stripped release

### 9. Missing Symbol Resolution — ✅ Done
- Template functions moved from `.cpp` to `.h` for proper instantiation
- Media sanitizer functions (8 total) skipped in codegen (feature not enabled)
- Added `jsiToBytestringArray()` implementation for packed string arrays

---

## Remaining Work

### Next Session (immediate)
1. **Rebuild devcontainer** — Updated Dockerfile adds emulator, system image,
   X11/display libs, `libprotobuf-dev`, and KVM passthrough
2. **Create React Native test app** — `npx @react-native-community/cli init`
   with the libsignal module linked as a local dependency
3. **Run on Android emulator** — Start emulator, build & install test app,
   verify JSI functions work at runtime

### High Priority (MVP)
4. **Fix function name matching**: 47 generated JS names may not match what
   the TypeScript layer expects (rest are skipped functions)
5. **Async function support**: 25 CPromise-based functions are stub-only;
   need React Native's `CallInvoker` for proper JS thread callbacks

### Medium Priority
6. **Store/callback implementations**: `SessionStore`, `IdentityKeyStore`,
   `PreKeyStore`, `SenderKeyStore` need hand-written JSI implementations
   (callback structs can't be auto-generated)
7. **Additional ABIs**: Build for `armeabi-v7a` and `x86` (currently only
   arm64-v8a and x86_64)
8. **TypeScript layer**: Complete `Native.ts` and `index.ts` with proper
   type-safe wrappers
9. **AAR packaging**: Exclude ReactAndroid .so files from AAR (they come from
   the app's React Native dependency at build time)

### Lower Priority
10. **iOS implementation**: Requires Mac for building; architecture is similar
    (uses same `signal_ffi.h` and C++ module)
11. **CI integration**: Add GitHub Actions workflow for automated builds/tests

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│ JavaScript / TypeScript                          │
│  import { install } from 'react-native-libsignal'│
│  install() → NativeModules.Libsignal.install()   │
│  globalThis.__libsignal.signal_*_function(...)   │
└──────────────────┬──────────────────────────────┘
                   │ JSI (synchronous C++ calls)
┌──────────────────▼──────────────────────────────┐
│ C++ TurboModule (LibsignalTurboModule)           │
│  - HostObject installed as __libsignal global    │
│  - 419 sync + 25 async JSI wrappers              │
│  - NativePointer handles (GC → signal_*_destroy) │
│  - Type conversion: JS ↔ C FFI types             │
└──────────────────┬──────────────────────────────┘
                   │ C function calls
┌──────────────────▼──────────────────────────────┐
│ libsignal_ffi.so (Rust → C API via cbindgen)     │
│  - Protocol operations (sessions, keys, etc.)    │
│  - Crypto primitives (AES, HKDF, ECDH, etc.)    │
│  - Account management, attestation, etc.         │
└─────────────────────────────────────────────────┘
```

---

## Technical Decisions & Rationale

### Why JSI (not NativeModules/Bridge)?
- Synchronous C++ calls avoid bridge serialization overhead
- Direct pointer passing for crypto operations (no base64 encoding)
- HostObject GC integration for automatic resource cleanup

### Why fork codegen from signal_ffi.h (not node/Native.ts)?
- The C header is the single source of truth for the FFI API
- Node.js uses N-API (different ABI from JSI)
- Codegen ensures 1:1 mapping between C functions and JS wrappers

### Why signal_ffi_cpp.h instead of modifying cbindgen config?
- Upstream cbindgen config generates valid C; changing it could break Swift/iOS
- sed transformation is simple, deterministic, and runs during build
- Only 3 enums need transformation

### Why HostObject (not TurboModule spec)?
- TurboModule codegen requires typed specs that don't match our dynamic API
- HostObject gives full control over property/function dispatch
- `global.__libsignal` pattern matches how other JSI libraries work

---

## Environment Requirements

### Build Dependencies
- Rust nightly (see `rust-toolchain` file)
- Android NDK 27.x (via `ANDROID_HOME`)
- `cargo-ndk`: `cargo install cargo-ndk`
- Android targets: `rustup target add aarch64-linux-android x86_64-linux-android`
- Python 3 (for codegen)
- CMake 3.13+ (for tests)
- `protobuf-compiler` + `libprotobuf-dev` (for Rust build — provides well-known .proto files)

### Devcontainer
All build dependencies are pre-installed in `.devcontainer/Dockerfile`.
The devcontainer also includes:
- Android emulator + x86_64 system image (API 35)
- Pre-configured AVD (`test_device`)
- KVM passthrough via `--device=/dev/kvm` (if host supports it)
- X11/display libraries for headless emulator operation

To rebuild the devcontainer after changes:
```
Ctrl+Shift+P → Dev Containers: Rebuild Container
```

### Running Tests
```bash
cd react-native
./scripts/run_tests.sh           # Full suite (builds Rust first)
./scripts/run_tests.sh --skip-rust-build  # Skip Rust build step
npm test                          # Same as --skip-rust-build
```

### Building Android .so
```bash
cd react-native
./scripts/build_android.sh                          # Debug build, all ABIs
./scripts/build_android.sh --release --strip        # Release build, stripped
./scripts/build_android.sh --release --strip --abi arm64-v8a  # Single ABI
```

### Regenerating Bindings
```bash
cd react-native
npm run codegen
# Or directly:
python3 scripts/gen_jsi_bindings.py \
    ../swift/Sources/SignalFfi/signal_ffi.h \
    cpp/generated_jsi_bindings.cpp \
    ../node/ts/Native.ts
```

---

## File Inventory

```
react-native/
├── package.json                  # NPM package config
├── tsconfig.json                 # TypeScript config
├── PROGRESS.md                   # This file — implementation status
├── .gitignore                    # Excludes build artifacts
├── ts/
│   ├── Native.ts                 # Low-level JS function declarations
│   └── index.ts                  # Public API entry point
├── cpp/
│   ├── LibsignalTurboModule.h    # JSI module header (templates inline)
│   ├── LibsignalTurboModule.cpp  # JSI module implementation
│   ├── generated_jsi_bindings.cpp # Auto-generated (413+25 functions)
│   ├── signal_ffi.h              # Copied from swift/Sources/SignalFfi/ (gitignored)
│   └── signal_ffi_cpp.h          # C++-compatible version (generated, gitignored)
├── android/
│   ├── build.gradle              # Android library build config
│   ├── CMakeLists.txt            # CMake for ReactAndroid integration
│   ├── settings.gradle           # Gradle settings with Maven repos
│   ├── gradlew                   # Gradle wrapper (from java/)
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── cpp/jni_install.cpp   # JNI → JSI bridge
│   │   └── java/org/signal/libsignal/reactnative/
│   │       ├── LibsignalModule.java
│   │       └── LibsignalPackage.java
│   └── jniLibs/                  # Cross-compiled Rust .so files (gitignored)
│       ├── arm64-v8a/libsignal_ffi.so
│       └── x86_64/libsignal_ffi.so
├── scripts/
│   ├── gen_jsi_bindings.py       # C header → C++ JSI codegen
│   ├── patch_header_cpp.py       # C → C++ header compatibility transform
│   ├── build_android.sh          # Android cross-compilation script
│   └── run_tests.sh              # Test runner
└── tests/
    ├── CMakeLists.txt            # Test build config
    └── test_ffi_host.cpp         # Host FFI integration tests (12 tests)
```
