# @aspect-build/react-native-libsignal

React Native bindings for [libsignal-client](https://github.com/nicegram/nicegram-libsignal), providing Signal Protocol cryptographic operations via JSI (JavaScript Interface) for high-performance native bridge calls.

## Features

- **438 JSI-bound functions** — full coverage of the libsignal C FFI API
- **25 async functions** with CPromise→JS Promise bridge via CallInvoker
- **Type-safe TypeScript API** with classes for keys, encryption, fingerprints, etc.
- **JSI-based** — synchronous native calls without React Native bridge overhead
- **Android support** (arm64-v8a + x86_64)

## Requirements

- React Native ≥ 0.71.0
- Android API 24+ (Android 7.0+)
- Android NDK 27.1.12297006
- Java 17+ (for building)

## Installation

### Option A: npm package (recommended)

```bash
npm install @aspect-build/react-native-libsignal
# or
yarn add @aspect-build/react-native-libsignal
```

Since this uses JSI (C++ native modules), you need to rebuild your app's native code:

```bash
cd android && ./gradlew clean assembleDebug
```

### Option B: Local file dependency

Copy the `react-native/` directory into your project and add it as a local dependency:

```json
// package.json
{
  "dependencies": {
    "@aspect-build/react-native-libsignal": "file:./libs/react-native-libsignal"
  }
}
```

Then in your `android/settings.gradle`:

```groovy
include ':react-native-libsignal'
project(':react-native-libsignal').projectDir = new File(rootProject.projectDir, '../libs/react-native-libsignal/android')
```

And in `android/app/build.gradle`:

```groovy
dependencies {
    implementation project(':react-native-libsignal')
}
```

### Option C: AAR file

Build the AAR:

```bash
cd react-native/example/android
JAVA_HOME=/path/to/java-17 ./gradlew :aspect-build_react-native-libsignal:assembleRelease
```

The AAR will be at `react-native/android/build/outputs/aar/react-native-libsignal-release.aar`.

Copy it to your app's `android/libs/` directory and add:

```groovy
// android/app/build.gradle
dependencies {
    implementation files('libs/react-native-libsignal-release.aar')
}
```

## Setup

### 1. Initialize the module

Call `install()` once at app startup, before using any libsignal functions:

```typescript
import { install } from '@aspect-build/react-native-libsignal';

// In your App.tsx or entry point:
install();
```

### 2. Auto-linking (React Native ≥ 0.60)

The module auto-links via React Native's autolinking. No manual native configuration needed.

If autolinking doesn't work, manually register the module in `MainApplication.java`:

```java
import org.signal.libsignal.reactnative.LibsignalPackage;

@Override
protected List<ReactPackage> getPackages() {
    List<ReactPackage> packages = new PackageList(this).getPackages();
    packages.add(new LibsignalPackage());
    return packages;
}
```

## Usage

### High-Level TypeScript API

```typescript
import {
  PrivateKey,
  PublicKey,
  IdentityKeyPair,
  ProtocolAddress,
  Fingerprint,
  Aes256GcmSiv,
  hkdf,
  AccountEntropyPool,
} from '@aspect-build/react-native-libsignal';

// Generate key pairs
const privateKey = PrivateKey.generate();
const publicKey = privateKey.getPublicKey();

// Sign and verify messages
const message = new Uint8Array([1, 2, 3, 4, 5]);
const signature = privateKey.sign(message);
const isValid = publicKey.verify(message, signature); // true

// ECDH key agreement
const alice = PrivateKey.generate();
const bob = PrivateKey.generate();
const sharedSecret = alice.agree(bob.getPublicKey());

// Serialize/deserialize keys
const serialized = publicKey.serialize(); // Uint8Array (33 bytes)
const deserialized = PublicKey.deserialize(serialized);
console.log(publicKey.equals(deserialized)); // true

// Identity key pairs
const identity = IdentityKeyPair.generate();
const identityBytes = identity.serialize();

// Protocol addresses
const address = ProtocolAddress.new('+14155550100', 1);
console.log(address.name());     // '+14155550100'
console.log(address.deviceId()); // 1

// Fingerprint verification
const fingerprint = Fingerprint.new(
  1024, 1,
  localIdentifier, alice.getPublicKey(),
  remoteIdentifier, bob.getPublicKey()
);
console.log(fingerprint.displayableFingerprint().toString());

// AES-256-GCM-SIV encryption
const key = new Uint8Array(32); // your 32-byte key
const nonce = new Uint8Array(12); // 12-byte nonce
const cipher = Aes256GcmSiv.new(key);
const encrypted = cipher.encrypt(plaintext, nonce);
const decrypted = cipher.decrypt(encrypted, nonce);

// HKDF key derivation
const derived = hkdf(32, inputKeyMaterial, info, salt);

// Account entropy pool
const pool = AccountEntropyPool.generate();
const backupKey = pool.deriveBackupKey();
```

### Low-Level Native API

For operations not covered by the high-level API, access the raw JSI bindings:

```typescript
import { install, Native } from '@aspect-build/react-native-libsignal';

install();

// Access __libsignal_native global directly
declare const __libsignal_native: any;

// All 438 FFI functions are available
const result = __libsignal_native.SomeFunction_Name(arg1, arg2);
```

See `ts/Native.ts` for the complete list of available functions and their type signatures.

## Architecture

```
TypeScript API (ts/index.ts, ts/EcKeys.ts, ...)
    ↓ calls
JSI HostObject (__libsignal_native)
    ↓ dispatches to
C++ JSI bindings (cpp/generated_jsi_bindings.cpp)
    ↓ calls
Rust FFI (libsignal_ffi.so via signal_ffi.h)
    ↓ implements
Core Rust crypto (libsignal-protocol, etc.)
```

- **Sync functions**: Direct JSI calls — no bridge overhead, immediate return
- **Async functions**: Return JS Promises. Rust async operations run on a Tokio runtime, and results are dispatched back to the JS thread via React Native's CallInvoker

## Building from Source

### Prerequisites

```bash
# Rust toolchain (for building libsignal_ffi.so)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add aarch64-linux-android x86_64-linux-android

# Android NDK
# Set ANDROID_NDK_HOME to your NDK installation
```

### Build Steps

```bash
# 1. Build the Rust FFI library for Android
cd react-native && bash scripts/build_android.sh

# 2. Generate JSI bindings from the C header
python3 scripts/gen_jsi_bindings.py cpp/signal_ffi.h cpp/generated_jsi_bindings.cpp ts/Native.ts

# 3. Build TypeScript
npm run build

# 4. Build the AAR
cd example/android
JAVA_HOME=/path/to/java-17 ./gradlew :aspect-build_react-native-libsignal:assembleRelease
```

### Regenerating Bindings

If the `signal_ffi.h` header changes (e.g., after updating libsignal):

```bash
cd react-native
python3 scripts/gen_jsi_bindings.py cpp/signal_ffi.h cpp/generated_jsi_bindings.cpp ts/Native.ts
npm run build
```

## Testing

The example app includes 26 integration tests covering:

- Module installation and JSI setup
- Key generation, serialization, deserialization
- Ed25519 signing and verification
- ECDH key agreement
- HKDF key derivation
- AES-256-GCM-SIV encryption/decryption
- Fingerprint generation
- Async infrastructure (TokioAsyncContext, Promise creation)
- High-level TypeScript API wrappers

```bash
# Build and run tests on emulator
cd react-native/example
npx react-native bundle --platform android --dev false \
  --entry-file index.js \
  --bundle-output android/app/src/main/assets/index.android.bundle
cd android && ./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.libsignaltestapp/.MainActivity
adb logcat -s ReactNativeJS  # Watch for test results
```

## Limitations

- **iOS**: Not yet implemented (requires macOS for building)
- **Store callbacks**: `SessionStore`, `PreKeyStore`, etc. are not implemented — these require bidirectional JS↔Rust callback plumbing. Apps needing session management should implement their own storage layer.
- **Network-dependent async functions**: Chat connections, CDSI lookup, and registration functions require a Signal server connection and appropriate credentials.
- **ABIs**: Only `arm64-v8a` and `x86_64` are built (covers all modern devices and emulators)

## License

AGPL-3.0-only — see [LICENSE](../LICENSE) for details.
