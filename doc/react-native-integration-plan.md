# React Native Integration Plan for libsignal

## Problem Statement

The current Node bridge (`libsignal-node`) produces a Neon-based `.node` native addon that depends
on Node.js N-API. React Native on iOS and Android does **not** embed Node.js — it uses Hermes (or
JavaScriptCore) as its JS engine. Neon native addons cannot load in these runtimes.

**Goal**: Expose the same TypeScript API surface currently available in `@signalapp/libsignal-client`
to React Native apps running on iOS and Android.

## Approach: C FFI Bridge + React Native TurboModule

libsignal already has exactly the infrastructure needed:

1. **`libsignal-ffi`** (`rust/bridge/ffi/`) — A C ABI static library (`libsignal_ffi.a`) that
   exposes ~500+ functions via `extern "C"`. This is what the Swift/iOS client already uses.

2. **`libsignal-jni`** (`rust/bridge/jni/`) — A JNI shared library for Android. This is what the
   Android client already uses.

3. **The TypeScript layer** (`node/ts/`) — High-level TypeScript classes and functions that wrap
   native calls via a `Native` module.

The strategy is to create a **React Native TurboModule** (New Architecture, JSI-based) that:

- On **iOS**: Links against the same `libsignal_ffi.a` static library, calling the C functions
  directly from a C++ JSI host object.
- On **Android**: Links against a JNI shared library (like `libsignal-jni`) or alternatively
  compiles `libsignal-ffi` as a shared library and calls it via JNI→C++→FFI.
- On **JS side**: Provides a `Native` module with the same function signatures as
  `node/ts/Native.ts`, allowing the existing TypeScript wrapper layer to be reused with minimal
  modifications.

### Why This Approach

| Alternative | Why not |
|---|---|
| UniFFI / uniffi-bindgen-react-native | Would require rewriting the entire API surface with UniFFI annotations. libsignal already has its own mature bridging macro system (`#[bridge_fn]`). Starting from scratch would be enormous effort. |
| Re-wrap the Java/Swift libraries | Would require two completely separate native module implementations with no shared logic, and the TypeScript API layer couldn't be reused. |
| WASM compilation | Hermes WASM support is limited/experimental; performance of crypto in WASM is significantly worse; no access to platform networking. |
| Embed Node.js in React Native | Massive binary size, complex, defeats the purpose. |

The FFI approach is optimal because libsignal already generates the C header and static library
for iOS, and already has JNI for Android. We need only a thin C++ JSI glue layer.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  React Native App (JavaScript / TypeScript)             │
│                                                         │
│  @signalapp/libsignal-client-react-native               │
│  ├── ts/ (reused from node/ts/ with modifications)      │
│  │   ├── Native.ts  ← re-implemented to call TurboModule│
│  │   ├── index.ts   ← mostly unchanged                  │
│  │   ├── Address.ts ← Buffer → Uint8Array changes       │
│  │   └── ...                                            │
│  └── NativeLibsignal TurboModule spec                   │
├─────────────────────────────────────────────────────────┤
│  C++ TurboModule (shared across platforms)              │
│  └── LibsignalTurboModule.cpp                           │
│      Implements JSI HostObject with methods like:       │
│      PrivateKey_Generate(), PublicKey_Serialize(), etc.  │
│      Each method calls the corresponding signal_* C fn  │
├──────────────────────┬──────────────────────────────────┤
│  iOS                 │  Android                         │
│  libsignal_ffi.a     │  libsignal_jni.so                │
│  (static lib, C ABI) │  (or libsignal_ffi.so + JNI)     │
│  Built for:          │  Built for:                       │
│  - arm64-apple-ios   │  - aarch64-linux-android          │
│  - arm64-apple-ios-sim│ - x86_64-linux-android           │
│  - x86_64-apple-ios-sim│- armv7-linux-androideabi        │
└──────────────────────┴──────────────────────────────────┘
```

---

## Detailed Implementation Plan

### Phase 1: Create the React Native Package Structure

Create a new top-level directory `react-native/` (parallel to `java/`, `swift/`, `node/`):

```
react-native/
├── package.json                    # npm package: @signalapp/libsignal-client-react-native
├── tsconfig.json
├── babel.config.js
├── libsignal-client-react-native.podspec
├── android/
│   ├── build.gradle
│   ├── CMakeLists.txt
│   └── src/main/java/org/signal/libsignal/reactnative/
│       └── LibsignalModule.java    # Android TurboModule registration
├── ios/
│   └── LibsignalModule.mm          # iOS TurboModule registration
├── cpp/
│   ├── LibsignalTurboModule.h
│   ├── LibsignalTurboModule.cpp    # Shared C++ JSI implementation
│   └── signal_ffi.h                # Copied/symlinked from swift/Sources/SignalFfi/
├── src/
│   ├── specs/
│   │   └── NativeLibsignal.ts      # TurboModule codegen spec
│   └── NativeLibsignal.ts          # JS-side TurboModule loader
├── ts/                             # TypeScript API layer (derived from node/ts/)
│   ├── Native.ts                   # Re-implemented: calls TurboModule instead of node-gyp-build
│   ├── index.ts                    # Adapted: no node:buffer, no node:crypto
│   ├── Address.ts
│   ├── EcKeys.ts
│   ├── Errors.ts
│   └── ...                         # Other files from node/ts/
└── scripts/
    ├── build_ios.sh                # Build libsignal_ffi.a for iOS targets
    └── build_android.sh            # Build libsignal_jni.so for Android targets
```

### Phase 2: Build the Rust Libraries for Mobile Targets

#### 2a. iOS — Build `libsignal-ffi` as a static library

The existing `swift/build_ffi.sh` already does this. We adapt it for React Native:

```bash
#!/bin/bash
# react-native/scripts/build_ios.sh

set -euo pipefail
cd "$(dirname "$0")/../.."

# Build for device
CARGO_BUILD_TARGET=aarch64-apple-ios swift/build_ffi.sh --release

# Build for simulator (arm64 Mac)
CARGO_BUILD_TARGET=aarch64-apple-ios-sim swift/build_ffi.sh --release

# Build for simulator (x86_64 Mac)
CARGO_BUILD_TARGET=x86_64-apple-ios swift/build_ffi.sh --release

# Create xcframework or fat library for the simulator targets
lipo -create \
  target/aarch64-apple-ios-sim/release/libsignal_ffi.a \
  target/x86_64-apple-ios/release/libsignal_ffi.a \
  -output target/ios-sim/libsignal_ffi.a

# Copy the C header
cp swift/Sources/SignalFfi/signal_ffi.h react-native/cpp/signal_ffi.h
```

#### 2b. Android — Build `libsignal-ffi` as a shared library

For Android, we have two options:

**Option A (Recommended)**: Compile `libsignal-ffi` as a **cdylib** (shared library) for Android
targets and call it directly from C++ via JNI→NDK. This avoids the complexity of the full JNI
bridge.

This requires adding a new Cargo.toml or a feature flag to `rust/bridge/ffi/Cargo.toml`:

```toml
# In rust/bridge/ffi/Cargo.toml, add:
[lib]
name = "signal_ffi"
crate-type = ["staticlib", "cdylib"]  # staticlib for iOS, cdylib for Android
```

Then build:

```bash
#!/bin/bash
# react-native/scripts/build_android.sh

set -euo pipefail
cd "$(dirname "$0")/../.."

export RUSTFLAGS="--cfg aes_armv8 ${RUSTFLAGS:-}"

for TARGET in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android; do
    cargo build -p libsignal-ffi --release --target "$TARGET"
done

# Copy outputs to android jniLibs structure
mkdir -p react-native/android/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}
cp target/aarch64-linux-android/release/libsignal_ffi.so react-native/android/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/libsignal_ffi.so react-native/android/src/main/jniLibs/armeabi-v7a/
cp target/x86_64-linux-android/release/libsignal_ffi.so react-native/android/src/main/jniLibs/x86_64/
cp target/i686-linux-android/release/libsignal_ffi.so react-native/android/src/main/jniLibs/x86/
```

**Option B**: Use the existing `libsignal-jni` unchanged. This would require the React Native
module to go through Java→JNI→Rust, adding an extra hop. Option A is preferred because it lets us
share the same C++ glue code on both platforms.

### Phase 3: Implement the C++ JSI TurboModule

This is the core new code. The C++ TurboModule acts as a thin adapter between React Native's JSI
and the `signal_*` C functions.

#### 3a. TurboModule Spec (TypeScript Codegen)

```typescript
// react-native/src/specs/NativeLibsignal.ts
import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

// We use a "Pure C++ TurboModule" approach — the spec defines only
// the module's existence. Individual function dispatch happens via
// a JSI HostObject, not codegen'd methods (the API surface is too large
// for individual codegen'd methods — 500+ functions).

export interface Spec extends TurboModule {
  // The module installs a global `__libsignal` JSI object
  // No spec methods needed — we use HostObject pattern
  install(): boolean;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Libsignal');
```

#### 3b. C++ JSI HostObject Implementation

The key insight: rather than code-generating 500+ TurboModule methods, we install a single JSI
HostObject that dispatches function calls by name. This mirrors how the Neon bridge works — the
Node native module exports named functions.

```cpp
// react-native/cpp/LibsignalTurboModule.h
#pragma once

#include <jsi/jsi.h>
#include <memory>
#include <string>
#include <unordered_map>

extern "C" {
#include "signal_ffi.h"
}

namespace libsignal {

using namespace facebook;

class LibsignalModule : public jsi::HostObject {
public:
    LibsignalModule(jsi::Runtime& runtime);

    jsi::Value get(jsi::Runtime& rt, const jsi::PropNameID& name) override;
    std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt) override;

    static void install(jsi::Runtime& runtime);

private:
    // Function registry: maps JS function name → C++ implementation
    using JsiFunction = std::function<jsi::Value(
        jsi::Runtime& rt,
        const jsi::Value& thisVal,
        const jsi::Value* args,
        size_t count)>;

    std::unordered_map<std::string, JsiFunction> functions_;

    void registerFunctions(jsi::Runtime& rt);

    // Helper methods for type conversion
    static std::vector<uint8_t> jsiToBytes(jsi::Runtime& rt, const jsi::Value& val);
    static jsi::Value bytesToJsi(jsi::Runtime& rt, const uint8_t* data, size_t len);
    static std::string jsiToString(jsi::Runtime& rt, const jsi::Value& val);

    // Error handling: converts SignalFfiError* to JS exception
    static void checkError(jsi::Runtime& rt, SignalFfiError* err);
};

} // namespace libsignal
```

```cpp
// react-native/cpp/LibsignalTurboModule.cpp (excerpt showing pattern)
#include "LibsignalTurboModule.h"

namespace libsignal {

void LibsignalModule::install(jsi::Runtime& runtime) {
    auto module = std::make_shared<LibsignalModule>(runtime);
    auto object = jsi::Object::createFromHostObject(runtime, module);
    runtime.global().setProperty(runtime, "__libsignal_native", std::move(object));
}

LibsignalModule::LibsignalModule(jsi::Runtime& runtime) {
    registerFunctions(runtime);
}

jsi::Value LibsignalModule::get(jsi::Runtime& rt, const jsi::PropNameID& name) {
    auto nameStr = name.utf8(rt);
    auto it = functions_.find(nameStr);
    if (it == functions_.end()) {
        return jsi::Value::undefined();
    }
    auto& fn = it->second;
    return jsi::Function::createFromHostFunction(
        rt, name, 0,
        [&fn](jsi::Runtime& rt, const jsi::Value& thisVal,
              const jsi::Value* args, size_t count) -> jsi::Value {
            return fn(rt, thisVal, args, count);
        });
}

void LibsignalModule::registerFunctions(jsi::Runtime& rt) {
    // Example: PrivateKey_Generate
    functions_["PrivateKey_Generate"] = [](jsi::Runtime& rt,
            const jsi::Value&, const jsi::Value*, size_t) -> jsi::Value {
        SignalPrivateKey* key = nullptr;
        SignalFfiError* err = signal_privatekey_generate(&key);
        checkError(rt, err);
        // Return as a pointer wrapped in a jsi::BigInt or external object
        return jsi::BigInt::fromUint64(rt, reinterpret_cast<uint64_t>(key));
    };

    // Example: PublicKey_Serialize
    functions_["PublicKey_Serialize"] = [](jsi::Runtime& rt,
            const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        auto keyPtr = reinterpret_cast<const SignalPublicKey*>(
            args[0].asBigInt(rt).getUint64(rt));
        SignalOwnedBuffer buf = {0};
        SignalFfiError* err = signal_publickey_serialize(&buf, keyPtr);
        checkError(rt, err);
        auto result = bytesToJsi(rt, buf.base, buf.length);
        signal_free_buffer(buf.base, buf.length);
        return result;
    };

    // ... ~500 more functions following the same pattern ...
    // These can be generated from the signal_ffi.h header
    // using a code generation script (see Phase 5).
}

void LibsignalModule::checkError(jsi::Runtime& rt, SignalFfiError* err) {
    if (err == nullptr) return;

    auto code = signal_error_get_type(err);
    // Get message, construct JS Error, throw
    const char* msg = nullptr;
    signal_error_get_message(err, &msg);
    std::string message = msg ? msg : "Unknown error";
    signal_free_string(msg);
    signal_error_free(err);

    throw jsi::JSError(rt, message);
}

std::vector<uint8_t> LibsignalModule::jsiToBytes(jsi::Runtime& rt, const jsi::Value& val) {
    auto obj = val.asObject(rt);
    auto arrayBuffer = obj.getArrayBuffer(rt);
    auto data = arrayBuffer.data(rt);
    auto size = arrayBuffer.size(rt);
    return std::vector<uint8_t>(data, data + size);
}

jsi::Value LibsignalModule::bytesToJsi(jsi::Runtime& rt,
        const uint8_t* data, size_t len) {
    auto arrayBuffer = rt.global()
        .getPropertyAsFunction(rt, "ArrayBuffer")
        .callAsConstructor(rt, static_cast<int>(len))
        .asObject(rt)
        .getArrayBuffer(rt);
    memcpy(arrayBuffer.data(rt), data, len);

    // Wrap in Uint8Array
    auto uint8ArrayCtor = rt.global().getPropertyAsFunction(rt, "Uint8Array");
    return uint8ArrayCtor.callAsConstructor(rt, arrayBuffer);
}

} // namespace libsignal
```

### Phase 4: Platform-Specific Registration

#### 4a. iOS (Objective-C++)

```objc
// react-native/ios/LibsignalModule.mm
#import <React/RCTBridgeModule.h>
#import <ReactCommon/CxxTurboModuleUtils.h>
#import <jsi/jsi.h>
#import "LibsignalTurboModule.h"

@interface LibsignalModule : NSObject <RCTBridgeModule>
@end

@implementation LibsignalModule

RCT_EXPORT_MODULE(Libsignal)

+ (BOOL)requiresMainQueueSetup {
    return NO;
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(install) {
    // Get the JSI runtime from the bridge
    RCTBridge* bridge = [RCTBridge currentBridge];
    RCTCxxBridge* cxxBridge = (RCTCxxBridge*)bridge;
    if (cxxBridge && cxxBridge.runtime) {
        auto& runtime = *(facebook::jsi::Runtime*)cxxBridge.runtime;
        libsignal::LibsignalModule::install(runtime);
        return @YES;
    }
    return @NO;
}

@end
```

#### 4b. iOS Podspec

```ruby
# react-native/libsignal-client-react-native.podspec
Pod::Spec.new do |s|
  s.name         = "libsignal-client-react-native"
  s.version      = "0.87.1"
  s.summary      = "Signal Protocol library for React Native"
  s.homepage     = "https://github.com/signalapp/libsignal"
  s.license      = "AGPL-3.0-only"
  s.authors      = "Signal Messenger LLC"
  s.source       = { :git => "https://github.com/signalapp/libsignal.git" }
  s.platforms    = { :ios => "15.0" }

  s.source_files = "ios/**/*.{h,m,mm}", "cpp/**/*.{h,cpp}"
  s.vendored_libraries = "prebuilds/ios/libsignal_ffi.a"

  s.pod_target_xcconfig = {
    'CLANG_CXX_LANGUAGE_STANDARD' => 'c++17',
    'HEADER_SEARCH_PATHS' => '"$(PODS_TARGET_SRCROOT)/cpp"'
  }

  s.dependency "React-Core"
  s.dependency "React-callinvoker"
  s.dependency "ReactCommon/turbomodule/core"

  # Build the Rust library as a pre-install step
  s.script_phase = {
    :name => 'Build libsignal FFI',
    :script => 'bash "${PODS_TARGET_SRCROOT}/../scripts/build_ios.sh"',
    :execution_position => :before_compile
  }
end
```

#### 4c. Android (Java + CMake)

```java
// react-native/android/src/main/java/org/signal/libsignal/reactnative/LibsignalModule.java
package org.signal.libsignal.reactnative;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.turbomodule.core.interfaces.TurboModule;

public class LibsignalModule extends ReactContextBaseJavaModule implements TurboModule {
    static {
        System.loadLibrary("signal_ffi");       // Load Rust shared library
        System.loadLibrary("libsignal_jsi");    // Load C++ JSI glue
    }

    public LibsignalModule(ReactApplicationContext context) {
        super(context);
    }

    @Override
    public String getName() {
        return "Libsignal";
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public boolean install() {
        return nativeInstall(
            getReactApplicationContext().getJavaScriptContextHolder().get()
        );
    }

    private static native boolean nativeInstall(long jsiRuntimePtr);
}
```

```cmake
# react-native/android/CMakeLists.txt
cmake_minimum_required(VERSION 3.13)
project(libsignal_jsi)

set(CMAKE_CXX_STANDARD 17)

# Find React Native and JSI headers
find_package(ReactAndroid REQUIRED CONFIG)

add_library(libsignal_jsi SHARED
    ../cpp/LibsignalTurboModule.cpp
    src/main/cpp/jni_install.cpp
)

# Link against the prebuilt Rust shared library
add_library(signal_ffi SHARED IMPORTED)
set_target_properties(signal_ffi PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libsignal_ffi.so"
)

target_include_directories(libsignal_jsi PRIVATE
    ../cpp
    ${CMAKE_SOURCE_DIR}/src/main/jniLibs/include
)

target_link_libraries(libsignal_jsi
    signal_ffi
    ReactAndroid::jsi
    ReactAndroid::turbomodulejsijni
    android
    log
)
```

```cpp
// react-native/android/src/main/cpp/jni_install.cpp
#include <jni.h>
#include <jsi/jsi.h>
#include "LibsignalTurboModule.h"

extern "C"
JNIEXPORT jboolean JNICALL
Java_org_signal_libsignal_reactnative_LibsignalModule_nativeInstall(
        JNIEnv *env, jclass clazz, jlong jsiRuntimePtr) {
    auto runtime = reinterpret_cast<facebook::jsi::Runtime*>(jsiRuntimePtr);
    if (runtime) {
        libsignal::LibsignalModule::install(*runtime);
        return JNI_TRUE;
    }
    return JNI_FALSE;
}
```

### Phase 5: Code Generation for C++ Bindings

Manually writing 500+ JSI wrapper functions is error-prone. Create a Python script that parses
`signal_ffi.h` and generates the C++ `registerFunctions()` body:

```
react-native/scripts/gen_jsi_bindings.py
```

This script would:

1. Parse `signal_ffi.h` using regex or a C header parser
2. For each `signal_*` function, determine:
   - Input parameter types (map C types to JSI conversion helpers)
   - Output parameters (pointer-to-pointer patterns → return values)
   - Return type (always `SignalFfiError*` for failable functions)
3. Generate the corresponding JSI function registration in C++
4. Map the C function name back to the TypeScript function name (strip `signal_` prefix,
   convert to PascalCase)

The mapping between C names and TypeScript names already exists implicitly in the bridge macros:
- C FFI: `signal_private_key_generate` (via `LIBSIGNAL_BRIDGE_FN_PREFIX_FFI`)
- TypeScript: `PrivateKey_Generate` (original bridge_fn name)

The codegen script produces output like:

```cpp
// AUTO-GENERATED — do not edit
void LibsignalModule::registerFunctions(jsi::Runtime& rt) {

    functions_["PrivateKey_Generate"] = [](jsi::Runtime& rt,
            const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        SignalPrivateKey* out = nullptr;
        checkError(rt, signal_privatekey_generate(&out));
        return pointerToJsi(rt, out);
    };

    functions_["PrivateKey_Serialize"] = [](jsi::Runtime& rt,
            const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        auto obj = jsiToPointer<SignalPrivateKey>(rt, args[0]);
        SignalOwnedBuffer buf = {0};
        checkError(rt, signal_privatekey_serialize(&buf, obj));
        auto result = bytesToJsi(rt, buf.base, buf.length);
        signal_free_buffer(buf.base, buf.length);
        return result;
    };

    // ... etc for all functions
}
```

### Phase 6: Adapt the TypeScript Layer

The existing `node/ts/` TypeScript files need these modifications:

#### 6a. Replace `Native.ts` Module Loading

Current (`node/ts/Native.ts`):
```typescript
import load from 'node-gyp-build';
const { PrivateKey_Generate, ... } = load(`${import.meta.dirname}/../`) as NativeFunctions;
```

React Native version (`react-native/ts/Native.ts`):
```typescript
import { NativeModules } from 'react-native';

const { Libsignal } = NativeModules;
Libsignal.install();

// Access the JSI HostObject installed on the global
declare const global: { __libsignal_native: NativeFunctions };
const native = global.__libsignal_native;

export const PrivateKey_Generate = native.PrivateKey_Generate;
export const PublicKey_Serialize = native.PublicKey_Serialize;
// ... etc
```

#### 6b. Replace `node:buffer` with `Uint8Array`

Throughout `node/ts/`, replace:
```typescript
import { Buffer } from 'node:buffer';
// Buffer.from(...), Buffer.alloc(...), etc.
```

With:
```typescript
// Use Uint8Array directly — supported by Hermes
// Provide a small compatibility shim for Buffer-like operations
```

A small utility module can provide the needed Buffer-like helpers:

```typescript
// react-native/ts/buffer-shim.ts
export function fromHex(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

export function toHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function concat(arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}
```

#### 6c. Replace `uuid` npm package

The `uuid` package uses Node.js `crypto.getRandomValues`. For React Native, use
`react-native-get-random-values` polyfill or `expo-crypto`.

#### 6d. Handle Async Operations

The current Node bridge uses `signal-neon-futures` for async. The FFI bridge handles async
differently — `#[bridge_io]` functions in FFI mode "expect to complete immediately without
blocking" (per the macro docs). For React Native:

- Synchronous FFI calls work directly through JSI (they're fast C calls)
- For truly async operations (network calls via `libsignal-net`), we need to either:
  - Run them on a native thread and resolve a Promise
  - Use the existing callback-based FFI patterns (the FFI bridge already supports async
    callbacks via `FfiInputStreamStruct` etc.)

This means the C++ layer needs a `Promise` creation helper:

```cpp
// For async functions, create a JS Promise and run the FFI call on a background thread
functions_["ConnectionManager_connect_chat"] = [](jsi::Runtime& rt,
        const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
    // Create Promise
    auto promiseCtor = rt.global().getPropertyAsFunction(rt, "Promise");
    return promiseCtor.callAsConstructor(rt,
        jsi::Function::createFromHostFunction(rt, ..., 2,
            [](jsi::Runtime& rt, ...) {
                // Dispatch to background thread, resolve/reject when done
            }));
};
```

### Phase 7: Build System Integration

#### 7a. `package.json` for the React Native package

```json
{
  "name": "@signalapp/libsignal-client-react-native",
  "version": "0.87.1",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "react-native": "dist/index.js",
  "files": [
    "dist/",
    "cpp/",
    "ios/",
    "android/",
    "prebuilds/",
    "libsignal-client-react-native.podspec"
  ],
  "scripts": {
    "build:ios": "bash scripts/build_ios.sh",
    "build:android": "bash scripts/build_android.sh",
    "tsc": "tsc -b"
  },
  "peerDependencies": {
    "react": ">=18",
    "react-native": ">=0.73"
  },
  "codegenConfig": {
    "name": "LibsignalSpec",
    "type": "modules",
    "jsSrcsDir": "src/specs"
  }
}
```

### Phase 8: Handle Native Object Lifecycle (Memory Management)

The FFI bridge uses opaque pointers (`SignalPrivateKey*`, `SignalPublicKey*`, etc.) that must be
explicitly freed. In the Node bridge, Neon handles pointers via its garbage-collection integration.
For React Native JSI, we need our own ref-counting / weak-ref mechanism:

**Option A — PointerBox HostObject**: Wrap each native pointer in a small HostObject with a C++
destructor that calls the appropriate `signal_*_destroy` function. When JS garbage-collects the
object, the destructor fires.

```cpp
class NativePointer : public jsi::HostObject {
    void* ptr_;
    using Destructor = void(*)(void*);
    Destructor destructor_;
public:
    NativePointer(void* ptr, Destructor destructor)
        : ptr_(ptr), destructor_(destructor) {}
    ~NativePointer() {
        if (ptr_ && destructor_) destructor_(ptr_);
    }
    void* get() const { return ptr_; }
};
```

**Option B — PointerRegistry**: Use a numeric handle (like the JNI bridge does with `long` handles)
and a global registry that maps handles to pointers, with explicit `destroy` calls from JS.

Option A is preferred because it integrates with the JS garbage collector, matching the Node
bridge's behavior where Neon releases objects automatically.

---

## Modifications to Existing Repo Files

### Must-change files:

| File | Change |
|---|---|
| `rust/bridge/ffi/Cargo.toml` | Add `cdylib` to `crate-type` list for Android shared library support |
| `Cargo.toml` (workspace) | No changes needed — `libsignal-ffi` is already a workspace member |

### New files/directories:

| Path | Purpose |
|---|---|
| `react-native/` (entire directory) | New React Native package |
| `react-native/cpp/LibsignalTurboModule.{h,cpp}` | C++ JSI glue layer |
| `react-native/cpp/signal_ffi.h` | C header (copied from generated output) |
| `react-native/ios/LibsignalModule.mm` | iOS TurboModule registration |
| `react-native/android/` | Android module (Java + CMake + JNI) |
| `react-native/ts/` | Adapted TypeScript API layer |
| `react-native/scripts/gen_jsi_bindings.py` | Code generator for C++ ↔ JSI bindings |
| `react-native/scripts/build_ios.sh` | iOS Rust build script |
| `react-native/scripts/build_android.sh` | Android Rust build script |

### Unchanged:

All existing `node/`, `java/`, `swift/`, and `rust/` code remains unchanged (except the one-line
`crate-type` addition to `rust/bridge/ffi/Cargo.toml`).

---

## Risks and Mitigations

### Risk 1: API Surface Size
~500+ functions need JSI wrappers. **Mitigation**: Code generation from `signal_ffi.h`.

### Risk 2: Async / Network Operations
The FFI bridge's async model differs from Node's. **Mitigation**: Use background threads + Promise
resolution for async ops; implement FFI callback structs for streaming operations.

### Risk 3: Memory Management
Native pointers must be freed. **Mitigation**: Use HostObject destructor pattern (Option A above)
for automatic GC-driven cleanup.

### Risk 4: `node:buffer` Dependency
~50 files use `node:buffer`. **Mitigation**: Systematic replacement with `Uint8Array` + small shim
module. This is mechanical and well-scoped.

### Risk 5: Binary Size
Including the full `libsignal_ffi` may be large. **Mitigation**: Use LTO, strip debug info, and
consider feature-gating unused modules (e.g., skip `signal-media` if not needed).

### Risk 6: Hermes Compatibility
Some JS features (BigInt for pointer passing) may not be fully supported in older Hermes versions.
**Mitigation**: Use HostObject wrapping for pointers instead of BigInt; target React Native 0.73+
which has good Hermes BigInt support.

---

## Implementation Order

1. Get `libsignal_ffi.a` building for iOS arm64 target (already works via `build_ffi.sh`)
2. Get `libsignal_ffi.so` building for Android targets (add `cdylib` crate type)
3. Write `gen_jsi_bindings.py` to auto-generate C++ from `signal_ffi.h`
4. Create minimal C++ TurboModule with 5–10 functions (e.g., key generation, serialization)
5. Create React Native package structure with podspec + CMakeLists
6. Verify end-to-end: JS → TurboModule → C++ → FFI → Rust → back
7. Generate full binding set
8. Fork and adapt `node/ts/` → `react-native/ts/` with Buffer→Uint8Array changes
9. Test on iOS simulator and Android emulator
10. Handle async operations (network, streaming)

## Estimated Scope

- **~200 lines** of changes to existing files (just the crate-type addition)
- **~500–1000 lines** of hand-written C++ (TurboModule infrastructure, helpers)
- **~5000+ lines** of auto-generated C++ (function bindings from codegen)
- **~2000 lines** of adapted TypeScript (fork of node/ts/ with React Native adaptations)
- **~200 lines** of build scripts and configuration
- **~300 lines** of Python codegen script
