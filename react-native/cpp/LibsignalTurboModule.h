//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#pragma once

#include <jsi/jsi.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>
#include <cstring>

extern "C" {
#include "signal_ffi.h"
}

namespace libsignal {

using namespace facebook;

// Forward declaration
class NativePointer;

// Callback for resolving async promises from background threads
struct PromiseResolver {
    std::function<void(jsi::Value)> resolve;
    std::function<void(std::string)> reject;
};

/**
 * A HostObject wrapper around a native pointer that calls the appropriate
 * signal_*_destroy function when garbage-collected.
 */
class NativePointer : public jsi::HostObject {
public:
    using Destructor = void (*)(void*);

    NativePointer(void* ptr, Destructor destructor)
        : ptr_(ptr), destructor_(destructor) {}

    ~NativePointer() override {
        if (ptr_ && destructor_) {
            destructor_(ptr_);
        }
    }

    void* get() const { return ptr_; }

    // Prevent copying
    NativePointer(const NativePointer&) = delete;
    NativePointer& operator=(const NativePointer&) = delete;

    jsi::Value get(jsi::Runtime& rt, const jsi::PropNameID& name) override {
        auto propName = name.utf8(rt);
        if (propName == "_pointer") {
            return jsi::BigInt::fromUint64(rt, reinterpret_cast<uint64_t>(ptr_));
        }
        return jsi::Value::undefined();
    }

    std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt) override {
        std::vector<jsi::PropNameID> names;
        names.push_back(jsi::PropNameID::forAscii(rt, "_pointer"));
        return names;
    }

private:
    void* ptr_;
    Destructor destructor_;
};

/**
 * The main JSI HostObject that exposes all signal_* functions to JavaScript.
 *
 * Usage from JS:
 *   const native = global.__libsignal_native;
 *   const key = native.PrivateKey_Generate();
 *   const serialized = native.PrivateKey_Serialize(key);
 */
class LibsignalModule : public jsi::HostObject {
public:
    explicit LibsignalModule(jsi::Runtime& runtime);

    jsi::Value get(jsi::Runtime& rt, const jsi::PropNameID& name) override;
    std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt) override;

    /**
     * Install the module as global.__libsignal_native on the given runtime.
     */
    static void install(jsi::Runtime& runtime);

private:
    // Function registry: maps JS function name -> C++ implementation
    using JsiFunction = std::function<jsi::Value(
        jsi::Runtime& rt,
        const jsi::Value& thisVal,
        const jsi::Value* args,
        size_t count)>;

    std::unordered_map<std::string, JsiFunction> functions_;

    // Hand-written function registrations (stores, listeners, logger, etc.)
    void registerHandwrittenFunctions(jsi::Runtime& rt);

    // Auto-generated function registrations (from gen_jsi_bindings.py)
    void registerGeneratedFunctions(jsi::Runtime& rt);

    // Auto-generated property names list
    std::vector<jsi::PropNameID> getGeneratedPropertyNames(jsi::Runtime& rt);

    // ---------------------------------------------------------------
    // Type conversion helpers
    // ---------------------------------------------------------------

    /**
     * Convert a JSI value (Uint8Array / ArrayBuffer) to a SignalBorrowedBuffer.
     * The returned buffer borrows from the JSI value and must not outlive it.
     */
    static SignalBorrowedBuffer jsiToBuffer(jsi::Runtime& rt, const jsi::Value& val);

    /**
     * Convert a JSI value to a SignalBorrowedMutableBuffer.
     */
    static SignalBorrowedMutableBuffer jsiToMutableBuffer(jsi::Runtime& rt, const jsi::Value& val);

    /**
     * Convert a JSI string value to a std::string.
     */
    static std::string jsiToString(jsi::Runtime& rt, const jsi::Value& val);

    /**
     * Convert a JSI value to a SignalUuid.
     */
    static SignalUuid jsiToUuid(jsi::Runtime& rt, const jsi::Value& val);

    /**
     * Convert a JSI value to a ServiceIdFixedWidthBinaryBytes.
     */
    static SignalServiceIdFixedWidthBinaryBytes jsiToServiceId(jsi::Runtime& rt, const jsi::Value& val);

    /**
     * Convert a JSI value to a fixed-size byte buffer (returned as vector).
     */
    static std::vector<uint8_t> jsiToFixedBuffer(jsi::Runtime& rt, const jsi::Value& val);

    /**
     * Convert a JSI array to a SignalBorrowedBytestringArray.
     */
    static SignalBorrowedBytestringArray jsiToBytestringArray(jsi::Runtime& rt, const jsi::Value& val);

    /**
     * Extract a NativePointer from a JSI HostObject value.
     */
    template<typename T>
    static T jsiToConstPointer(jsi::Runtime& rt, const jsi::Value& val);

    template<typename T>
    static T jsiToMutPointer(jsi::Runtime& rt, const jsi::Value& val);

    // ---------------------------------------------------------------
    // Output conversion helpers
    // ---------------------------------------------------------------

    /**
     * Wrap a native pointer in a NativePointer HostObject for GC-driven cleanup.
     */
    template<typename WrapperType>
    static jsi::Value pointerToJsi(jsi::Runtime& rt, WrapperType ptr);

    /**
     * Convert a SignalOwnedBuffer to a Uint8Array, freeing the buffer.
     */
    static jsi::Value ownedBufferToJsi(jsi::Runtime& rt, SignalOwnedBuffer buf);

    /**
     * Convert a fixed-size array to a Uint8Array.
     */
    static jsi::Value fixedArrayToJsi(jsi::Runtime& rt, const uint8_t* data, size_t len);

    /**
     * Convert a C string to a JSI string value, freeing the C string.
     */
    static jsi::Value stringToJsi(jsi::Runtime& rt, const char* str);

    /**
     * Convert a SignalUuid to a JSI Uint8Array.
     */
    static jsi::Value uuidToJsi(jsi::Runtime& rt, const SignalUuid& uuid);

    /**
     * Convert a SignalBytestringArray to a JSI array, freeing the native array.
     */
    static jsi::Value bytestringArrayToJsi(jsi::Runtime& rt, SignalBytestringArray& arr);

    // ---------------------------------------------------------------
    // Error handling
    // ---------------------------------------------------------------

    /**
     * Check a SignalFfiError* and throw a JSI exception if non-null.
     * The error is freed after extracting the message.
     */
    static void checkError(jsi::Runtime& rt, SignalFfiError* err);

    // ---------------------------------------------------------------
    // Async helpers
    // ---------------------------------------------------------------

    /**
     * Create a JS Promise that runs an FFI call on a background thread.
     */
    static jsi::Value createAsyncCall(
        jsi::Runtime& rt,
        const jsi::Value* args,
        size_t count,
        std::function<void(jsi::Runtime&, const jsi::Value*, size_t, PromiseResolver)> work);
};

} // namespace libsignal
