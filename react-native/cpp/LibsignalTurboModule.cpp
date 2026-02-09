//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#include "LibsignalTurboModule.h"
#include <cstdlib>
#include <stdexcept>

namespace libsignal {

// ---------------------------------------------------------------
// Helper: get the TypedArray global constructor from JS runtime
// ---------------------------------------------------------------
static jsi::Function getUint8ArrayConstructor(jsi::Runtime& rt) {
    return rt.global()
        .getPropertyAsObject(rt, "Uint8Array")
        .asFunction(rt);
}

static jsi::Object getArrayBufferConstructor(jsi::Runtime& rt) {
    return rt.global().getPropertyAsObject(rt, "ArrayBuffer");
}

// ---------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------

void LibsignalModule::checkError(jsi::Runtime& rt, SignalFfiError* err) {
    if (!err) return;

    uint32_t errType = signal_error_get_type(err);

    const char* msg = nullptr;
    SignalFfiError* msgErr = signal_error_get_message(&msg, err);
    std::string message;
    if (msg) {
        message = msg;
        signal_free_string(msg);
    } else {
        message = "Unknown libsignal error";
    }
    if (msgErr) {
        signal_error_free(msgErr);
    }

    signal_error_free(err);

    // Create an Error object with type code attached
    auto errorCtor = rt.global().getPropertyAsFunction(rt, "Error");
    auto jsError = errorCtor.callAsConstructor(
        rt, jsi::String::createFromUtf8(rt, message))
        .asObject(rt);
    jsError.setProperty(rt, "code", static_cast<double>(errType));

    throw jsi::JSError(rt, jsi::Value(rt, jsError));
}

// ---------------------------------------------------------------
// Type conversions: JSI → C
// ---------------------------------------------------------------

SignalBorrowedBuffer LibsignalModule::jsiToBuffer(jsi::Runtime& rt, const jsi::Value& val) {
    if (val.isNull() || val.isUndefined()) {
        return SignalBorrowedBuffer{nullptr, 0};
    }

    auto obj = val.asObject(rt);

    // Handle TypedArray (Uint8Array)
    if (obj.hasProperty(rt, "buffer")) {
        auto byteOffset = static_cast<size_t>(
            obj.getProperty(rt, "byteOffset").asNumber());
        auto byteLength = static_cast<size_t>(
            obj.getProperty(rt, "byteLength").asNumber());
        auto arrayBuffer = obj.getProperty(rt, "buffer")
            .asObject(rt)
            .getArrayBuffer(rt);
        return SignalBorrowedBuffer{
            arrayBuffer.data(rt) + byteOffset,
            byteLength
        };
    }

    // Handle ArrayBuffer directly
    if (obj.isArrayBuffer(rt)) {
        auto ab = obj.getArrayBuffer(rt);
        return SignalBorrowedBuffer{ab.data(rt), ab.size(rt)};
    }

    throw jsi::JSError(rt, "Expected Uint8Array or ArrayBuffer");
}

SignalBorrowedMutableBuffer LibsignalModule::jsiToMutableBuffer(
    jsi::Runtime& rt, const jsi::Value& val) {

    auto obj = val.asObject(rt);

    if (obj.hasProperty(rt, "buffer")) {
        auto byteOffset = static_cast<size_t>(
            obj.getProperty(rt, "byteOffset").asNumber());
        auto byteLength = static_cast<size_t>(
            obj.getProperty(rt, "byteLength").asNumber());
        auto arrayBuffer = obj.getProperty(rt, "buffer")
            .asObject(rt)
            .getArrayBuffer(rt);
        return SignalBorrowedMutableBuffer{
            arrayBuffer.data(rt) + byteOffset,
            byteLength
        };
    }

    if (obj.isArrayBuffer(rt)) {
        auto ab = obj.getArrayBuffer(rt);
        return SignalBorrowedMutableBuffer{ab.data(rt), ab.size(rt)};
    }

    throw jsi::JSError(rt, "Expected mutable Uint8Array or ArrayBuffer");
}

std::string LibsignalModule::jsiToString(jsi::Runtime& rt, const jsi::Value& val) {
    if (val.isNull() || val.isUndefined()) {
        return "";
    }
    return val.asString(rt).utf8(rt);
}

SignalUuid LibsignalModule::jsiToUuid(jsi::Runtime& rt, const jsi::Value& val) {
    auto buf = jsiToBuffer(rt, val);
    if (buf.length != 16) {
        throw jsi::JSError(rt, "UUID must be exactly 16 bytes");
    }
    SignalUuid uuid;
    std::memcpy(uuid.bytes, buf.base, 16);
    return uuid;
}

void LibsignalModule::jsiToServiceId(
    jsi::Runtime& rt, const jsi::Value& val, SignalServiceIdFixedWidthBinaryBytes out) {
    auto buf = jsiToBuffer(rt, val);
    if (buf.length != 17) {
        throw jsi::JSError(rt, "ServiceId must be exactly 17 bytes");
    }
    std::memcpy(out, buf.base, 17);
}

std::vector<uint8_t> LibsignalModule::jsiToFixedBuffer(
    jsi::Runtime& rt, const jsi::Value& val) {
    auto buf = jsiToBuffer(rt, val);
    return std::vector<uint8_t>(buf.base, buf.base + buf.length);
}

LibsignalModule::BorrowedSliceOfBuffers LibsignalModule::jsiToSliceOfBuffers(
    jsi::Runtime& rt, const jsi::Value& val) {
    BorrowedSliceOfBuffers result;

    auto obj = val.asObject(rt);
    auto arr = obj.asArray(rt);
    size_t len = arr.size(rt);

    result.buffers.resize(len);
    for (size_t i = 0; i < len; i++) {
        auto elem = arr.getValueAtIndex(rt, i);
        result.buffers[i] = jsiToBuffer(rt, elem);
    }

    result.slice.base = result.buffers.data();
    result.slice.length = len;
    return result;
}

SignalBorrowedBytestringArray LibsignalModule::jsiToBytestringArray(
    jsi::Runtime& rt, const jsi::Value& val) {
    // BorrowedBytestringArray packs all strings into one contiguous buffer
    // with a separate lengths array. Since we can't easily manage the lifetime
    // of the packed buffer here, we use a thread_local static to hold it.
    // This is safe because JSI calls are single-threaded.
    thread_local std::vector<uint8_t> packedBytes;
    thread_local std::vector<size_t> lengths;

    packedBytes.clear();
    lengths.clear();

    auto obj = val.asObject(rt);
    auto arr = obj.asArray(rt);
    size_t len = arr.size(rt);

    for (size_t i = 0; i < len; i++) {
        auto elem = arr.getValueAtIndex(rt, i);
        auto buf = jsiToBuffer(rt, elem);
        packedBytes.insert(packedBytes.end(), buf.base, buf.base + buf.length);
        lengths.push_back(buf.length);
    }

    SignalBorrowedBytestringArray result;
    result.bytes.base = packedBytes.data();
    result.bytes.length = packedBytes.size();
    result.lengths.base = lengths.data();
    result.lengths.length = lengths.size();
    return result;
}

// ---------------------------------------------------------------
// Type conversions: C → JSI
// ---------------------------------------------------------------

jsi::Value LibsignalModule::ownedBufferToJsi(jsi::Runtime& rt, SignalOwnedBuffer buf) {
    if (!buf.base || buf.length == 0) {
        auto ctor = getUint8ArrayConstructor(rt);
        return ctor.callAsConstructor(rt, 0);
    }

    auto ctor = getUint8ArrayConstructor(rt);
    auto result = ctor.callAsConstructor(rt, static_cast<int>(buf.length))
        .asObject(rt);

    auto arrayBuffer = result.getProperty(rt, "buffer")
        .asObject(rt)
        .getArrayBuffer(rt);
    std::memcpy(arrayBuffer.data(rt), buf.base, buf.length);

    signal_free_buffer(buf.base, buf.length);

    return jsi::Value(rt, result);
}

jsi::Value LibsignalModule::fixedArrayToJsi(
    jsi::Runtime& rt, const uint8_t* data, size_t len) {
    auto ctor = getUint8ArrayConstructor(rt);
    auto result = ctor.callAsConstructor(rt, static_cast<int>(len))
        .asObject(rt);

    auto arrayBuffer = result.getProperty(rt, "buffer")
        .asObject(rt)
        .getArrayBuffer(rt);
    std::memcpy(arrayBuffer.data(rt), data, len);

    return jsi::Value(rt, result);
}

jsi::Value LibsignalModule::stringToJsi(jsi::Runtime& rt, const char* str) {
    if (!str) {
        return jsi::Value::null();
    }
    auto result = jsi::String::createFromUtf8(rt, str);
    signal_free_string(str);
    return jsi::Value(rt, result);
}

jsi::Value LibsignalModule::uuidToJsi(jsi::Runtime& rt, const SignalUuid& uuid) {
    return fixedArrayToJsi(rt, uuid.bytes, 16);
}

jsi::Value LibsignalModule::bytestringArrayToJsi(
    jsi::Runtime& rt, SignalBytestringArray& arr) {
    auto jsArray = jsi::Array(rt, arr.bytes.length == 0 ? 0 : arr.lengths.length);
    const uint8_t* cursor = arr.bytes.base;

    for (size_t i = 0; i < arr.lengths.length; i++) {
        size_t entryLen = arr.lengths.base[i];
        auto entry = fixedArrayToJsi(rt, cursor, entryLen);
        jsArray.setValueAtIndex(rt, i, std::move(entry));
        cursor += entryLen;
    }

    signal_free_bytestring_array(arr);

    return jsi::Value(rt, jsArray);
}

// ---------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------

LibsignalModule::LibsignalModule(jsi::Runtime& runtime) {
    registerGeneratedFunctions(runtime);
    registerHandwrittenFunctions(runtime);
}

// ---------------------------------------------------------------
// HostObject interface
// ---------------------------------------------------------------

jsi::Value LibsignalModule::get(jsi::Runtime& rt, const jsi::PropNameID& name) {
    auto propName = name.utf8(rt);

    auto it = functions_.find(propName);
    if (it != functions_.end()) {
        auto& fn = it->second;
        return jsi::Function::createFromHostFunction(
            rt,
            name,
            0, // length hint (variadic)
            [&fn](jsi::Runtime& rt,
                  const jsi::Value& thisVal,
                  const jsi::Value* args,
                  size_t count) -> jsi::Value {
                return fn(rt, thisVal, args, count);
            });
    }

    return jsi::Value::undefined();
}

std::vector<jsi::PropNameID> LibsignalModule::getPropertyNames(jsi::Runtime& rt) {
    std::vector<jsi::PropNameID> names;
    names.reserve(functions_.size());
    for (auto& pair : functions_) {
        names.push_back(jsi::PropNameID::forAscii(rt, pair.first));
    }
    return names;
}

// ---------------------------------------------------------------
// Install
// ---------------------------------------------------------------

void LibsignalModule::install(jsi::Runtime& runtime) {
    auto module = std::make_shared<LibsignalModule>(runtime);
    runtime.global().setProperty(
        runtime,
        "__libsignal_native",
        jsi::Object::createFromHostObject(runtime, module));
}

// ---------------------------------------------------------------
// Hand-written functions
// ---------------------------------------------------------------

void LibsignalModule::registerHandwrittenFunctions(jsi::Runtime& rt) {
    // TESTING_OnlyCheckFeatureFlag - simple string check
    functions_["TESTING_OnlyCheckFeatureFlag"] = [](jsi::Runtime& rt,
            const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        (void)count;
        // This is a testing-only function, no-op in RN
        return jsi::Value::undefined();
    };

    // initLogger - set up logging from native to JS
    functions_["initLogger"] = [](jsi::Runtime& rt,
            const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        // TODO: implement native-to-JS logging bridge
        // For now, this is a no-op
        return jsi::Value::undefined();
    };

    // TODO: Add store callback implementations:
    // - SessionStore operations
    // - IdentityKeyStore operations
    // - PreKeyStore operations
    // - SenderKeyStore operations
    // These require setting up C function pointer callbacks that invoke JSI functions.
}

// ---------------------------------------------------------------
// Async helpers (stub — needs threading infrastructure)
// ---------------------------------------------------------------

jsi::Value LibsignalModule::createAsyncCall(
    jsi::Runtime& rt,
    const jsi::Value* args,
    size_t count,
    std::function<void(jsi::Runtime&, const jsi::Value*, size_t, PromiseResolver)> work) {

    // Create a JS Promise
    auto promiseCtor = rt.global().getPropertyAsFunction(rt, "Promise");
    auto promiseCallback = jsi::Function::createFromHostFunction(
        rt,
        jsi::PropNameID::forAscii(rt, "promiseCallback"),
        2,
        [&work, args, count](jsi::Runtime& rt,
                             const jsi::Value&,
                             const jsi::Value* promiseArgs,
                             size_t) -> jsi::Value {
            auto resolve = std::make_shared<jsi::Value>(rt, promiseArgs[0]);
            auto reject = std::make_shared<jsi::Value>(rt, promiseArgs[1]);

            PromiseResolver resolver{
                .resolve = [&rt, resolve](jsi::Value val) {
                    resolve->asObject(rt).asFunction(rt).call(rt, std::move(val));
                },
                .reject = [&rt, reject](std::string msg) {
                    auto errCtor = rt.global().getPropertyAsFunction(rt, "Error");
                    auto err = errCtor.callAsConstructor(
                        rt, jsi::String::createFromUtf8(rt, msg));
                    reject->asObject(rt).asFunction(rt).call(rt, std::move(err));
                }
            };

            // TODO: For proper async support, this should dispatch `work`
            // to a background thread and call resolve/reject via the
            // React Native CallInvoker on the JS thread.
            // For now, we execute synchronously on the JS thread.
            work(rt, args, count, std::move(resolver));

            return jsi::Value::undefined();
        });

    return promiseCtor.callAsConstructor(rt, promiseCallback);
}

} // namespace libsignal
