//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#include "LibsignalTurboModule.h"
#include <cstdlib>
#include <stdexcept>

// Declare testing FFI functions (available when libsignal_ffi.so is built
// with --features libsignal-bridge-testing). These are weak symbols so
// the module loads even when testing is not available.
extern "C" {

// CPromise type for i32 results (only in testing header)
typedef struct {
  void (*complete)(SignalFfiError *error, const int32_t *result, const void *context);
  const void *context;
  uint64_t cancellation_id;
} SignalCPromisei32;

__attribute__((weak))
SignalFfiError* signal_testing_tokio_async_future(
    SignalCPromisei32* promise,
    SignalConstPointerTokioAsyncContext async_runtime,
    uint8_t input);

__attribute__((weak))
SignalFfiError* signal_testing_tokio_async_context_future_success_bytes(
    SignalCPromiseOwnedBufferOfc_uchar* promise,
    SignalConstPointerTokioAsyncContext async_runtime,
    int32_t count);
}

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

LibsignalModule::LibsignalModule(jsi::Runtime& runtime, std::shared_ptr<facebook::react::CallInvoker> callInvoker)
    : callInvoker_(callInvoker), asyncContext_({nullptr}), ownsAsyncContext_(false) {
    // Create a TokioAsyncContext for async FFI calls
    SignalMutPointerTokioAsyncContext ctx = {nullptr};
    SignalFfiError* err = signal_tokio_async_context_new(&ctx);
    if (!err && ctx.raw) {
        asyncContext_.raw = ctx.raw;
        ownsAsyncContext_ = true;
    }

    registerGeneratedFunctions(runtime);
    registerHandwrittenFunctions(runtime);
}

LibsignalModule::~LibsignalModule() {
    if (ownsAsyncContext_ && asyncContext_.raw) {
        SignalMutPointerTokioAsyncContext mut;
        mut.raw = const_cast<SignalTokioAsyncContext*>(asyncContext_.raw);
        signal_tokio_async_context_destroy(mut);
    }
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

void LibsignalModule::install(jsi::Runtime& runtime, std::shared_ptr<facebook::react::CallInvoker> callInvoker) {
    auto module = std::make_shared<LibsignalModule>(runtime, callInvoker);
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

    // TokioAsyncContext_New - returns the module's shared async context.
    // We expose it as a NativePointer wrapping the module's TokioAsyncContext.
    // The destructor is null because the module owns the context lifecycle.
    auto asyncCtx = asyncContext_;
    functions_["TokioAsyncContext_New"] = [asyncCtx](jsi::Runtime& rt,
            const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (!asyncCtx.raw) {
            throw jsi::JSError(rt, "TokioAsyncContext not available");
        }
        auto pointerObj = std::make_shared<NativePointer>(
            const_cast<void*>(reinterpret_cast<const void*>(asyncCtx.raw)),
            nullptr  // Module owns the lifecycle, no destructor
        );
        return jsi::Object::createFromHostObject(rt, pointerObj);
    };

    // TokioAsyncContext_Cancel - cancel an async operation
    auto asyncCtxForCancel = asyncContext_;
    functions_["TokioAsyncContext_Cancel"] = [asyncCtxForCancel](jsi::Runtime& rt,
            const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (!asyncCtxForCancel.raw) {
            throw jsi::JSError(rt, "TokioAsyncContext not available");
        }
        // args[0] is a BigInt cancellation_id
        // args[1] is the TokioAsyncContext (ignored, we use the module's)
        uint64_t cancellationId = 0;
        if (count > 0 && args[0].isBigInt()) {
            cancellationId = args[0].getBigInt(rt).getUint64(rt);
        } else if (count > 0 && args[0].isNumber()) {
            cancellationId = static_cast<uint64_t>(args[0].getNumber());
        }
        checkError(rt, signal_tokio_async_context_cancel(asyncCtxForCancel, cancellationId));
        return jsi::Value::undefined();
    };

    // TODO: Add store callback implementations:
    // - SessionStore operations
    // - IdentityKeyStore operations
    // - PreKeyStore operations
    // - SenderKeyStore operations
    // These require setting up C function pointer callbacks that invoke JSI functions.

    // ---- Testing async functions (require libsignal_ffi.so built with testing feature) ----
    // These use the TokioAsyncContext and return Promises, exercising the full async pipeline.
    // Weak symbols: if libsignal_ffi.so was built without testing, these throw at runtime.

    bool hasTestingSymbols = (signal_testing_tokio_async_future != nullptr);

    // TESTING_TokioAsyncFuture: async fn that returns the input value as i32
    // signal_testing_tokio_async_future(promise, async_runtime, input: u8) -> i32
    functions_["TESTING_TokioAsyncFuture"] = [this, hasTestingSymbols](jsi::Runtime& rt,
            const jsi::Value& /*thisVal*/, const jsi::Value* args, size_t count) -> jsi::Value {
        if (!hasTestingSymbols) {
            throw jsi::JSError(rt, "Testing functions not available (rebuild libsignal_ffi.so with --features libsignal-bridge-testing)");
        }
        auto ci = callInvoker_;
        return createAsyncCall(rt, args, count, ci, [this](jsi::Runtime& rt, const jsi::Value* args, size_t count,
                PromiseResolver resolver) {
            auto* resolverPtr = new PromiseResolver(std::move(resolver));
            uint8_t input = static_cast<uint8_t>(args[0].asNumber());
            SignalCPromisei32 promise = {};
            promise.context = reinterpret_cast<const void*>(resolverPtr);
            promise.complete = [](SignalFfiError* err, const int32_t* result, const void* ctx) {
                auto* resolver = const_cast<PromiseResolver*>(reinterpret_cast<const PromiseResolver*>(ctx));
                if (err) {
                    const char* msg = nullptr;
                    signal_error_get_message(&msg, err);
                    std::string errorMsg = msg ? msg : "Unknown error";
                    if (msg) signal_free_string(msg);
                    signal_error_free(err);
                    resolver->reject(errorMsg);
                } else if (result) {
                    resolver->resolve_int(*result);
                } else {
                    resolver->resolve_null();
                }
                delete resolver;
            };
            SignalFfiError* err = signal_testing_tokio_async_future(&promise, asyncContext_, input);
            if (err) {
                const char* msg = nullptr;
                signal_error_get_message(&msg, err);
                std::string errorMsg = msg ? msg : "Unknown error";
                if (msg) signal_free_string(msg);
                signal_error_free(err);
                resolverPtr->reject(errorMsg);
                delete resolverPtr;
            }
        });
    };

    // TESTING_TokioAsyncContextFutureSuccessBytes: async fn that returns 'count' bytes
    // signal_testing_tokio_async_context_future_success_bytes(promise, async_runtime, count: i32) -> OwnedBuffer
    functions_["TESTING_TokioAsyncContextFutureSuccessBytes"] = [this, hasTestingSymbols](jsi::Runtime& rt,
            const jsi::Value& /*thisVal*/, const jsi::Value* args, size_t count) -> jsi::Value {
        if (!hasTestingSymbols) {
            throw jsi::JSError(rt, "Testing functions not available (rebuild libsignal_ffi.so with --features libsignal-bridge-testing)");
        }
        auto ci = callInvoker_;
        return createAsyncCall(rt, args, count, ci, [this](jsi::Runtime& rt, const jsi::Value* args, size_t count,
                PromiseResolver resolver) {
            auto* resolverPtr = new PromiseResolver(std::move(resolver));
            int32_t byteCount = static_cast<int32_t>(args[0].asNumber());
            SignalCPromiseOwnedBufferOfc_uchar promise = {};
            promise.context = reinterpret_cast<const void*>(resolverPtr);
            promise.complete = [](SignalFfiError* err, const SignalOwnedBuffer* result, const void* ctx) {
                auto* resolver = const_cast<PromiseResolver*>(reinterpret_cast<const PromiseResolver*>(ctx));
                if (err) {
                    const char* msg = nullptr;
                    signal_error_get_message(&msg, err);
                    std::string errorMsg = msg ? msg : "Unknown error";
                    if (msg) signal_free_string(msg);
                    signal_error_free(err);
                    resolver->reject(errorMsg);
                } else if (result && result->base) {
                    auto data = std::make_shared<std::vector<uint8_t>>(
                        result->base, result->base + result->length);
                    resolver->resolve_with_data(data);
                } else {
                    resolver->resolve_null();
                }
                delete resolver;
            };
            SignalFfiError* err = signal_testing_tokio_async_context_future_success_bytes(&promise, asyncContext_, byteCount);
            if (err) {
                const char* msg = nullptr;
                signal_error_get_message(&msg, err);
                std::string errorMsg = msg ? msg : "Unknown error";
                if (msg) signal_free_string(msg);
                signal_error_free(err);
                resolverPtr->reject(errorMsg);
                delete resolverPtr;
            }
        });
    };
}

// ---------------------------------------------------------------
// Async helpers — uses CallInvoker for thread-safe JS dispatch
// ---------------------------------------------------------------

jsi::Value LibsignalModule::createAsyncCall(
    jsi::Runtime& rt,
    const jsi::Value* args,
    size_t count,
    std::shared_ptr<facebook::react::CallInvoker> callInvoker,
    std::function<void(jsi::Runtime&, const jsi::Value*, size_t, PromiseResolver)> work) {

    // Create a JS Promise
    auto promiseCtor = rt.global().getPropertyAsFunction(rt, "Promise");
    auto promiseCallback = jsi::Function::createFromHostFunction(
        rt,
        jsi::PropNameID::forAscii(rt, "promiseCallback"),
        2,
        [work = std::move(work), args, count, callInvoker](jsi::Runtime& rt,
                             const jsi::Value&,
                             const jsi::Value* promiseArgs,
                             size_t) -> jsi::Value {
            auto resolve = std::make_shared<jsi::Value>(rt, promiseArgs[0]);
            auto reject = std::make_shared<jsi::Value>(rt, promiseArgs[1]);

            PromiseResolver resolver{
                .resolve_bool = [callInvoker, resolve](bool val) {
                    if (callInvoker) {
                        callInvoker->invokeAsync([resolve, val](jsi::Runtime& rt) {
                            resolve->asObject(rt).asFunction(rt).call(rt, jsi::Value(val));
                        });
                    }
                },
                .resolve_int = [callInvoker, resolve](int32_t val) {
                    if (callInvoker) {
                        callInvoker->invokeAsync([resolve, val](jsi::Runtime& rt) {
                            resolve->asObject(rt).asFunction(rt).call(rt, jsi::Value(val));
                        });
                    }
                },
                .resolve_null = [callInvoker, resolve]() {
                    if (callInvoker) {
                        callInvoker->invokeAsync([resolve](jsi::Runtime& rt) {
                            resolve->asObject(rt).asFunction(rt).call(rt, jsi::Value::null());
                        });
                    }
                },
                .reject = [callInvoker, reject](std::string msg) {
                    if (callInvoker) {
                        callInvoker->invokeAsync([reject, msg = std::move(msg)](jsi::Runtime& rt) {
                            auto errCtor = rt.global().getPropertyAsFunction(rt, "Error");
                            auto err = errCtor.callAsConstructor(
                                rt, jsi::String::createFromUtf8(rt, msg));
                            reject->asObject(rt).asFunction(rt).call(rt, std::move(err));
                        });
                    }
                },
                .resolve_with_data = [callInvoker, resolve](std::shared_ptr<std::vector<uint8_t>> data) {
                    if (callInvoker) {
                        callInvoker->invokeAsync([resolve, data](jsi::Runtime& rt) {
                            auto arrayBuffer = rt.global()
                                .getPropertyAsFunction(rt, "ArrayBuffer")
                                .callAsConstructor(rt, static_cast<int>(data->size()))
                                .getObject(rt);
                            auto bufPtr = arrayBuffer.getArrayBuffer(rt).data(rt);
                            memcpy(bufPtr, data->data(), data->size());
                            auto uint8Ctor = rt.global().getPropertyAsFunction(rt, "Uint8Array");
                            auto result = uint8Ctor.callAsConstructor(rt, std::move(arrayBuffer));
                            resolve->asObject(rt).asFunction(rt).call(rt, std::move(result));
                        });
                    }
                },
                .resolve_with_pointer = [callInvoker, resolve](void* ptr) {
                    if (callInvoker) {
                        callInvoker->invokeAsync([resolve, ptr](jsi::Runtime& rt) {
                            if (!ptr) {
                                resolve->asObject(rt).asFunction(rt).call(rt, jsi::Value::null());
                                return;
                            }
                            auto pointerObj = std::make_shared<NativePointer>(ptr, nullptr);
                            auto result = jsi::Object::createFromHostObject(rt, pointerObj);
                            resolve->asObject(rt).asFunction(rt).call(rt, std::move(result));
                        });
                    }
                }
            };

            // The work callback sets up the CPromise and calls the FFI function.
            // The FFI function's CPromise callback will be invoked from the Rust
            // async runtime on a background thread, and will use the resolver
            // (which dispatches via CallInvoker) to safely resolve on the JS thread.
            work(rt, args, count, std::move(resolver));

            return jsi::Value::undefined();
        });

    return promiseCtor.callAsConstructor(rt, promiseCallback);
}

} // namespace libsignal
