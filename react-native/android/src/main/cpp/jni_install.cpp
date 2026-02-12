//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#include <jni.h>
#include <jsi/jsi.h>
#include <fbjni/fbjni.h>
#include <ReactCommon/CallInvokerHolder.h>
#include "LibsignalTurboModule.h"

extern "C"
JNIEXPORT void JNICALL
Java_org_signal_libsignal_reactnative_LibsignalModule_nativeInstall(
    JNIEnv* env,
    jobject thiz,
    jlong jsiRuntimePointer,
    jobject callInvokerHolder) {

    auto* runtime = reinterpret_cast<facebook::jsi::Runtime*>(jsiRuntimePointer);
    if (runtime) {
        std::shared_ptr<facebook::react::CallInvoker> callInvoker = nullptr;
        if (callInvokerHolder) {
            auto holder = facebook::jni::make_local(
                reinterpret_cast<facebook::react::CallInvokerHolder::javaobject>(callInvokerHolder));
            callInvoker = holder->cthis()->getCallInvoker();
        }
        libsignal::LibsignalModule::install(*runtime, callInvoker);
    }
}
