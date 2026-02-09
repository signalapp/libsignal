//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#include <jni.h>
#include <jsi/jsi.h>
#include "LibsignalTurboModule.h"

extern "C"
JNIEXPORT void JNICALL
Java_org_signal_libsignal_reactnative_LibsignalModule_nativeInstall(
    JNIEnv* env,
    jobject thiz,
    jlong jsiRuntimePointer) {

    auto* runtime = reinterpret_cast<facebook::jsi::Runtime*>(jsiRuntimePointer);
    if (runtime) {
        libsignal::LibsignalModule::install(*runtime);
    }
}
