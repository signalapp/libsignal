//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]

use jni::objects::JClass;
use jni::JNIEnv;
// Import bridged functions. Without this, the compiler and/or linker are too
// smart and don't include the symbols in the library.
#[allow(unused_imports)]
use libsignal_bridge_testing::*;
use libsignal_bridge_types::jni::run_ffi_safe;

/// Initialize internal data structures.
///
/// Initialization function used to set up internal data structures. This should be called once when
/// the library is first loaded. Must support being run in the same shared object as the
/// `initializeLibrary` in libsignal-jni, as well as the intended use case of running in a different
/// one.
#[no_mangle]
pub unsafe extern "C" fn Java_org_signal_libsignal_internal_NativeTesting_initializeLibrary<
    'local,
>(
    mut env: JNIEnv<'local>,
    class: JClass<'local>,
) {
    run_ffi_safe(&mut env, |env| {
        #[cfg(target_os = "android")]
        libsignal_bridge_types::jni::save_class_loader(env, &class)?;

        // Silence the unused variable warning on non-Android.
        _ = class;
        _ = env;

        Ok(())
    })
}
