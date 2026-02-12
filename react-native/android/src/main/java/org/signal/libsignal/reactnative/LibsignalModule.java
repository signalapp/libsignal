package org.signal.libsignal.reactnative;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;
import com.facebook.react.turbomodule.core.interfaces.CallInvokerHolder;

@ReactModule(name = LibsignalModule.NAME)
public class LibsignalModule extends ReactContextBaseJavaModule {
    public static final String NAME = "Libsignal";

    public LibsignalModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return NAME;
    }

    /**
     * Called by React Native on module initialization.
     * Loads the native library and installs JSI bindings.
     */
    @ReactMethod(isBlockingSynchronousMethod = true)
    public boolean install() {
        try {
            // Load the Rust FFI shared library
            System.loadLibrary("signal_ffi");
            // Load and install the JSI bindings
            System.loadLibrary("libsignal-react-native");
            long jsiRuntimePointer = getReactApplicationContext()
                .getJavaScriptContextHolder()
                .get();
            CallInvokerHolder callInvokerHolder = getReactApplicationContext()
                .getJSCallInvokerHolder();
            nativeInstall(jsiRuntimePointer, callInvokerHolder);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static native void nativeInstall(long jsiRuntimePointer, Object callInvokerHolder);
}
