# Prevent native methods from being renamed as long as they're used.
-keepclasseswithmembernames,includedescriptorclasses class org.signal.libsignal.** {
    native <methods>;
}

# Keep members that the Rust library accesses directly on a variety of classes.
-keepclassmembers class org.signal.libsignal.** {
    # Accessed by Rust code to retrieve a pointer to a wrapped Rust type.
    long unsafeHandle;
    # Called by Rust code to construct a type that wraps a Rust pointer.
    <init>(long);
}

## Handling for the @CalledFromNative annotation:
#
# The annotation can (should) be attached to anything that is accessed from
# native code. The simple case is methods and fields that are accessed directly
# via JNI.
-keepclassmembers,includedescriptorclasses class org.signal.libsignal.** {
    @org.signal.libsignal.internal.CalledFromNative *;
}

# Native code can access methods on objects whose classes are defined outside
# this library but that implement an interface in this library. Those methods
# need to be preserved since the call sites to them are invisible. We mark
# those methods for keeping, which in turn prevents their implementations
# on other classes from being stripped.
-keepclassmembers @org.signal.libsignal.internal.CalledFromNative interface org.signal.libsignal.** {
    *;
}

# Native code might construct instances of classes that are otherwise unused
# (like exceptions). Prevent these from being removed, but don't say anything
# about the methods that are called. The ones called by native code should be
# annotated separately.
-keep @org.signal.libsignal.internal.CalledFromNative class org.signal.libsignal.**

# As a convenience, enums with @CalledFromNative keep all their values.
-keep @org.signal.libsignal.internal.CalledFromNative enum org.signal.libsignal.** {
    <fields>;
}

# Keep constructors for all our exceptions.
# (This could be more fine-grained but doesn't really have to be.)
-keep,includedescriptorclasses class org.signal.libsignal.**.*Exception {
    <init>(...);
}

# Keep some types that the Rust library constructs unconditionally.
# (The constructors are covered by the above -keepclassmembers)
-keep class org.signal.libsignal.protocol.SignalProtocolAddress
-keep class org.signal.libsignal.protocol.message.* implements org.signal.libsignal.protocol.message.CiphertextMessage

# Keep names for store-related types, and the members used from the Rust library not covered above.
# (Thus, if you don't use a store, it won't be kept.)
-keepnames interface org.signal.libsignal.**.*Store { *; }

-keepnames enum org.signal.libsignal.protocol.state.IdentityKeyStore$Direction { *; }
-keepnames class org.signal.libsignal.**.*Record

# Keep rustls-platform-verifier classes
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }
