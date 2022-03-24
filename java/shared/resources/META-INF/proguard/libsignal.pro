# Prevent native methods from being renamed as long as they're used.
-keepclasseswithmembernames,includedescriptorclasses class org.signal.libsignal.** {
    native <methods>;
}

# Keep members that the Rust library accesses directly on a variety of classes.
-keepclassmembers class org.signal.libsignal.** {
    long unsafeHandle;
    <init>(long);

    byte[] serialize();

    void log(...);
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
-keepnames class org.signal.libsignal.protocol.IdentityKey
-keepnames class org.signal.libsignal.**.*Record
