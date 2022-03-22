/**
 * Copyright (C) 2021 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.signal.libsignal.internal;

/**
 * Provides access to a Rust object handle while keeping the Java wrapper alive.
 *
 * Intended for use with try-with-resources syntax. NativeHandleGuard prevents the Java wrapper from
 * being finalized, which would destroy the Rust object, while the handle is in use.
 * To use it, the Java wrapper type should conform to the {@link NativeHandleGuard.Owner} interface.
 * 
 * Note that it is not necessary to use NativeHandleGuard in the implementation of {@code finalize} 
 * itself. The point of NativeHandleGuard is to delay finalization while the Rust object is being
 * used; once finalization has begun, there can be no other uses of the Rust object from Java.
 */
public class NativeHandleGuard implements AutoCloseable {
    /**
     * @see NativeHandleGuard
     */
    public static interface Owner {
        long unsafeNativeHandleWithoutGuard();
    }

    private final Owner owner;

    public NativeHandleGuard(Owner owner) {
        this.owner = owner;
    }

    /**
     * Returns the native handle owned by the Java object, or 0 if the owner is {@code null}.
     */
    public long nativeHandle() {
        if (owner == null) {
            return 0;
        }
        return owner.unsafeNativeHandleWithoutGuard();
    }

    public void close() {
        // Act as an optimization barrier, so the whole guard doesn't get inlined away.
        // (In Java 9 we'd use Reference.reachabilityFence() for the same effect.)
        Native.keepAlive(this.owner);
    }
}