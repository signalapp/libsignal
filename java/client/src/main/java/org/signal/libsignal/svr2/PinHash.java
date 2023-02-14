//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.svr2;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

/**
 * A hash of the pin that can be used to interact with a Secure Value Recovery service.
 */
public class PinHash implements NativeHandleGuard.Owner {
    private final long unsafeHandle;

    private PinHash(final long unsafeHandle) {
        this.unsafeHandle = unsafeHandle;
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void finalize() {
        Native.PinHash_Destroy(this.unsafeHandle);
    }

    public long unsafeNativeHandleWithoutGuard() {
        return this.unsafeHandle;
    }

    static PinHash create(final byte[] pin, final byte[] salt) {
        return new PinHash(Native.PinHash_FromSalt(pin, salt));
    }

    static PinHash create(final byte[] pin, final byte[] username, final long groupId) {
        return new PinHash(Native.PinHash_FromUsernameGroupId(pin, username, groupId));
    }

    /**
     * A key that can be used to encrypt or decrypt values before uploading them to a secure store.
     *
     * @return a 32 byte encryption key
     */
    public byte[] encryptionKey() {
        return Native.PinHash_EncryptionKey(unsafeHandle);
    }

    /**
     * A secret that can be used to access a value in a secure store.
     *
     * @return a 32 byte access key
     */
    public byte[] accessKey() {
        return Native.PinHash_AccessKey(unsafeHandle);
    }
}
