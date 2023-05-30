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


    /**
     * Hash a pin for use with a remote SecureValueRecovery1 service.
     *
     * Note: This should be used with SVR1 only. For SVR1, the salt should be the backup id.
     * For SVR2 clients, use {@link PinHash#svr2} which handles salt selection internally.
     *
     * @param pin A normalized, UTF-8 encoded byte representation of the pin
     * @param salt A 32 byte salt
     * @return A {@link PinHash}
     */
    public static PinHash svr1(final byte[] normalizedPin, final byte[] salt) {
        return new PinHash(Native.PinHash_FromSalt(normalizedPin, salt));
    }

    /**
     * Hash a pin for use with a remote SecureValueRecovery2 service.
     *
     * Note: This should be used with SVR2 only. For SVR1 clients, use {@link PinHash#svr1}
     *
     * @param pin A normalized, UTF-8 encoded byte representation of the pin
     * @param username The Basic Auth username used to authenticate with SVR2
     * @param mrenclave The mrenclave where the hashed pin will be stored
     * @return A {@link PinHash}
     */
    public static PinHash svr2(final byte[] normalizedPin, final String username, final byte[] mrenclave) {
        return new PinHash(Native.PinHash_FromUsernameMrenclave(normalizedPin, username, mrenclave));
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
