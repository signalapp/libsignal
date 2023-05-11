//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.svr2;

import org.signal.libsignal.sgxsession.SgxClient;
import org.signal.libsignal.attest.AttestationDataException;
import org.signal.libsignal.internal.Native;

import java.time.Instant;

/**
 * Svr2Client provides bindings to interact with Signal's v2 Secure Value Recovery service. <p>
 * <p>
 * {@inheritDoc}
 */
public class Svr2Client extends SgxClient {
    private final long groupId;

    private Svr2Client(long unsafeHandle, long groupId) {
        super(unsafeHandle);
        this.groupId = groupId;
    }

    /**
     * Hash a pin so it can be used with SVR2.
     *
     * @param pin An already normalized UTF-8 encoded byte representation of the pin
     * @param username The Basic Auth username used to authenticate with SVR2
     * @return A {@link PinHash}
     */
    public PinHash hashPin(final byte[] pin, final byte[] username) {
        return PinHash.create(pin, username, groupId);
    }


    public static Svr2Client create(byte[] mrenclave, byte[] attestationMsg, Instant currentInstant) throws AttestationDataException {
        long handle = Native.Svr2Client_New(mrenclave, attestationMsg, currentInstant.toEpochMilli());
        try {
            return new Svr2Client(Native.Svr2Client_TakeSgxClientState(handle), Native.Svr2Client_GroupId(handle));
        } finally {
            Native.Svr2Client_Destroy(handle);
        }
    }
}
