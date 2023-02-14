//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.cds2;

import org.signal.libsignal.attest.AttestationDataException;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

import java.util.Optional;
import java.util.HashMap;
import java.util.Map;
import java.time.Instant;

public final class Cds2Metrics {

    private Cds2Metrics() {}

    /**
     * Parse a cds2 attestation response (ClientHandshakeStart) and return
     * supplemental information extracted from the response's evidence and
     * endorsements.
     *
     * @param attestationMessage A ClientHandshakeStart message
     *
     * @throws AttestationDataException if the attestationMessage cannot be parsed
     */
    public static Map<String, Long> extract(final byte[] attestationMessage) throws AttestationDataException {
        @SuppressWarnings("unchecked")
        Map<String, Long> result = Native.Cds2Metrics_extract(attestationMessage);
        return result;
    }
}

