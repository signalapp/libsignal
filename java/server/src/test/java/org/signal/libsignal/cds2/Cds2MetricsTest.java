//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.cds2;

import org.signal.libsignal.attest.AttestationDataException;

import junit.framework.TestCase;
import java.io.InputStream;
import java.util.Map;
import java.util.Arrays;


public class Cds2MetricsTest extends TestCase {
    private byte[] attestationMsg;
    protected void setUp() throws Exception {
        super.setUp();

        // Test data should be ~14k
        attestationMsg = new byte[15_000];

        try (InputStream stream = getClass().getResourceAsStream("clienthandshakestart.data")) {
            assert stream != null;
            int read = stream.read(attestationMsg);
            // should be empty
            assert(stream.read() == -1);
            attestationMsg = Arrays.copyOf(attestationMsg, read);
        }
    }

    public void testValidMetrics() throws AttestationDataException {
        Map<String, Long> metrics = Cds2Metrics.extract(attestationMsg);
        // 2022-08-14 02:31:29 UTC
        assertEquals(metrics.get("tcb_info_expiration_ts").longValue(), 1658440468);
        // May 21 10:50:10 2018 GMT
        assertEquals(metrics.get("tcb_signer_not_before_ts").longValue(), 1526899810);
        // May 21 10:50:10 2025 GMT
        assertEquals(metrics.get("tcb_signer_not_after_ts").longValue(), 1747824610);
    }
}
