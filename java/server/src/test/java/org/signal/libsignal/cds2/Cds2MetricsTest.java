//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.cds2;

import static org.junit.Assert.assertEquals;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Map;
import org.junit.Test;

public class Cds2MetricsTest {
  @Test
  public void testValidMetrics() throws Exception {
    // First, the setup
    // Test data should be ~14k
    byte[] attestationMsg = new byte[15_000];

    try (InputStream stream = getClass().getResourceAsStream("clienthandshakestart.data")) {
      assert stream != null;
      int read = stream.read(attestationMsg);
      // should be empty
      assertEquals(-1, stream.read());
      attestationMsg = Arrays.copyOf(attestationMsg, read);
    }

    Map<String, Long> metrics = Cds2Metrics.extract(attestationMsg);
    // 2022-08-14 02:31:29 UTC
    assertEquals(metrics.get("tcb_info_expiration_ts").longValue(), 1658440468);
    // May 21 10:50:10 2018 GMT
    assertEquals(metrics.get("tcb_signer_not_before_ts").longValue(), 1526899810);
    // May 21 10:50:10 2025 GMT
    assertEquals(metrics.get("tcb_signer_not_after_ts").longValue(), 1747824610);
  }
}
