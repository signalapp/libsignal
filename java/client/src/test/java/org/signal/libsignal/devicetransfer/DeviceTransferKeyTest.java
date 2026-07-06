//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.devicetransfer;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import org.junit.Test;

public class DeviceTransferKeyTest {
  @Test
  public void testDeviceTransferKey() throws Exception {
    DeviceTransferKey key = new DeviceTransferKey();
    byte[] certBytes = key.generateCertificate("name", 365);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    cf.generateCertificate(new ByteArrayInputStream(certBytes));
  }
}
