//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.devicetransfer;

import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;

public class DeviceTransferKeyTest extends TestCase {
  public void testDeviceTransferKey() throws Exception {
    DeviceTransferKey key = new DeviceTransferKey();
    byte[] certBytes = key.generateCertificate("name", 365);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    cf.generateCertificate(new ByteArrayInputStream(certBytes));
  }
}
