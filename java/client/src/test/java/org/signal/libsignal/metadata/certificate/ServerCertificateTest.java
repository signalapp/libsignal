//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.certificate;

import junit.framework.TestCase;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;

public class ServerCertificateTest extends TestCase {

  public void testSignature() throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair keyPair = Curve.generateKeyPair();
    ServerCertificate certificate =
        new ServerCertificate(trustRoot.getPrivateKey(), 1, keyPair.getPublicKey());

    new CertificateValidator(trustRoot.getPublicKey()).validate(certificate);

    byte[] serialized = certificate.getSerialized();
    new CertificateValidator(trustRoot.getPublicKey()).validate(new ServerCertificate(serialized));
  }

  public void testBadSignature() throws Exception {
    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair keyPair = Curve.generateKeyPair();

    ServerCertificate certificate =
        new ServerCertificate(trustRoot.getPrivateKey(), 1, keyPair.getPublicKey());

    byte[] badSignature = certificate.getSerialized();

    badSignature[badSignature.length - 1] ^= 1;

    ServerCertificate badCert = new ServerCertificate(badSignature);

    try {
      new CertificateValidator(trustRoot.getPublicKey())
          .validate(new ServerCertificate(badSignature));
      fail();
    } catch (InvalidCertificateException e) {
      // good
    }
  }
}
