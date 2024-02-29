//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.certificate;

import java.util.Optional;
import java.util.UUID;
import junit.framework.TestCase;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

public class SenderCertificateTest extends TestCase {

  private final ECKeyPair trustRoot = Curve.generateKeyPair();

  public void testSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key = Curve.generateKeyPair();
    SenderCertificate senderCertificate =
        createCertificateFor(
            trustRoot,
            UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"),
            "+14151111111",
            31337,
            key.getPublicKey(),
            31337);

    new CertificateValidator(trustRoot.getPublicKey()).validate(senderCertificate, 31336);
  }

  public void testExpiredSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key = Curve.generateKeyPair();

    SenderCertificate senderCertificate =
        createCertificateFor(
            trustRoot,
            UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"),
            "+14151111111",
            31338,
            key.getPublicKey(),
            31337);
    try {
      new CertificateValidator(trustRoot.getPublicKey()).validate(senderCertificate, 31338);
      throw new AssertionError();
    } catch (InvalidCertificateException e) {
      // good
    }
  }

  public void testBadSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key = Curve.generateKeyPair();

    SenderCertificate senderCertificate =
        createCertificateFor(
            trustRoot,
            UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"),
            "+14151111111",
            31338,
            key.getPublicKey(),
            31337);

    byte[] badSignature = senderCertificate.getSerialized();

    badSignature[badSignature.length - 1] ^= 1;

    SenderCertificate badCert = new SenderCertificate(badSignature);

    try {
      new CertificateValidator(trustRoot.getPublicKey()).validate(badCert, 31336);
      throw new AssertionError();
    } catch (InvalidCertificateException e) {
      // good
    }
  }

  public void testGetSenderAci()
      throws InvalidCertificateException, InvalidKeyException, ServiceId.InvalidServiceIdException {
    ECKeyPair key = Curve.generateKeyPair();
    UUID uuid = UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f");
    SenderCertificate senderCertificate =
        createCertificateFor(trustRoot, uuid, null, 31338, key.getPublicKey(), 31337);
    assertEquals(Optional.empty(), senderCertificate.getSenderE164());
    assertEquals(uuid, senderCertificate.getSenderAci().getRawUUID());
  }

  private SenderCertificate createCertificateFor(
      ECKeyPair trustRoot,
      UUID uuid,
      String e164,
      int deviceId,
      ECPublicKey identityKey,
      long expires)
      throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair serverKey = Curve.generateKeyPair();
    ServerCertificate serverCertificate =
        new ServerCertificate(trustRoot.getPrivateKey(), 1, serverKey.getPublicKey());
    return serverCertificate.issue(
        serverKey.getPrivateKey(),
        uuid.toString(),
        Optional.ofNullable(e164),
        deviceId,
        identityKey,
        expires);
  }
}
