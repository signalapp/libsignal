package org.signal.libsignal.metadata.certificate;

import junit.framework.TestCase;

import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

import java.util.UUID;

public class SenderCertificateTest extends TestCase {

  private final ECKeyPair trustRoot = Curve.generateKeyPair();

  public void testSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 31337, key.getPublicKey(), 31337);

    new CertificateValidator(trustRoot.getPublicKey()).validate(senderCertificate, 31336);
  }

  public void testExpiredSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key       = Curve.generateKeyPair();

    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 31338, key.getPublicKey(), 31337);
    try {
      new CertificateValidator(trustRoot.getPublicKey()).validate(senderCertificate, 31338);
      throw new AssertionError();
    } catch (InvalidCertificateException e) {
      // good
    }
  }

  public void testBadSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key       = Curve.generateKeyPair();

    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 31338, key.getPublicKey(), 31337);

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

  private SenderCertificate createCertificateFor(ECKeyPair trustRoot, UUID uuid, String e164, int deviceId, ECPublicKey identityKey, long expires)
      throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair serverKey = Curve.generateKeyPair();

    try (
      NativeHandleGuard serverPublicGuard = new NativeHandleGuard(serverKey.getPublicKey());
      NativeHandleGuard trustRootPrivateGuard = new NativeHandleGuard(trustRoot.getPrivateKey());
    ) {
      ServerCertificate serverCertificate = new ServerCertificate(Native.ServerCertificate_New(1, serverPublicGuard.nativeHandle(), trustRootPrivateGuard.nativeHandle()));

      try (
        NativeHandleGuard identityGuard = new NativeHandleGuard(identityKey);
        NativeHandleGuard serverCertificateGuard = new NativeHandleGuard(serverCertificate);
        NativeHandleGuard serverPrivateGuard = new NativeHandleGuard(serverKey.getPrivateKey());
      ) {
        return new SenderCertificate(Native.SenderCertificate_New(uuid.toString(), e164, deviceId, identityGuard.nativeHandle(), expires, serverCertificateGuard.nativeHandle(), serverPrivateGuard.nativeHandle()));
      }
    }
  }
}
