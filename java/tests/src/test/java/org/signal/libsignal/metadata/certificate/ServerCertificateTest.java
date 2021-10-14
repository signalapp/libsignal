package org.signal.libsignal.metadata.certificate;

import junit.framework.TestCase;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;

public class ServerCertificateTest extends TestCase {

  public void testSignature() throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair keyPair   = Curve.generateKeyPair();

    try (
      NativeHandleGuard serverPublicGuard = new NativeHandleGuard(keyPair.getPublicKey());
      NativeHandleGuard trustRootPrivateGuard = new NativeHandleGuard(trustRoot.getPrivateKey());
    ) {
      ServerCertificate certificate = new ServerCertificate(
         Native.ServerCertificate_New(1, serverPublicGuard.nativeHandle(), trustRootPrivateGuard.nativeHandle()));
  
      new CertificateValidator(trustRoot.getPublicKey()).validate(certificate);
  
      byte[] serialized = certificate.getSerialized();
      new CertificateValidator(trustRoot.getPublicKey()).validate(new ServerCertificate(serialized));  
    }
  }

  public void testBadSignature() throws Exception {
    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair keyPair   = Curve.generateKeyPair();

    try (
      NativeHandleGuard serverPublicGuard = new NativeHandleGuard(keyPair.getPublicKey());
      NativeHandleGuard trustRootPrivateGuard = new NativeHandleGuard(trustRoot.getPrivateKey());
    ) {
      ServerCertificate certificate = new ServerCertificate(
         Native.ServerCertificate_New(1, serverPublicGuard.nativeHandle(), trustRootPrivateGuard.nativeHandle()));

      byte[] badSignature = certificate.getSerialized();

      badSignature[badSignature.length - 1] ^= 1;

      ServerCertificate badCert = new ServerCertificate(badSignature);

      try {
         new CertificateValidator(trustRoot.getPublicKey()).validate(new ServerCertificate(badSignature));
         fail();
      } catch (InvalidCertificateException e) {
         // good
      }
    }
  }

}
