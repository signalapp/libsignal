package org.signal.libsignal.metadata.certificate;

import com.google.protobuf.ByteString;

import junit.framework.TestCase;

import org.signal.libsignal.metadata.SignalProtos;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

public class ServerCertificateTest extends TestCase {

  public void testBadFields() {
    SignalProtos.ServerCertificate.Certificate.Builder certificate = SignalProtos.ServerCertificate.Certificate.newBuilder();

    try {
      new ServerCertificate(SignalProtos.ServerCertificate.newBuilder().setSignature(ByteString.copyFrom(new byte[64])).build().toByteArray());
      throw new AssertionError();
    } catch (InvalidCertificateException e) {
      // good
    }

    try {
      new ServerCertificate(SignalProtos.ServerCertificate.newBuilder().setCertificate(certificate.build().toByteString())
                                                          .setSignature(ByteString.copyFrom(new byte[64])).build().toByteArray());
      throw new AssertionError();
    } catch (InvalidCertificateException e) {
      // good
    }

    try {
      new ServerCertificate(SignalProtos.ServerCertificate.newBuilder().setCertificate(certificate.setId(1).build().toByteString())
                                                          .setSignature(ByteString.copyFrom(new byte[64])).build().toByteArray());
      throw new AssertionError();
    } catch (InvalidCertificateException e) {
      // good
    }
  }

  public void testSignature() throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair keyPair   = Curve.generateKeyPair();

    SignalProtos.ServerCertificate.Certificate certificate = SignalProtos.ServerCertificate.Certificate.newBuilder()
        .setId(1)
        .setKey(ByteString.copyFrom(keyPair.getPublicKey().serialize()))
        .build();

    byte[] certificateBytes     = certificate.toByteArray();
    byte[] certificateSignature = Curve.calculateSignature(trustRoot.getPrivateKey(), certificateBytes);

    byte[] serialized = SignalProtos.ServerCertificate.newBuilder()
                                                      .setCertificate(ByteString.copyFrom(certificateBytes))
                                                      .setSignature(ByteString.copyFrom(certificateSignature))
                                                      .build().toByteArray();

    new CertificateValidator(trustRoot.getPublicKey()).validate(new ServerCertificate(serialized));
  }

  public void testBadSignature() throws Exception {
    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair keyPair   = Curve.generateKeyPair();

    SignalProtos.ServerCertificate.Certificate certificate = SignalProtos.ServerCertificate.Certificate.newBuilder()
                                                                                                       .setId(1)
                                                                                                       .setKey(ByteString.copyFrom(keyPair.getPublicKey().serialize()))
                                                                                                       .build();

    byte[] certificateBytes     = certificate.toByteArray();
    byte[] certificateSignature = Curve.calculateSignature(trustRoot.getPrivateKey(), certificateBytes);

    for (int i=0;i<certificateSignature.length;i++) {
      for (int b=0;b<8;b++) {
        byte[] badSignature = new byte[certificateSignature.length];
        System.arraycopy(certificateSignature, 0, badSignature, 0, badSignature.length);

        badSignature[i] = (byte) (badSignature[i] ^ (1 << b));

        byte[] serialized = SignalProtos.ServerCertificate.newBuilder()
                                                          .setCertificate(ByteString.copyFrom(certificateBytes))
                                                          .setSignature(ByteString.copyFrom(badSignature))
                                                          .build().toByteArray();

        try {
          new CertificateValidator(trustRoot.getPublicKey()).validate(new ServerCertificate(serialized));
          throw new AssertionError();
        } catch (InvalidCertificateException e) {
          // good
        }
      }
    }

    for (int i=0;i<certificateBytes.length;i++) {
      for (int b=0;b<8;b++) {
        byte[] badCertificate = new byte[certificateBytes.length];
        System.arraycopy(certificateBytes, 0, badCertificate, 0, badCertificate.length);

        badCertificate[i] = (byte) (badCertificate[i] ^ (1 << b));

        byte[] serialized = SignalProtos.ServerCertificate.newBuilder()
                                                          .setCertificate(ByteString.copyFrom(badCertificate))
                                                          .setSignature(ByteString.copyFrom(certificateSignature))
                                                          .build().toByteArray();

        try {
          new CertificateValidator(trustRoot.getPublicKey()).validate(new ServerCertificate(serialized));
          throw new AssertionError();
        } catch (InvalidCertificateException e) {
          // good
        }
      }
    }

  }

}
