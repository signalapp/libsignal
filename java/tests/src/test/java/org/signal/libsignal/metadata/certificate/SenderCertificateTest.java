package org.signal.libsignal.metadata.certificate;


import com.google.protobuf.ByteString;

import junit.framework.TestCase;

import org.signal.libsignal.metadata.SignalProtos;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

public class SenderCertificateTest extends TestCase {

  private final ECKeyPair trustRoot = Curve.generateKeyPair();

  public void testSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair serverKey = Curve.generateKeyPair();
    ECKeyPair key       = Curve.generateKeyPair();

    byte[] certificateBytes = SignalProtos.SenderCertificate.Certificate.newBuilder()
                                                                        .setSenderUuid("9d0652a3-dcc3-4d11-975f-74d61598733f")
                                                                        .setSenderE164("+14152222222")
                                                                        .setSenderDevice(1)
                                                                        .setExpires(31337)
                                                                        .setIdentityKey(ByteString.copyFrom(key.getPublicKey().serialize()))
                                                                        .setSigner(getServerCertificate(serverKey))
                                                                        .build()
                                                                        .toByteArray();

    byte[] certificateSignature = Curve.calculateSignature(serverKey.getPrivateKey(), certificateBytes);

    SenderCertificate senderCertificate  = new SenderCertificate(SignalProtos.SenderCertificate.newBuilder()
                                                                                               .setCertificate(ByteString.copyFrom(certificateBytes))
                                                                                               .setSignature(ByteString.copyFrom(certificateSignature))
                                                                                               .build()
                                                                                               .toByteArray());

    new CertificateValidator(trustRoot.getPublicKey()).validate(senderCertificate, 31336);
  }

  public void testExpiredSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair serverKey = Curve.generateKeyPair();
    ECKeyPair key       = Curve.generateKeyPair();

    byte[] certificateBytes = SignalProtos.SenderCertificate.Certificate.newBuilder()
                                                                        .setSenderUuid("9d0652a3-dcc3-4d11-975f-74d61598733f")
                                                                        .setSenderE164("+14152222222")
                                                                        .setSenderDevice(1)
                                                                        .setExpires(31337)
                                                                        .setIdentityKey(ByteString.copyFrom(key.getPublicKey().serialize()))
                                                                        .setSigner(getServerCertificate(serverKey))
                                                                        .build()
                                                                        .toByteArray();

    byte[] certificateSignature = Curve.calculateSignature(serverKey.getPrivateKey(), certificateBytes);

    SenderCertificate senderCertificate  = new SenderCertificate(SignalProtos.SenderCertificate.newBuilder()
                                                                                               .setCertificate(ByteString.copyFrom(certificateBytes))
                                                                                               .setSignature(ByteString.copyFrom(certificateSignature))
                                                                                               .build()
                                                                                               .toByteArray());

    try {
      new CertificateValidator(trustRoot.getPublicKey()).validate(senderCertificate, 31338);
      throw new AssertionError();
    } catch (InvalidCertificateException e) {
      // good
    }
  }

  public void testBadSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair serverKey = Curve.generateKeyPair();
    ECKeyPair key       = Curve.generateKeyPair();

    byte[] certificateBytes = SignalProtos.SenderCertificate.Certificate.newBuilder()
                                                                        .setSenderUuid("9d0652a3-dcc3-4d11-975f-74d61598733f")
                                                                        .setSenderE164("+14152222222")
                                                                        .setSenderDevice(1)
                                                                        .setExpires(31337)
                                                                        .setIdentityKey(ByteString.copyFrom(key.getPublicKey().serialize()))
                                                                        .setSigner(getServerCertificate(serverKey))
                                                                        .build()
                                                                        .toByteArray();

    byte[] certificateSignature = Curve.calculateSignature(serverKey.getPrivateKey(), certificateBytes);

    for (int i=0;i<certificateSignature.length;i++) {
      for (int b=0;b<8;b++) {
        byte[] badSignature = new byte[certificateSignature.length];
        System.arraycopy(certificateSignature, 0, badSignature, 0, certificateSignature.length);

        badSignature[i] = (byte)(badSignature[i] ^ 1 << b);

        SenderCertificate senderCertificate = new SenderCertificate(SignalProtos.SenderCertificate.newBuilder()
                                                                                                  .setCertificate(ByteString.copyFrom(certificateBytes))
                                                                                                  .setSignature(ByteString.copyFrom(badSignature))
                                                                                                  .build()
                                                                                                  .toByteArray());


        try {
          new CertificateValidator(trustRoot.getPublicKey()).validate(senderCertificate, 31336);
          throw new AssertionError();
        } catch (InvalidCertificateException e) {
          // good
        }
      }
    }

  }


  private SignalProtos.ServerCertificate getServerCertificate(ECKeyPair serverKey) throws InvalidKeyException, InvalidCertificateException {
    byte[] certificateBytes = SignalProtos.ServerCertificate.Certificate.newBuilder()
                                                                        .setId(1)
                                                                        .setKey(ByteString.copyFrom(serverKey.getPublicKey().serialize()))
                                                                        .build()
                                                                        .toByteArray();

    byte[] certificateSignature = Curve.calculateSignature(trustRoot.getPrivateKey(), certificateBytes);

    return SignalProtos.ServerCertificate.newBuilder()
                                         .setCertificate(ByteString.copyFrom(certificateBytes))
                                         .setSignature(ByteString.copyFrom(certificateSignature))
                                         .build();
  }


}
