package org.signal.libsignal.metadata.certificate;


import com.google.protobuf.InvalidProtocolBufferException;

import org.signal.libsignal.metadata.SignalProtos;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.guava.Optional;


public class SenderCertificate {

  private final ServerCertificate signer;
  private final ECPublicKey       key;
  private final int               senderDeviceId;
  private final Optional<String>  senderUuid;
  private final Optional<String>  senderE164;
  private final long              expiration;

  private final byte[] serialized;
  private final byte[] certificate;
  private final byte[] signature;

  public SenderCertificate(byte[] serialized) throws InvalidCertificateException {
    try {
      SignalProtos.SenderCertificate wrapper = SignalProtos.SenderCertificate.parseFrom(serialized);

      if (!wrapper.hasSignature() || !wrapper.hasCertificate()) {
        throw new InvalidCertificateException("Missing fields");
      }

      SignalProtos.SenderCertificate.Certificate certificate = SignalProtos.SenderCertificate.Certificate.parseFrom(wrapper.getCertificate());

      if (!certificate.hasSigner()       ||
          !certificate.hasIdentityKey()  ||
          !certificate.hasSenderDevice() ||
          !certificate.hasExpires()      ||
          (!certificate.hasSenderUuid() && !certificate.hasSenderE164()))
      {
        throw new InvalidCertificateException("Missing fields");
      }

      this.signer         = new ServerCertificate(certificate.getSigner().toByteArray());
      this.key            = Curve.decodePoint(certificate.getIdentityKey().toByteArray(), 0);
      this.senderUuid     = certificate.hasSenderUuid() ? Optional.of(certificate.getSenderUuid()) : Optional.<String>absent();
      this.senderE164     = certificate.hasSenderE164() ? Optional.of(certificate.getSenderE164()) : Optional.<String>absent();
      this.senderDeviceId = certificate.getSenderDevice();
      this.expiration     = certificate.getExpires();

      this.serialized  = serialized;
      this.certificate = wrapper.getCertificate().toByteArray();
      this.signature   = wrapper.getSignature().toByteArray();

    } catch (InvalidProtocolBufferException | InvalidKeyException e) {
      throw new InvalidCertificateException(e);
    }
  }

  public ServerCertificate getSigner() {
    return signer;
  }

  public ECPublicKey getKey() {
    return key;
  }

  public int getSenderDeviceId() {
    return senderDeviceId;
  }

  public Optional<String> getSenderUuid() {
    return senderUuid;
  }

  public Optional<String> getSenderE164() {
    return senderE164;
  }

  public String getSender() {
    return senderE164.or(senderUuid).orNull();
  }

  public long getExpiration() {
    return expiration;
  }

  public byte[] getSerialized() {
    return serialized;
  }

  public byte[] getCertificate() {
    return certificate;
  }

  public byte[] getSignature() {
    return signature;
  }
}
