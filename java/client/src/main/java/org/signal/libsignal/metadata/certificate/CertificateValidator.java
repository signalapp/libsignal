package org.signal.libsignal.metadata.certificate;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.InvalidKeyException;

public class CertificateValidator {
  private final ECPublicKey trustRoot;

  public CertificateValidator(ECPublicKey trustRoot) {
    this.trustRoot = trustRoot;
  }

  public ECPublicKey getTrustRoot() {
    return this.trustRoot;
  }

  public void validate(SenderCertificate certificate, long validationTime) throws InvalidCertificateException {
    try (
      NativeHandleGuard certificateGuard = new NativeHandleGuard(certificate);
      NativeHandleGuard trustRootGuard = new NativeHandleGuard(trustRoot);
    ) {
       if (!Native.SenderCertificate_Validate(certificateGuard.nativeHandle(), trustRootGuard.nativeHandle(), validationTime)) {
         throw new InvalidCertificateException("Validation failed");
       }
    } catch (Exception e) {
      throw new InvalidCertificateException(e);
    }
  }

  // VisibleForTesting
  void validate(ServerCertificate certificate) throws InvalidCertificateException {
    try {
      if (!Curve.verifySignature(trustRoot, certificate.getCertificate(), certificate.getSignature())) {
        throw new InvalidCertificateException("Signature failed");
      }
    } catch (InvalidKeyException e) {
      throw new InvalidCertificateException(e);
    }
  }
}
