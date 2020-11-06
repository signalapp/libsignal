package org.signal.libsignal.metadata.certificate;


import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.util.HashSet;
import java.util.Set;

public class CertificateValidator {

  @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
  private static final Set<Integer> REVOKED = new HashSet<Integer>() {{

  }};

  private final ECPublicKey trustRoot;

  public CertificateValidator(ECPublicKey trustRoot) {
    this.trustRoot = trustRoot;
  }

  public void validate(SenderCertificate certificate, long validationTime) throws InvalidCertificateException {
    try {
      ServerCertificate serverCertificate = certificate.getSigner();
      validate(serverCertificate);

      if (!Curve.verifySignature(serverCertificate.getKey(), certificate.getCertificate(), certificate.getSignature())) {
        throw new InvalidCertificateException("Signature failed");
      }

      if (validationTime > certificate.getExpiration()) {
        throw new InvalidCertificateException("Certificate is expired");
      }
    } catch (InvalidKeyException e) {
      throw new InvalidCertificateException(e);
    }
  }

  // VisibleForTesting
  void validate(ServerCertificate certificate) throws InvalidCertificateException {
    try {
      if (!Curve.verifySignature(trustRoot, certificate.getCertificate(), certificate.getSignature())) {
        throw new InvalidCertificateException("Signature failed");
      }

      if (REVOKED.contains(certificate.getKeyId())) {
        throw new InvalidCertificateException("Server certificate has been revoked");
      }
    } catch (InvalidKeyException e) {
      throw new InvalidCertificateException(e);
    }
  }
}

