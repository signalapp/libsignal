package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.util.guava.Optional;

public class ProtocolUntrustedIdentityException extends ProtocolException {
  public ProtocolUntrustedIdentityException(UntrustedIdentityException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  public ProtocolUntrustedIdentityException(UntrustedIdentityException e, String sender, int senderDevice, int contentHint, Optional<byte[]> groupId) {
    super(e, sender, senderDevice, contentHint, groupId);
  }
}
