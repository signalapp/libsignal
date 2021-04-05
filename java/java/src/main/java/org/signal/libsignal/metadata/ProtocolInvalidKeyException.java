package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.guava.Optional;

public class ProtocolInvalidKeyException extends ProtocolException {
  public ProtocolInvalidKeyException(InvalidKeyException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  public ProtocolInvalidKeyException(InvalidKeyException e, String sender, int senderDevice, int contentHint, Optional<byte[]> groupId) {
    super(e, sender, senderDevice, contentHint, groupId);
  }
}
