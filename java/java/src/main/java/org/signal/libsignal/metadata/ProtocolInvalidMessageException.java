package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.util.guava.Optional;

public class ProtocolInvalidMessageException extends ProtocolException {
  public ProtocolInvalidMessageException(InvalidMessageException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  public ProtocolInvalidMessageException(InvalidMessageException e, String sender, int senderDevice, int contentHint, Optional<byte[]> groupId) {
    super(e, sender, senderDevice, contentHint, groupId);
  }}
