//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata;

import java.util.Optional;
import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.signal.libsignal.protocol.ServiceId;

public abstract class ProtocolException extends Exception {

  private final Optional<UnidentifiedSenderMessageContent> content;
  private final String sender;
  private final int senderDevice;

  public ProtocolException(Exception e, String sender, int senderDevice) {
    super(e);
    this.content = Optional.empty();
    this.sender = sender;
    this.senderDevice = senderDevice;
  }

  ProtocolException(Exception e, UnidentifiedSenderMessageContent content) {
    super(e);
    this.content = Optional.of(content);
    this.sender = content.getSenderCertificate().getSender();
    this.senderDevice = content.getSenderCertificate().getSenderDeviceId();
  }

  public Optional<UnidentifiedSenderMessageContent> getUnidentifiedSenderMessageContent() {
    return content;
  }

  public String getSender() {
    return sender;
  }

  /** Returns an Aci if the sender is a valid UUID, {@code null} otherwise. */
  public ServiceId.Aci getSenderAci() {
    try {
      return ServiceId.Aci.parseFromString(getSender());
    } catch (ServiceId.InvalidServiceIdException e) {
      return null;
    }
  }

  public int getSenderDevice() {
    return senderDevice;
  }

  public int getContentHint() {
    if (content.isPresent()) {
      return content.get().getContentHint();
    }
    return UnidentifiedSenderMessageContent.CONTENT_HINT_DEFAULT;
  }

  public Optional<byte[]> getGroupId() {
    if (content.isPresent()) {
      return content.get().getGroupId();
    }
    return Optional.<byte[]>empty();
  }
}
