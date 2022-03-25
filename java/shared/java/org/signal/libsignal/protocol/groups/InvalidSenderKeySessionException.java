/**
 * Copyright (C) 2021 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.groups;

import java.util.UUID;

public class InvalidSenderKeySessionException extends IllegalStateException {

  private final UUID distributionId;

  public InvalidSenderKeySessionException(UUID distributionId, String message) {
    super(message);
    this.distributionId = distributionId;
  }

  public UUID getDistributionId() {
    return distributionId;
  }
}
