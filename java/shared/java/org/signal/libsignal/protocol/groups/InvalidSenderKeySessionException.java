//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

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
