//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.util.EnumSet

/**
 * Thrown when a request should be retried after waiting.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 428} response to
 * requests to a number of endpoints.
 */
public class RateLimitChallengeException : ChatServiceException {
  public val token: String
  public val options: Set<ChallengeOption>

  @CalledFromNative
  public constructor(message: String, token: String, options: Array<ChallengeOption>) : super(message) {
    this.token = token
    this.options = EnumSet.copyOf(options.asList())
  }
}
