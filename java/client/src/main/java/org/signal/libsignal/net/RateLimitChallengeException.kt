//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.time.Duration
import java.util.EnumSet

/**
 * Thrown when a request should be retried after waiting.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 428} response to
 * requests to a number of endpoints.
 */
public class RateLimitChallengeException :
  ChatServiceException,
  BadRequestError,
  SyncSendFailure,
  UnsealedSendFailure {
  public val token: String
  public val options: Set<ChallengeOption>
  public val retryLater: Duration?

  public constructor(
    message: String,
    token: String,
    options: Array<ChallengeOption>,
    retryLater: Duration?,
  ) : super(message) {
    this.token = token
    this.options = EnumSet.copyOf(options.asList())
    this.retryLater = retryLater
  }

  @CalledFromNative
  internal constructor(
    message: String,
    token: String,
    options: Array<ChallengeOption>,
    retryLater: Long,
  ) : this(
    message,
    token,
    options,
    if (retryLater < 0) null else Duration.ofSeconds(retryLater),
  ) {
  }
}
