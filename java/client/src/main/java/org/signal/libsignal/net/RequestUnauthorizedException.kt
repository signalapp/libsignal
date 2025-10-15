//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import java.io.IOException

/**
 * A request requires authorization, but the provided authorization (if any) was incorrect or
 * insufficient.
 *
 * See the specific request docs for more information.
 */
public class RequestUnauthorizedException :
  IOException,
  MultiRecipientSendFailure {
  public constructor(message: String) : super(message) {}
}
