//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException

/**
 * A request relating to a [org.signal.libsignal.protocol.ServiceId] could not be completed as the
 * ServiceId, or its devices, could not be found.
 *
 * See the specific request docs for more information.
 */
public class ServiceIdNotFoundException :
  IOException,
  GetPreKeysError,
  SealedSendFailure {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}
