//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.zkgroup.InvalidInputException
import org.signal.libsignal.zkgroup.internal.ByteArray as SignalByteArray

/**
 * An account's SVR key: the 32-byte root from which account-related secrets are derived.
 *
 * This is the same key that [org.signal.libsignal.messagebackup.AccountEntropyPool.deriveSvrKey]
 * produces. Signal clients historically call these bytes the "master key"; libsignal calls it the
 * SVR key. The two names refer to the same value.
 *
 * @see AuthAccountsService.setRegistrationLock
 */
public class SvrKey
  @Throws(InvalidInputException::class)
  constructor(
    contents: ByteArray,
  ) : SignalByteArray(contents, SIZE) {
    public companion object {
      public const val SIZE: Int = 32
    }
  }
