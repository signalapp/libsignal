//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.usernames

import org.signal.libsignal.zkgroup.InvalidInputException
import org.signal.libsignal.zkgroup.internal.ByteArray as SignalByteArray

/**
 * A 32-byte hash of a username, as computed by [Username.getHash].
 *
 * This is the value the Signal service stores and looks accounts up by, rather than the username
 * itself.
 */
public class UsernameHash
  @Throws(InvalidInputException::class)
  constructor(
    contents: ByteArray,
  ) : SignalByteArray(contents, SIZE) {
    public companion object {
      public const val SIZE: Int = 32
    }
  }
