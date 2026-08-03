//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.NativeNice
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
    /** Derives the raw 32-byte token used to enable registration lock. */
    public fun deriveRegistrationLock(): ByteArray = NativeNice.SvrKey_DeriveRegistrationLock(serialize())

    /** Derives the raw 32-byte password used to recover an account without SMS verification. */
    public fun deriveRegistrationRecoveryPassword(): ByteArray =
      NativeNice.SvrKey_DeriveRegistrationRecoveryPassword(serialize())

    /** Derives the raw 32-byte root key used to encrypt data in Storage Service. */
    public fun deriveStorageServiceKey(): ByteArray = NativeNice.SvrKey_DeriveStorageServiceKey(serialize())

    /** Derives the raw 32-byte key used to obscure sensitive identifiers in logs. */
    public fun deriveLoggingKey(): ByteArray = NativeNice.SvrKey_DeriveLoggingKey(serialize())

    public companion object {
      public const val SIZE: Int = 32
    }
  }
