//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

@file:Suppress("ktlint:standard:filename") // We'll have more interfaces added later.

package org.signal.libsignal.protocol.state.internal

import org.signal.libsignal.internal.CalledFromNative
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.internal.ObjectHandle

@CalledFromNative
internal interface PreKeyStore {
  @Throws(Exception::class)
  public fun loadPreKey(id: Int): NativeHandleGuard.Owner

  @Throws(Exception::class)
  public fun storePreKey(
    id: Int,
    rawPreKey: ObjectHandle,
  )

  @Throws(Exception::class)
  public fun removePreKey(id: Int)
}
