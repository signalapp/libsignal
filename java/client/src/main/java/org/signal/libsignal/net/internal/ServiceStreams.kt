//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Eventually there will be more streams here.
@file:Suppress("ktlint:standard:filename")

package org.signal.libsignal.net.internal

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.internal.ObjectHandle

// `public` so that NativeNice's methods can reference it, which are in turn public for testing
// reasons.
public class CopyBackupMediaStream(
  handle: ObjectHandle,
) : NativeHandleGuard.SimpleOwner(handle) {
  override fun release(nativeHandle: ObjectHandle) {
    Native.CopyBackupMediaStream_Destroy(nativeHandle)
  }
}
