//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

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

// `public` so that NativeNice's methods can reference it, which are in turn public for testing
// reasons.
public class DeleteBackupMediaStream(
  handle: ObjectHandle,
) : NativeHandleGuard.SimpleOwner(handle) {
  override fun release(nativeHandle: ObjectHandle) {
    Native.DeleteBackupMediaStream_Destroy(nativeHandle)
  }
}
