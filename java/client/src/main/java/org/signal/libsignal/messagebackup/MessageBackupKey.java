//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.ServiceId.Aci;

public class MessageBackupKey implements NativeHandleGuard.Owner {

  public MessageBackupKey(byte[] masterKey, Aci aci) {
    this.nativeHandle = Native.MessageBackupKey_New(masterKey, aci.toServiceIdFixedWidthBinary());
  }

  @Override
  public long unsafeNativeHandleWithoutGuard() {
    return nativeHandle;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.MessageBackupKey_Destroy(this.nativeHandle);
  }

  private long nativeHandle;
}
