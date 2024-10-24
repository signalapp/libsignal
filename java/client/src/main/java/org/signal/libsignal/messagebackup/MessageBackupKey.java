//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.ServiceId.Aci;

public class MessageBackupKey implements NativeHandleGuard.Owner {

  /**
   * @deprecated Use AccountEntropyPool instead.
   */
  @Deprecated
  public MessageBackupKey(byte[] masterKey, Aci aci) {
    this.nativeHandle =
        Native.MessageBackupKey_FromMasterKey(masterKey, aci.toServiceIdFixedWidthBinary());
  }

  /**
   * Derives a MessageBackupKey from the given account entropy pool.
   *
   * <p>{@code accountEntropy} must be a <b>validated</b> account entropy pool; passing an arbitrary
   * String here is considered a programmer error.
   */
  public MessageBackupKey(String accountEntropy, Aci aci) {
    this.nativeHandle =
        Native.MessageBackupKey_FromAccountEntropyPool(
            accountEntropy, aci.toServiceIdFixedWidthBinary());
  }

  /**
   * Derives a MessageBackupKey from a backup key and ID.
   *
   * <p>Used when reading from a local backup, which may have been created with a different ACI.
   *
   * <p>This uses AccountEntropyPool-based key derivation rules; it cannot be used to read a backup
   * created from a master key.
   */
  public MessageBackupKey(byte[] backupKey, byte[] backupId) {
    this.nativeHandle = Native.MessageBackupKey_FromBackupKeyAndBackupId(backupKey, backupId);
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
