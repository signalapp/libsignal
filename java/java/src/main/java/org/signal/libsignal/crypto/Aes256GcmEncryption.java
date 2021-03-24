//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidKeyException;

public class Aes256GcmEncryption {
  private long handle;

  public Aes256GcmEncryption(byte[] key, byte[] nonce, byte[] associatedData) throws InvalidKeyException {
    this.handle = Native.Aes256GcmEncryption_New(key, nonce, associatedData);
  }

  @Override
  protected void finalize() {
    Native.Aes256GcmEncryption_Destroy(this.handle);
  }

  public void encrypt(byte[] plaintext, int offset, int length) {
     Native.Aes256GcmEncryption_Update(this.handle, plaintext, offset, length);
  }

  public void encrypt(byte[] plaintext) {
    Native.Aes256GcmEncryption_Update(this.handle, plaintext, 0, plaintext.length);
  }

  public byte[] computeTag() {
    byte[] tag = Native.Aes256GcmEncryption_ComputeTag(this.handle);
    Native.Aes256GcmEncryption_Destroy(this.handle);
    this.handle = 0;
    return tag;
  }

}
