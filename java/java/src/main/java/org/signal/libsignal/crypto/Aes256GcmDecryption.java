//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidKeyException;

public class Aes256GcmDecryption {
  public static final int TAG_SIZE_IN_BYTES = 16;

  private long handle;

  public Aes256GcmDecryption(byte[] key, byte[] nonce, byte[] associatedData) throws InvalidKeyException {
    this.handle = Native.Aes256GcmDecryption_New(key, nonce, associatedData);
  }

  @Override
  protected void finalize() {
    Native.Aes256GcmDecryption_Destroy(this.handle);
  }

  public void decrypt(byte[] plaintext) {
    Native.Aes256GcmDecryption_Update(this.handle, plaintext, 0, plaintext.length);
  }

  public void decrypt(byte[] plaintext, int offset, int length) {
    Native.Aes256GcmDecryption_Update(this.handle, plaintext, offset, length);
  }

  public boolean verifyTag(byte[] tag) {
    boolean tagOk = Native.Aes256GcmDecryption_VerifyTag(this.handle, tag);
    Native.Aes256GcmDecryption_Destroy(this.handle);
    this.handle = 0;
    return tagOk;
  }

}
