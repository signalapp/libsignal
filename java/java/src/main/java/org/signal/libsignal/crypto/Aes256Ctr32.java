//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidKeyException;

public class Aes256Ctr32 {
  private final long handle;

  public Aes256Ctr32(byte[] key, byte[] nonce, int initialCtr) throws InvalidKeyException {
    this.handle = Native.Aes256Ctr32_New(key, nonce, initialCtr);
  }

  @Override
  protected void finalize() {
    Native.Aes256Ctr32_Destroy(this.handle);
  }

  public void process(byte[] data) {
    Native.Aes256Ctr32_Process(this.handle, data, 0, data.length);
  }

  public void process(byte[] data, int offset, int length) {
    Native.Aes256Ctr32_Process(this.handle, data, offset, length);
  }

}
