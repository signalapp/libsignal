//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.ServiceId.Aci;

abstract class KeyTransparency {
  static byte[] searchKeyForAci(Aci aci) {
    return Native.KeyTransparency_AciSearchKey(aci.toServiceIdFixedWidthBinary());
  }

  static byte[] searchKeyForE164(String e164) {
    return Native.KeyTransparency_E164SearchKey(e164);
  }

  static byte[] searchKeyForUsernameHash(byte[] usernameHash) {
    return Native.KeyTransparency_UsernameHashSearchKey(usernameHash);
  }
}
