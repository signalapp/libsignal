//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.devicetransfer;

import org.signal.libsignal.internal.Native;

public class DeviceTransferKey {
  byte[] keyMaterial;

  public DeviceTransferKey() {
    this.keyMaterial = Native.DeviceTransfer_GeneratePrivateKey();
  }

  public byte[] keyMaterial() {
    return this.keyMaterial;
  }

  public byte[] generateCertificate(String name, int daysTilExpires) {
    return Native.DeviceTransfer_GenerateCertificate(this.keyMaterial, name, daysTilExpires);
  }
}
