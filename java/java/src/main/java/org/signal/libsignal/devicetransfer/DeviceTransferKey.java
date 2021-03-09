//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.devicetransfer;

import org.signal.client.internal.Native;

public class DeviceTransferKey {
  byte[] keyMaterial;

  DeviceTransferKey() {
    this.keyMaterial = Native.DeviceTransfer_GeneratePrivateKey();
  }

  byte[] keyMaterial() {
    return this.keyMaterial;
  }

  byte[] generateCertificate(String name, int daysTilExpires) {
    return Native.DeviceTransfer_GenerateCertificate(this.keyMaterial, name, daysTilExpires);
  }
}
