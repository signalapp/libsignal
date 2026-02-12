//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native';

function getNative(): any {
  return (globalThis as any).__libsignal_native;
}

/**
 * A device-specific protocol address (name + device ID).
 */
export class ProtocolAddress {
  readonly _nativeHandle: Native.ProtocolAddress;

  private constructor(handle: Native.ProtocolAddress) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.ProtocolAddress): ProtocolAddress {
    return new ProtocolAddress(handle);
  }

  /**
   * Create a new protocol address.
   * @param name The name (typically a phone number or UUID string)
   * @param deviceId The device ID
   */
  static new(name: string, deviceId: number): ProtocolAddress {
    const n = getNative();
    return new ProtocolAddress(n.ProtocolAddress_New(name, deviceId));
  }

  /**
   * Get the name component of this address.
   */
  name(): string {
    const n = getNative();
    return n.ProtocolAddress_Name(this._nativeHandle);
  }

  /**
   * Get the device ID component of this address.
   */
  deviceId(): number {
    const n = getNative();
    return n.ProtocolAddress_DeviceId(this._nativeHandle);
  }
}
