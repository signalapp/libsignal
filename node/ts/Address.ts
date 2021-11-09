//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native';

export class ProtocolAddress {
  readonly _nativeHandle: Native.ProtocolAddress;

  private constructor(handle: Native.ProtocolAddress) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.ProtocolAddress): ProtocolAddress {
    return new ProtocolAddress(handle);
  }

  static new(name: string, deviceId: number): ProtocolAddress {
    return new ProtocolAddress(Native.ProtocolAddress_New(name, deviceId));
  }

  name(): string {
    return Native.ProtocolAddress_Name(this);
  }

  deviceId(): number {
    return Native.ProtocolAddress_DeviceId(this);
  }
}
