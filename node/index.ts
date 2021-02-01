//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as os from 'os';
import bindings = require('bindings'); // eslint-disable-line @typescript-eslint/no-require-imports
import * as SignalClient from './libsignal_client';

const SC = bindings('libsignal_client_' + os.platform()) as typeof SignalClient;

export const { initLogger, LogLevel } = SC;

export class ProtocolAddress {
  private readonly nativeHandle: SignalClient.ProtocolAddress;

  private constructor(handle: SignalClient.ProtocolAddress) {
    this.nativeHandle = handle;
  }

  static fromNativeHandle(
    handle: SignalClient.ProtocolAddress
  ): ProtocolAddress {
    return new ProtocolAddress(handle);
  }

  static new(name: string, deviceId: number): ProtocolAddress {
    return new ProtocolAddress(SC.ProtocolAddress_New(name, deviceId));
  }

  name(): string {
    return SC.ProtocolAddress_Name(this.nativeHandle);
  }

  deviceId(): number {
    return SC.ProtocolAddress_DeviceId(this.nativeHandle);
  }
}

export class PublicKey {
  private readonly nativeHandle: SignalClient.PublicKey;

  private constructor(handle: SignalClient.PublicKey) {
    this.nativeHandle = handle;
  }

  static fromNativeHandle(handle: SignalClient.PublicKey): PublicKey {
    return new PublicKey(handle);
  }

  static deserialize(buf: Buffer): PublicKey {
    return new PublicKey(SC.PublicKey_Deserialize(buf));
  }

  serialize(): Buffer {
    return SC.PublicKey_Serialize(this.nativeHandle);
  }

  verify(msg: Buffer, sig: Buffer): boolean {
    return SC.PublicKey_Verify(this.nativeHandle, msg, sig);
  }

  _unsafeGetNativeHandle(): SignalClient.PublicKey {
    return this.nativeHandle;
  }
}

export class PrivateKey {
  private readonly nativeHandle: SignalClient.PrivateKey;

  private constructor(handle: SignalClient.PrivateKey) {
    this.nativeHandle = handle;
  }

  static generate(): PrivateKey {
    return new PrivateKey(SC.PrivateKey_Generate());
  }

  static deserialize(buf: Buffer): PrivateKey {
    return new PrivateKey(SC.PrivateKey_Deserialize(buf));
  }

  serialize(): Buffer {
    return SC.PrivateKey_Serialize(this.nativeHandle);
  }

  sign(msg: Buffer): Buffer {
    return SC.PrivateKey_Sign(this.nativeHandle, msg);
  }

  agree(other_key: PublicKey): Buffer {
    return SC.PrivateKey_Agree(
      this.nativeHandle,
      other_key._unsafeGetNativeHandle()
    );
  }

  getPublicKey(): PublicKey {
    return PublicKey.fromNativeHandle(
      SC.PrivateKey_GetPublicKey(this.nativeHandle)
    );
  }
}
