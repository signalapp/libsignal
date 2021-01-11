//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as os from 'os';
import bindings = require('bindings'); // eslint-disable-line @typescript-eslint/no-require-imports
import * as SignalClient from './libsignal_client';

const SC = bindings('libsignal_client_' + os.platform()) as typeof SignalClient;

export class PublicKey {
  private readonly nativeHandle: SignalClient.PublicKey;

  private constructor(handle: SignalClient.PublicKey) {
    this.nativeHandle = handle;
  }

  static fromNativeHandle(handle: SignalClient.PublicKey): PublicKey {
    return new PublicKey(handle);
  }

  static deserialize(buf: Buffer): PublicKey {
    return new PublicKey(SC.PublicKey_deserialize(buf));
  }

  serialize(): Buffer {
    return SC.PublicKey_serialize(this.nativeHandle);
  }

  verify(msg: Buffer, sig: Buffer): boolean {
    return SC.PublicKey_verify(this.nativeHandle, msg, sig);
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
    return new PrivateKey(SC.PrivateKey_generate());
  }

  static deserialize(buf: Buffer): PrivateKey {
    return new PrivateKey(SC.PrivateKey_deserialize(buf));
  }

  serialize(): Buffer {
    return SC.PrivateKey_serialize(this.nativeHandle);
  }

  sign(msg: Buffer): Buffer {
    return SC.PrivateKey_sign(this.nativeHandle, msg);
  }

  agree(other_key: PublicKey): Buffer {
    return SC.PrivateKey_agree(
      this.nativeHandle,
      other_key._unsafeGetNativeHandle()
    );
  }

  getPublicKey(): PublicKey {
    return PublicKey.fromNativeHandle(
      SC.PrivateKey_getPublicKey(this.nativeHandle)
    );
  }
}
