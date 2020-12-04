//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import bindings = require('bindings'); // eslint-disable-line @typescript-eslint/no-require-imports
import * as SignalClient from './libsignal_client';

const SC = bindings('libsignal_client') as typeof SignalClient;

export class PrivateKey {
  private readonly nativeHandle: SignalClient.PrivateKey;

  constructor() {
    this.nativeHandle = SC.PrivateKey_generate();
  }

  serialize(): Buffer {
    return SC.PrivateKey_serialize(this.nativeHandle);
  }
}
