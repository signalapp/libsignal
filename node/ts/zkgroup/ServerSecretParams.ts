//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';
import { randomBytes } from 'node:crypto';
import * as Native from '../Native.js';

import { RANDOM_LENGTH } from './internal/Constants.js';
import ServerPublicParams from './ServerPublicParams.js';
import NotarySignature from './NotarySignature.js';

export default class ServerSecretParams {
  static generate(): ServerSecretParams {
    const random = randomBytes(RANDOM_LENGTH);

    return ServerSecretParams.generateWithRandom(random);
  }

  static generateWithRandom(random: Bytes): ServerSecretParams {
    return new ServerSecretParams(
      Native.ServerSecretParams_GenerateDeterministic(random)
    );
  }

  readonly _nativeHandle: Native.ServerSecretParams;

  constructor(contents: Bytes | Native.ServerSecretParams) {
    if (contents instanceof Uint8Array) {
      this._nativeHandle = Native.ServerSecretParams_Deserialize(contents);
    } else {
      this._nativeHandle = contents;
    }
  }

  getPublicParams(): ServerPublicParams {
    return new ServerPublicParams(
      Native.ServerSecretParams_GetPublicParams(this)
    );
  }

  sign(message: Bytes): NotarySignature {
    const random = randomBytes(RANDOM_LENGTH);

    return this.signWithRandom(random, message);
  }

  signWithRandom(random: Bytes, message: Bytes): NotarySignature {
    return new NotarySignature(
      Native.ServerSecretParams_SignDeterministic(this, random, message)
    );
  }

  serialize(): Bytes {
    return Native.ServerSecretParams_Serialize(this);
  }
}
