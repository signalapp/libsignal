//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

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

  static generateWithRandom(random: Uint8Array): ServerSecretParams {
    return new ServerSecretParams(
      Native.ServerSecretParams_GenerateDeterministic(random)
    );
  }

  readonly _nativeHandle: Native.ServerSecretParams;

  constructor(contents: Uint8Array | Native.ServerSecretParams) {
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

  sign(message: Uint8Array): NotarySignature {
    const random = randomBytes(RANDOM_LENGTH);

    return this.signWithRandom(random, message);
  }

  signWithRandom(random: Uint8Array, message: Uint8Array): NotarySignature {
    return new NotarySignature(
      Native.ServerSecretParams_SignDeterministic(this, random, message)
    );
  }

  serialize(): Uint8Array {
    return Native.ServerSecretParams_Serialize(this);
  }
}
