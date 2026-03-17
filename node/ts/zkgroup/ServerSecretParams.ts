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

  static generateWithRandom(
    random: Uint8Array<ArrayBuffer>
  ): ServerSecretParams {
    return new ServerSecretParams(
      Native.ServerSecretParams_GenerateDeterministic(random)
    );
  }

  readonly _nativeHandle: Native.ServerSecretParams;

  constructor(contents: Uint8Array<ArrayBuffer> | Native.ServerSecretParams) {
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

  sign(message: Uint8Array<ArrayBuffer>): NotarySignature {
    const random = randomBytes(RANDOM_LENGTH);

    return this.signWithRandom(random, message);
  }

  signWithRandom(
    random: Uint8Array<ArrayBuffer>,
    message: Uint8Array<ArrayBuffer>
  ): NotarySignature {
    return new NotarySignature(
      Native.ServerSecretParams_SignDeterministic(this, random, message)
    );
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.ServerSecretParams_Serialize(this);
  }
}
