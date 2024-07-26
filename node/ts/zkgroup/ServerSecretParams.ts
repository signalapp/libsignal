//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';
import * as Native from '../../Native';

import { RANDOM_LENGTH } from './internal/Constants';
import ServerPublicParams from './ServerPublicParams';
import NotarySignature from './NotarySignature';

export default class ServerSecretParams {
  static generate(): ServerSecretParams {
    const random = randomBytes(RANDOM_LENGTH);

    return ServerSecretParams.generateWithRandom(random);
  }

  static generateWithRandom(random: Buffer): ServerSecretParams {
    return new ServerSecretParams(
      Native.ServerSecretParams_GenerateDeterministic(random)
    );
  }

  readonly _nativeHandle: Native.ServerSecretParams;

  constructor(contents: Buffer | Native.ServerSecretParams) {
    if (contents instanceof Buffer) {
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

  sign(message: Buffer): NotarySignature {
    const random = randomBytes(RANDOM_LENGTH);

    return this.signWithRandom(random, message);
  }

  signWithRandom(random: Buffer, message: Buffer): NotarySignature {
    return new NotarySignature(
      Native.ServerSecretParams_SignDeterministic(this, random, message)
    );
  }

  serialize(): Buffer {
    return Native.ServerSecretParams_Serialize(this);
  }
}
