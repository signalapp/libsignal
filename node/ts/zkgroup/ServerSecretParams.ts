//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';
import * as Native from '../../Native';
import ByteArray from './internal/ByteArray';

import { RANDOM_LENGTH } from './internal/Constants';
import ServerPublicParams from './ServerPublicParams';
import NotarySignature from './NotarySignature';

export default class ServerSecretParams extends ByteArray {
  private readonly __type?: never;

  static generate(): ServerSecretParams {
    const random = randomBytes(RANDOM_LENGTH);

    return ServerSecretParams.generateWithRandom(random);
  }

  static generateWithRandom(random: Buffer): ServerSecretParams {
    return new ServerSecretParams(
      Native.ServerSecretParams_GenerateDeterministic(random)
    );
  }

  constructor(contents: Buffer) {
    super(contents, Native.ServerSecretParams_CheckValidContents);
  }

  getPublicParams(): ServerPublicParams {
    return new ServerPublicParams(
      Native.ServerSecretParams_GetPublicParams(this.contents)
    );
  }

  sign(message: Buffer): NotarySignature {
    const random = randomBytes(RANDOM_LENGTH);

    return this.signWithRandom(random, message);
  }

  signWithRandom(random: Buffer, message: Buffer): NotarySignature {
    return new NotarySignature(
      Native.ServerSecretParams_SignDeterministic(
        this.contents,
        random,
        message
      )
    );
  }
}
