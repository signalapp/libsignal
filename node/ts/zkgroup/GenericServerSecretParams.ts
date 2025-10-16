//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';
import * as Native from '../Native.js';
import ByteArray from './internal/ByteArray.js';

import { RANDOM_LENGTH } from './internal/Constants.js';
import GenericServerPublicParams from './GenericServerPublicParams.js';

export default class GenericServerSecretParams extends ByteArray {
  private readonly __type?: never;

  static generate(): GenericServerSecretParams {
    const random = randomBytes(RANDOM_LENGTH);

    return GenericServerSecretParams.generateWithRandom(random);
  }

  static generateWithRandom(random: Uint8Array): GenericServerSecretParams {
    return new GenericServerSecretParams(
      Native.GenericServerSecretParams_GenerateDeterministic(random)
    );
  }

  constructor(contents: Uint8Array) {
    super(contents, Native.GenericServerSecretParams_CheckValidContents);
  }

  getPublicParams(): GenericServerPublicParams {
    return new GenericServerPublicParams(
      Native.GenericServerSecretParams_GetPublicParams(this.contents)
    );
  }
}
