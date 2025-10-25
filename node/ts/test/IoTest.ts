//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Buffer } from 'node:buffer';

import * as Native from '../Native.js';
import { Uint8ArrayInputStream } from './ioutil.js';
import { assertArrayEquals } from './util.js';

use(chaiAsPromised);

const CAPS_ALPHABET_INPUT = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ');

describe('InputStream', () => {
  it('handles reads into empty buffers', async () => {
    const input = new Uint8ArrayInputStream(CAPS_ALPHABET_INPUT);
    const output = await Native.TESTING_InputStreamReadIntoZeroLengthSlice(
      input
    );
    assertArrayEquals(output, CAPS_ALPHABET_INPUT);
  });
});
