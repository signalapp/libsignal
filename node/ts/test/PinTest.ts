//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import * as pin from '../pin';
import * as util from './util';

util.initLogger();

describe('Pin', () => {
  describe('AccountEntropyPool', () => {
    describe('generate()', () => {
      const NUM_TEST_ITERATIONS = 100;

      it('returns a unique string each time', () => {
        const generatedEntropyPools = new Set<string>();

        for (let i = 0; i < NUM_TEST_ITERATIONS; i++) {
          const pool = pin.AccountEntropyPool.generate();
          assert.isFalse(
            generatedEntropyPools.has(pool),
            `${pool} was generated twice`
          );
          generatedEntropyPools.add(pool);
        }
      });

      it('returns only strings consisting of 64 characters a-z and 0-9', () => {
        const validCharactersRegex = /^[a-z0-9]{64}$/;
        for (let i = 0; i < NUM_TEST_ITERATIONS; i++) {
          const pool = pin.AccountEntropyPool.generate();
          assert.match(
            pool,
            validCharactersRegex,
            'Pool must be 64 characters consisting of only a-z and 0-9'
          );
        }
      });
    });
  });
});
