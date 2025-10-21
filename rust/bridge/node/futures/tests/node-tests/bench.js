//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/* eslint-env es2017 */

import Benchmark from 'benchmark';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url)
const Native = require(process.env.SIGNAL_NEON_FUTURES_TEST_LIB);

async function singleIteration() {
  await Native.incrementCallbackPromise(async () => 7);
}

if (process.env.SIGNAL_NEON_FUTURES_TEST_SMOKE_ONLY) {
  await singleIteration();
} else {
  const suite = new Benchmark.Suite();
  suite
    .add('await Native.incrementCallbackPromise(async () => 7)', {
      defer: true,
      fn: async deferred => {
        await singleIteration();
        deferred.resolve();
      },
    })
    .on('cycle', event => {
      console.log(String(event.target));
    })
    .run();
}
