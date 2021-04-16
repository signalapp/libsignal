//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/* eslint-env es2017 */

const Benchmark = require('benchmark');

const Native = require(process.env.SIGNAL_NEON_FUTURES_TEST_LIB);

const suite = new Benchmark.Suite();
suite
  .add('await Native.incrementCallbackPromise(async () => 7)', {
    defer: true,
    fn: async deferred => {
      await Native.incrementCallbackPromise(async () => 7);
      deferred.resolve();
    },
  })
  .on('cycle', event => {
    console.log(String(event.target));
  })
  .run();
