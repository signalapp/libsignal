//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/* eslint-env es2017 */

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');

const { assert, expect } = chai;
chai.use(chaiAsPromised);

const native = require(process.env.SIGNAL_NEON_FUTURES_TEST_LIB);

function promisify(operation) {
  return function() {
    return new Promise((resolve, reject) => {
      try {
        operation(...arguments, resolve);
      } catch (error) {
        reject(error);
      }
    });
  };
}

describe('native', () => {
  it('can fulfill promises', async () => {
    const result = await promisify(native.incrementAsync)(Promise.resolve(5));
    assert.equal(result, 6);
  });

  it('can handle rejection', async () => {
    const result = await promisify(native.incrementAsync)(
      Promise.reject('badness')
    );
    assert.equal(result, 'error: badness');
  });

  it("doesn't crash on bad promises", async () => {
    const result = await promisify(native.incrementAsync)({
      then: function(resolve, reject) {
        queueMicrotask(() => {
          resolve(5);
          assert.throws(() => resolve(-5), /promise fulfilled twice/);
        });
      },
    });
    assert.equal(result, 6);
  });

  it('can handle store-like callbacks', async () => {
    const result = await native.doubleNameFromStore({
      getName: () => Promise.resolve('Moxie'),
    });
    assert.equal(result, 'Moxie Moxie');
  });

  it('can handle store-like callbacks that fail', async () => {
    const promise = native.doubleNameFromStore({
      getName: () => Promise.reject('uh oh'),
    });
    await assert.isRejected(promise, /rejected: uh oh/);
  });

  it('can handle parallel store-like callbacks', async () => {
    const result = await native.doubleNameFromStoreUsingJoin({
      getName: () => Promise.resolve('Moxie'),
    });
    assert.equal(result, 'Moxie Moxie');
  });

  it('can handle parallel store-like callbacks that fail', async () => {
    const promise = native.doubleNameFromStoreUsingJoin({
      getName: () => Promise.reject('uh oh'),
    });
    await assert.isRejected(promise, /rejected: uh oh/);
  });

  describe('promises', () => {
    it('can fulfill promises', async () => {
      const result = await native.incrementPromise(Promise.resolve(5));
      assert.equal(result, 6);
    });

    it('can handle rejection', async () => {
      const promise = native.incrementPromise(Promise.reject('badness'));
      await assert.isRejected(promise, /badness/);
    });

    it('recovers from non-promises', async () => {
      assert.throws(
        () => native.incrementPromise('badness'),
        /failed to downcast .+ to object/
      );
    });
  });

  describe('panic recovery', () => {
    it('handles pre-await panics', async () => {
      const promise = native.panicPreAwait(Promise.resolve(6));
      await assert.isRejected(promise, /unexpected panic: check for this/);
    });

    it('handles callback panics', async () => {
      const promise = native.panicDuringCallback(Promise.resolve(6));
      await assert.isRejected(promise, /unexpected panic: check for this/);
    });

    it('handles post-await panics', async () => {
      const promise = native.panicPostAwait(Promise.resolve(6));
      await assert.isRejected(promise, /unexpected panic: check for this/);
    });

    it('handles fulfillment panics', async () => {
      const promise = native.panicDuringFulfill(Promise.resolve(6));
      await assert.isRejected(promise, /unexpected panic: check for this/);
    });
  });

  describe('exception recovery', () => {
    it('handles pre-await throws', async () => {
      const promise = native.throwPreAwait(Promise.resolve(6));
      await assert.isRejected(promise, /^check for this$/);
    });

    it('handles callback throws', async () => {
      const promise = native.throwDuringCallback(Promise.resolve(6));
      await assert.isRejected(promise, /^check for this$/);
    });

    it('handles post-await throws', async () => {
      const promise = native.throwPostAwait(Promise.resolve(6));
      await assert.isRejected(promise, /^check for this$/);
    });

    it('handles fulfillment throws', async () => {
      const promise = native.throwDuringFulfill(Promise.resolve(6));
      await assert.isRejected(promise, /^check for this$/);
    });
  });
});
