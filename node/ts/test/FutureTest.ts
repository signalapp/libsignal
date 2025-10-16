//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import * as Native from '../Native.js';
import { ErrorCode, LibSignalError, LibSignalErrorBase } from '../Errors.js';
import { TokioAsyncContext } from '../net.js';
import { setTimeout } from 'node:timers/promises';

use(chaiAsPromised);

function makeAsyncRuntime(): Native.Wrapper<Native.NonSuspendingBackgroundThreadRuntime> {
  return {
    _nativeHandle: Native.TESTING_NonSuspendingBackgroundThreadRuntime_New(),
  };
}

class CancelCounter {
  readonly _nativeHandle: Native.TestingFutureCancellationCounter;
  constructor(initialValue: number = 0) {
    this._nativeHandle =
      Native.TESTING_FutureCancellationCounter_Create(initialValue);
  }

  public async waitForCount(context: TokioAsyncContext, target: number) {
    await Native.TESTING_FutureCancellationCounter_WaitForCount(
      context,
      this,
      target
    );
  }
}

describe('Async runtime not on the Node executor', () => {
  it('handles success', async () => {
    const runtime = makeAsyncRuntime();
    assert.equal(await Native.TESTING_FutureSuccess(runtime, 21), 42);
  });

  it('handles failure', async () => {
    try {
      const runtime = makeAsyncRuntime();
      await Native.TESTING_FutureFailure(runtime, 21);
      assert.fail('should have thrown an error');
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, LibSignalErrorBase);
      const err = e as LibSignalError;
      assert.equal(err.code, ErrorCode.Generic);
    }
  });
});

describe('TokioAsyncContext', () => {
  it('supports cancellation of running future', async () => {
    const runtime = new TokioAsyncContext(Native.TokioAsyncContext_new());
    const abortController = new AbortController();
    const counter = new CancelCounter();
    const pending = runtime.makeCancellable(
      abortController.signal,
      Native.TESTING_FutureIncrementOnCancel(runtime, counter)
    );
    const timeout = setTimeout(200, 'timed out');
    assert.equal('timed out', await Promise.race([pending, timeout]));
    abortController.abort();
    return Promise.all([
      expect(pending)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.have.property('code', ErrorCode.Cancelled),
      expect(counter.waitForCount(runtime, 1)).to.be.fulfilled,
    ]);
  });

  it('supports pre-cancellation of not-yet-running future', async () => {
    const runtime = new TokioAsyncContext(Native.TokioAsyncContext_new());
    const abortController = new AbortController();
    const counter = new CancelCounter();
    abortController.abort();
    const pending = runtime.makeCancellable(
      abortController.signal,
      Native.TESTING_FutureIncrementOnCancel(runtime, counter)
    );
    return Promise.all([
      expect(pending)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.have.property('code', ErrorCode.Cancelled),
      expect(counter.waitForCount(runtime, 1)).to.be.fulfilled,
    ]);
  });
});
