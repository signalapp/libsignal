//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, expect, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as Native from '../../Native';
import { ErrorCode, LibSignalError, LibSignalErrorBase } from '../Errors';
import { TokioAsyncContext } from '../net';
import { setTimeout } from 'timers/promises';

use(chaiAsPromised);

function makeAsyncRuntime(): Native.Wrapper<Native.NonSuspendingBackgroundThreadRuntime> {
  return {
    _nativeHandle: Native.TESTING_NonSuspendingBackgroundThreadRuntime_New(),
  };
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
    const pending = runtime.makeCancellable(
      abortController.signal,
      Native.TESTING_OnlyCompletesByCancellation(runtime)
    );
    const timeout = setTimeout(200, 'timed out');
    assert.equal('timed out', await Promise.race([pending, timeout]));
    abortController.abort();
    return expect(pending)
      .to.eventually.be.rejectedWith(LibSignalErrorBase)
      .and.have.property('code', ErrorCode.Cancelled);
  });

  it('supports pre-cancellation of not-yet-running future', async () => {
    const runtime = new TokioAsyncContext(Native.TokioAsyncContext_new());
    const abortController = new AbortController();
    abortController.abort();
    const pending = runtime.makeCancellable(
      abortController.signal,
      Native.TESTING_OnlyCompletesByCancellation(runtime)
    );
    return expect(pending)
      .to.eventually.be.rejectedWith(LibSignalErrorBase)
      .and.have.property('code', ErrorCode.Cancelled);
  });
});
