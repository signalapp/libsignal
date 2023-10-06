//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as Native from '../../Native';
import { ErrorCode, LibSignalError, LibSignalErrorBase } from '../Errors';

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
