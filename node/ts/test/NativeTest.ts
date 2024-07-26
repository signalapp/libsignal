//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as Native from '../../Native';

use(chaiAsPromised);

describe('Native', () => {
  it('has test-only functions', () => {
    const value = Native.test_only_fn_returns_123();
    assert.equal(value, 123);
  });
});
