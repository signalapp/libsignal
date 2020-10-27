//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import * as SignalClient from '../index';

describe('SignalClient', () => {
  it('can generate and serialize PrivateKeys', () => {
    const a = new SignalClient.PrivateKey();
    const b = new SignalClient.PrivateKey();
    assert.equal(a.serialize().length, 32, 'correct length');
    assert(a.serialize().equals(a.serialize()), 'repeatable');
    assert(
      !a.serialize().equals(b.serialize()),
      'different for different keys',
    );
  });
});
