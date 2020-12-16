//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import * as SignalClient from '../index';

describe('SignalClient', () => {
  it('ECC signatures work', () => {
    const priv_a = SignalClient.PrivateKey.generate();
    const priv_b = SignalClient.PrivateKey.generate();
    assert.lengthOf(priv_a.serialize(), 32, 'private key serialization length');
    assert.deepEqual(priv_a.serialize(), priv_a.serialize(), 'repeatable');
    assert.notDeepEqual(
      priv_a.serialize(),
      priv_b.serialize(),
      'different for different keys'
    );

    const pub_a = priv_a.getPublicKey();
    const pub_b = priv_b.getPublicKey();

    const msg = Buffer.from([1, 2, 3]);

    const sig_a = priv_a.sign(msg);
    assert.lengthOf(sig_a, 64, 'signature length');

    assert(pub_a.verify(msg, sig_a));
    assert(!pub_b.verify(msg, sig_a));

    const sig_b = priv_b.sign(msg);
    assert.lengthOf(sig_b, 64, 'signature length');

    assert(pub_b.verify(msg, sig_b));
    assert(!pub_a.verify(msg, sig_b));
  });

  it('ECC key agreement work', () => {
    const priv_a = SignalClient.PrivateKey.generate();
    const priv_b = SignalClient.PrivateKey.generate();

    const pub_a = priv_a.getPublicKey();
    const pub_b = priv_b.getPublicKey();

    const shared_a = priv_a.agree(pub_b);
    const shared_b = priv_b.agree(pub_a);

    assert.deepEqual(shared_a, shared_b, 'key agreement works');
  });

  it('ECC keys roundtrip through serialization', () => {
    const key = Buffer.alloc(32, 0xab);
    const priv = SignalClient.PrivateKey.deserialize(key);
    assert(key.equals(priv.serialize()));

    const pub = priv.getPublicKey();
    const pub_bytes = pub.serialize();
    assert.lengthOf(pub_bytes, 32 + 1);

    const pub2 = SignalClient.PublicKey.deserialize(pub_bytes);

    assert.deepEqual(pub.serialize(), pub2.serialize());
  });

  it('decoding invalid ECC key throws an error', () => {
    const invalid_key = Buffer.alloc(33, 0xab);

    assert.throws(() => {
      SignalClient.PrivateKey.deserialize(invalid_key);
    }, 'bad key length <33> for key with type <Djb>');

    assert.throws(() => {
      SignalClient.PublicKey.deserialize(invalid_key);
    }, 'bad key type <0xab>');
  });
});
