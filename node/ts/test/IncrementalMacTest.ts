//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import {
  DigestingWritable,
  ValidatingWritable,
  everyNthByte,
  inferChunkSize,
  chunkSizeInBytes,
} from '../incremental_mac';
import { LibSignalErrorBase } from '../Errors';

import * as stream from 'stream';

use(chaiAsPromised);

const TEST_KEY = Buffer.from(
  'a83481457efecc69ad1342e21d9c0297f71debbf5c9304b4c1b2e433c1a78f98',
  'hex'
);
const TEST_INPUT = [
  'this is a test',
  ' input to the incremental ',
  'mac stream',
];
const TEST_DIGEST = Buffer.from(
  '84892f70600e549fb72879667a9d96a273f144b698ff9ef5a76062a56061a909884f6d9f42918a9e476ed518c4ac8f714bd33f045152ae049877fd3d1b0db25a',
  'hex'
);

const CHUNK_SIZE = everyNthByte(32);

describe('Incremental MAC', () => {
  it('calculates the chunk size', () => {
    assert.equal(42, chunkSizeInBytes(inferChunkSize(42)));
    assert.equal(1024, chunkSizeInBytes(inferChunkSize(1024)));
    assert.equal(8192, chunkSizeInBytes(inferChunkSize(10 * 1024)));
    assert.equal(3276800, chunkSizeInBytes(inferChunkSize(100 * 1024 * 1024)));
  });

  describe('DigestingWritable', () => {
    it('produces the digest', async () => {
      const digesting = new DigestingWritable(TEST_KEY, CHUNK_SIZE);
      await stream.promises.pipeline(testInputStream(), digesting);
      assert.equal(
        TEST_DIGEST.toString('hex'),
        digesting.getFinalDigest().toString('hex')
      );
    });
  });

  describe('ValidatingWritable', () => {
    it('successful validation', async () => {
      const validating = new ValidatingWritable(
        TEST_KEY,
        CHUNK_SIZE,
        TEST_DIGEST
      );
      await stream.promises.pipeline(testInputStream(), validating);
      assert.isTrue(true);
    });

    it('corrupted input', async () => {
      const validating = new ValidatingWritable(
        TEST_KEY,
        CHUNK_SIZE,
        TEST_DIGEST
      );
      const badInput = ['!', ...TEST_INPUT];
      const promise = stream.promises.pipeline(
        stream.Readable.from(badInput),
        validating
      );
      await assert.isRejected(promise, LibSignalErrorBase);
    });

    it('corrupted input in finalize', async () => {
      const validating = new ValidatingWritable(
        TEST_KEY,
        CHUNK_SIZE,
        TEST_DIGEST
      );
      const badInput = [...TEST_INPUT, '!'];
      const promise = stream.promises.pipeline(
        stream.Readable.from(badInput),
        validating
      );
      await assert.isRejected(promise, LibSignalErrorBase);
    });

    it('corrupted digest', async () => {
      const badDigest = Buffer.from(TEST_DIGEST);
      badDigest[42] ^= 0xff;
      const validating = new ValidatingWritable(
        TEST_KEY,
        CHUNK_SIZE,
        badDigest
      );
      const promise = stream.promises.pipeline(
        stream.Readable.from(TEST_INPUT),
        validating
      );
      await assert.isRejected(promise, LibSignalErrorBase);
    });
  });
});

function testInputStream(): stream.Readable {
  return stream.Readable.from(TEST_INPUT);
}
