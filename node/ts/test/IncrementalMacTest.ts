//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import * as stream from 'node:stream';

import {
  chunkSizeInBytes,
  DigestingPassThrough,
  everyNthByte,
  inferChunkSize,
  ValidatingPassThrough,
} from '../incremental_mac.js';
import { ErrorCode, LibSignalErrorBase } from '../Errors.js';

import { assertArrayEquals } from './util.js';

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

describe('Incremental MAC', () => {
  describe('chunkSizeInBytes', () => {
    it('calculates the chunk size', () => {
      assert.equal(64 * 1024, chunkSizeInBytes(inferChunkSize(0)));
      assert.equal(64 * 1024, chunkSizeInBytes(inferChunkSize(42)));
      assert.equal(64 * 1024, chunkSizeInBytes(inferChunkSize(1024)));
      assert.equal(64 * 1024, chunkSizeInBytes(inferChunkSize(10 * 1024)));
      assert.equal(
        400 * 1024,
        chunkSizeInBytes(inferChunkSize(100 * 1024 * 1024))
      );
    });
  });

  describe('DigestingPassThrough', () => {
    const CHUNK_SIZE = everyNthByte(32);

    it('produces the digest', async () => {
      const digestingPassThrough = new DigestingPassThrough(
        TEST_KEY,
        CHUNK_SIZE
      );
      await stream.promises.pipeline(testInputStream(), digestingPassThrough);
      assertArrayEquals(TEST_DIGEST, digestingPassThrough.getFinalDigest());
    });
  });

  describe('ValidatingPassThrough', () => {
    const CHUNK_SIZE = everyNthByte(32);

    it('successful validation', async () => {
      const validating = new ValidatingPassThrough(
        TEST_KEY,
        CHUNK_SIZE,
        TEST_DIGEST
      );
      await stream.promises.pipeline(testInputStream(), validating);
      assert.isTrue(true);
    });

    it('corrupted input', async () => {
      const validating = new ValidatingPassThrough(
        TEST_KEY,
        CHUNK_SIZE,
        TEST_DIGEST
      );
      const badInput = ['!', ...TEST_INPUT];
      const promise = stream.promises.pipeline(
        stream.Readable.from(badInput),
        validating
      );
      const error = (await expect(promise).to.be.rejectedWith(
        LibSignalErrorBase
      )) as LibSignalErrorBase;
      assert.equal(error.code, ErrorCode.IncrementalMacVerificationFailed);
    });

    it('corrupted input in finalize', async () => {
      const validating = new ValidatingPassThrough(
        TEST_KEY,
        CHUNK_SIZE,
        TEST_DIGEST
      );
      const badInput = [...TEST_INPUT, '!'];
      const promise = stream.promises.pipeline(
        stream.Readable.from(badInput),
        validating
      );
      const error = (await expect(promise).to.be.rejectedWith(
        LibSignalErrorBase
      )) as LibSignalErrorBase;
      assert.equal(error.code, ErrorCode.IncrementalMacVerificationFailed);
    });

    it('corrupted digest', async () => {
      const badDigest = Buffer.from(TEST_DIGEST);
      badDigest[42] ^= 0xff;
      const validating = new ValidatingPassThrough(
        TEST_KEY,
        CHUNK_SIZE,
        badDigest
      );
      const promise = stream.promises.pipeline(
        stream.Readable.from(TEST_INPUT),
        validating
      );
      const error = (await expect(promise).to.be.rejectedWith(
        LibSignalErrorBase
      )) as LibSignalErrorBase;
      assert.equal(error.code, ErrorCode.IncrementalMacVerificationFailed);
    });
  });
  describe('ValidatingPassThrough', () => {
    // Use uneven chunk size to trigger buffering
    const CHUNK_SIZE = 13579;

    function toChunkedReadable(buffer: Uint8Array): stream.Readable {
      const chunked = new Array<Uint8Array>();
      for (let i = 0; i < buffer.byteLength; i += CHUNK_SIZE) {
        chunked.push(buffer.subarray(i, i + CHUNK_SIZE));
      }

      return stream.Readable.from(chunked);
    }

    it('should emit whole source stream', async () => {
      const source = randomBytes(10 * 1024 * 1024);
      const key = randomBytes(32);

      const chunkSize = inferChunkSize(source.byteLength);
      const writable = new DigestingPassThrough(key, chunkSize);
      await stream.promises.pipeline(stream.Readable.from(source), writable);

      const digest = writable.getFinalDigest();
      const validator = new ValidatingPassThrough(key, chunkSize, digest);

      const received = new Array<Buffer>();
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      validator.on('data', (chunk) => received.push(chunk));

      await Promise.all([
        stream.promises.pipeline(toChunkedReadable(source), validator),
        stream.promises.finished(validator),
      ]);

      const actual = Buffer.concat(received);
      assert.isTrue(actual.equals(source));
    });

    it('should emit error on digest mismatch', async () => {
      const source = randomBytes(10 * 1024 * 1024);
      const key = randomBytes(32);

      const chunkSize = inferChunkSize(source.byteLength);
      const writable = new DigestingPassThrough(key, chunkSize);
      await stream.promises.pipeline(stream.Readable.from(source), writable);

      const digest = writable.getFinalDigest();
      const wrongKey = randomBytes(32);
      const validator = new ValidatingPassThrough(wrongKey, chunkSize, digest);

      validator.on('data', () => {
        throw new Error('Should not be called');
      });

      const promise = stream.promises.pipeline(
        toChunkedReadable(source),
        validator
      );
      const error = (await expect(promise).to.be.rejectedWith(
        LibSignalErrorBase
      )) as LibSignalErrorBase;
      assert.equal(error.code, ErrorCode.IncrementalMacVerificationFailed);
      assert.equal(error.message, 'Corrupted input data');
    });

    it('handles an invalid digest', () => {
      const badDigest = Buffer.of(1);
      expect(
        () =>
          new ValidatingPassThrough(TEST_KEY, inferChunkSize(1000), badDigest)
      )
        .to.throw(LibSignalErrorBase)
        .with.property('code', ErrorCode.IncrementalMacVerificationFailed);
    });
  });
});

function testInputStream(): stream.Readable {
  return stream.Readable.from(TEST_INPUT);
}
