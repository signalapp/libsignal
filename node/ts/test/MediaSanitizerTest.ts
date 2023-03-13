//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import { InputStream } from '../io';
import * as Mp4Sanitizer from '../Mp4Sanitizer';
import { SanitizedMetadata } from '../Mp4Sanitizer';
import * as util from './util';
import { ErrorCode, LibSignalErrorBase } from '../Errors';

util.initLogger();

describe('Mp4Sanitizer', () => {
  describe('sanitize', () => {
    it('throws on empty input', async () => {
      const input = new Uint8Array([]);
      try {
        await Mp4Sanitizer.sanitize(
          new Uint8ArrayInputStream(input),
          BigInt(input.length)
        );
        assert.fail('did not throw');
      } catch (e) {
        assert(e instanceof LibSignalErrorBase);
        assert.equal(e.code, ErrorCode.InvalidMediaInput);
      }
    });

    it('throws on truncated input', async () => {
      const input = new Uint8Array([0, 0, 0, 0]);
      try {
        await Mp4Sanitizer.sanitize(
          new Uint8ArrayInputStream(input),
          BigInt(input.length)
        );
        assert.fail('did not throw');
      } catch (e) {
        assert(e instanceof LibSignalErrorBase);
        assert.equal(e.code, ErrorCode.InvalidMediaInput);
      }
    });

    it("accepts a minimal mp4 which doesn't need sanitizing", async () => {
      const metadata = ftyp().concat(moov());
      const data = new Uint8Array(metadata.concat(mdat()));
      const sanitized = await Mp4Sanitizer.sanitize(
        new Uint8ArrayInputStream(data),
        BigInt(data.length)
      );
      assertSanitizedMetadataEqual(
        sanitized,
        metadata.length,
        data.length - metadata.length,
        null
      );
    });

    it('accepts a minimal mp4 which needs sanitizing', async () => {
      const metadata = new Uint8Array(ftyp().concat(moov()));
      const data = new Uint8Array(ftyp().concat(mdat(), moov()));
      const sanitized = await Mp4Sanitizer.sanitize(
        new Uint8ArrayInputStream(data),
        BigInt(data.length)
      );
      assertSanitizedMetadataEqual(
        sanitized,
        ftyp().length,
        data.length - metadata.length,
        metadata
      );
    });

    it('propagates an io error', async () => {
      try {
        await Mp4Sanitizer.sanitize(new ErrorInputStream(), BigInt(0));
        assert.fail('did not throw');
      } catch (e) {
        assert(e instanceof LibSignalErrorBase);
        assert.equal(e.code, ErrorCode.IoError);
      }
    });
  });
});

function ftyp(): Array<number> {
  const array: number[] = [];
  return array.concat(
    [0, 0, 0, 20], // box size
    boxType('ftyp'), // box type
    boxType('isom'), // major_brand
    [0, 0, 0, 0], // minor_version
    boxType('isom') // compatible_brands
  );
}

function moov(): Array<number> {
  const array: number[] = [];
  return array.concat(
    // moov box header
    [0, 0, 0, 56], // box size
    boxType('moov'), // box type

    // trak box (inside moov box)
    [0, 0, 0, 48], // box size
    boxType('trak'), // box type

    // mdia box (inside trak box)
    [0, 0, 0, 40], // box size
    boxType('mdia'), // box type

    // minf box (inside mdia box)
    [0, 0, 0, 32], // box size
    boxType('minf'), // box type

    // stbl box (inside minf box)
    [0, 0, 0, 24], // box size
    boxType('stbl'), // box type

    // stco box (inside stbl box)
    [0, 0, 0, 16], // box size
    boxType('stco'), // box type
    [0, 0, 0, 0], // box version & flags
    [0, 0, 0, 0] // entry count
  );
}

function mdat(): Array<number> {
  const array: number[] = [];
  return array.concat(
    // mdat box
    [0, 0, 0, 8], // box size
    boxType('mdat') // box type
  );
}

function boxType(boxTypeStr: string): Array<number> {
  return [
    boxTypeStr.charCodeAt(0),
    boxTypeStr.charCodeAt(1),
    boxTypeStr.charCodeAt(2),
    boxTypeStr.charCodeAt(3),
  ];
}

function assertSanitizedMetadataEqual(
  sanitized: SanitizedMetadata,
  dataOffset: number | bigint,
  dataLen: number | bigint,
  metadata: Uint8Array | null
) {
  assert.deepEqual(sanitized.getMetadata(), metadata);
  assert.equal(sanitized.getDataOffset(), BigInt(dataOffset));
  assert.equal(sanitized.getDataLen(), BigInt(dataLen));
}

class ErrorInputStream extends InputStream {
  read(_amount: number): Promise<Buffer> {
    throw new Error('test io error');
  }
  skip(_amount: number): Promise<void> {
    throw new Error('test io error');
  }
}

class Uint8ArrayInputStream extends InputStream {
  data: Uint8Array;

  constructor(data: Uint8Array) {
    super();
    this.data = data;
  }

  read(amount: number): Promise<Buffer> {
    const read_amount = Math.min(amount, this.data.length);
    const read_data = this.data.slice(0, read_amount);
    this.data = this.data.slice(read_amount);
    return Promise.resolve(Buffer.from(read_data));
  }

  skip(amount: number): Promise<void> {
    if (amount > this.data.length) {
      throw Error('skipped past end of data');
    }
    this.data = this.data.slice(amount);
    return Promise.resolve();
  }
}
