//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import * as Mp4Sanitizer from '../Mp4Sanitizer';
import * as WebpSanitizer from '../WebpSanitizer';
import { SanitizedMetadata } from '../Mp4Sanitizer';
import * as util from './util';
import { ErrorCode, LibSignalErrorBase } from '../Errors';
import { ErrorInputStream, Uint8ArrayInputStream } from './ioutil';

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
        await Mp4Sanitizer.sanitize(new ErrorInputStream(), 0n);
        assert.fail('did not throw');
      } catch (e) {
        assert(e instanceof LibSignalErrorBase);
        assert.equal(e.code, ErrorCode.IoError);
      }
    });
  });
});

describe('WebpSanitizer', () => {
  describe('sanitize', () => {
    it('throws on empty input', () => {
      const input = new Uint8Array([]);
      try {
        WebpSanitizer.sanitize(Buffer.from(input));
        assert.fail('did not throw');
      } catch (e) {
        assert(e instanceof LibSignalErrorBase);
        assert.equal(e.code, ErrorCode.InvalidMediaInput);
      }
    });

    it('throws on truncated input', () => {
      const input = new Uint8Array([0, 0, 0, 0]);
      try {
        WebpSanitizer.sanitize(Buffer.from(input));
        assert.fail('did not throw');
      } catch (e) {
        assert(e instanceof LibSignalErrorBase);
        assert.equal(e.code, ErrorCode.InvalidMediaInput);
      }
    });

    it('accepts a minimal webp', () => {
      const input = new Uint8Array(webp());
      WebpSanitizer.sanitize(Buffer.from(input));
    });
  });
});

function ftyp(): Array<number> {
  const array: number[] = [];
  return array.concat(
    [0, 0, 0, 20], // box size
    fourcc('ftyp'), // box type
    fourcc('isom'), // major_brand
    [0, 0, 0, 0], // minor_version
    fourcc('isom') // compatible_brands
  );
}

function moov(): Array<number> {
  const array: number[] = [];
  return array.concat(
    // moov box header
    [0, 0, 0, 56], // box size
    fourcc('moov'), // box type

    // trak box (inside moov box)
    [0, 0, 0, 48], // box size
    fourcc('trak'), // box type

    // mdia box (inside trak box)
    [0, 0, 0, 40], // box size
    fourcc('mdia'), // box type

    // minf box (inside mdia box)
    [0, 0, 0, 32], // box size
    fourcc('minf'), // box type

    // stbl box (inside minf box)
    [0, 0, 0, 24], // box size
    fourcc('stbl'), // box type

    // stco box (inside stbl box)
    [0, 0, 0, 16], // box size
    fourcc('stco'), // box type
    [0, 0, 0, 0], // box version & flags
    [0, 0, 0, 0] // entry count
  );
}

function mdat(): Array<number> {
  const array: number[] = [];
  return array.concat(
    // mdat box
    [0, 0, 0, 8], // box size
    fourcc('mdat') // box type
  );
}

function webp(): Array<number> {
  const array: number[] = [];
  return array.concat(
    fourcc('RIFF'), // chunk type
    [20, 0, 0, 0], // chunk size
    fourcc('WEBP'), // webp header

    fourcc('VP8L'), // chunk type
    [8, 0, 0, 0], // chunk size
    [0x2f, 0, 0, 0, 0, 0x88, 0x88, 8] // VP8L data
  );
}

function fourcc(fourccStr: string): Array<number> {
  return [
    fourccStr.charCodeAt(0),
    fourccStr.charCodeAt(1),
    fourccStr.charCodeAt(2),
    fourccStr.charCodeAt(3),
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
