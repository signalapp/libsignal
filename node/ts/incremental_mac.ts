//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native';
import * as stream from 'stream';
import { LibSignalErrorBase } from './Errors';

export type ChunkSizeChoice =
  | { kind: 'everyN'; n: number }
  | { kind: 'chunksOf'; dataSize: number };

export function everyNthByte(n: number): ChunkSizeChoice {
  return { kind: 'everyN', n: n };
}

export function inferChunkSize(dataSize: number): ChunkSizeChoice {
  return { kind: 'chunksOf', dataSize: dataSize };
}

export class DigestingWritable extends stream.Writable {
  _nativeHandle: Native.IncrementalMac;

  _digests: Buffer[] = [];

  constructor(key: Buffer, sizeChoice: ChunkSizeChoice) {
    super();
    this._nativeHandle = Native.IncrementalMac_Initialize(
      key,
      chunkSizeInBytes(sizeChoice)
    );
  }

  getFinalDigest(): Buffer {
    return Buffer.concat(this._digests);
  }

  _write(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/explicit-module-boundary-types
    chunk: any,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void
  ): void {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    const buffer = Buffer.from(chunk, 'binary');
    const next_digest = Native.IncrementalMac_Update(
      this,
      buffer,
      0,
      buffer.length
    );
    if (next_digest.length != 0) {
      this._digests.push(next_digest);
    }
    callback();
  }

  _final(callback: (error?: Error | null) => void): void {
    this._digests.push(Native.IncrementalMac_Finalize(this));
    callback();
  }
}

export class ValidatingWritable extends stream.Writable {
  _nativeHandle: Native.ValidatingMac;

  constructor(key: Buffer, sizeChoice: ChunkSizeChoice, digest: Buffer) {
    super();
    this._nativeHandle = Native.ValidatingMac_Initialize(
      key,
      chunkSizeInBytes(sizeChoice),
      digest
    );
  }

  _write(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/explicit-module-boundary-types
    chunk: any,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void
  ): void {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    const buffer = Buffer.from(chunk, 'binary');
    if (Native.ValidatingMac_Update(this, buffer, 0, buffer.length)) {
      callback();
    } else {
      callback(makeVerificationError('Corrupted input data'));
    }
  }

  _final(callback: (error?: Error | null) => void): void {
    if (Native.ValidatingMac_Finalize(this)) {
      callback();
    } else {
      callback(makeVerificationError('Corrupted input data (finalize)'));
    }
  }
}

export function chunkSizeInBytes(sizeChoice: ChunkSizeChoice): number {
  switch (sizeChoice.kind) {
    case 'everyN':
      return sizeChoice.n;
      break;
    case 'chunksOf':
      return Native.IncrementalMac_CalculateChunkSize(sizeChoice.dataSize);
      break;
  }
}

function makeVerificationError(message: string): LibSignalErrorBase {
  return new LibSignalErrorBase(
    message,
    'VerificationFailed',
    'incremental_mac'
  );
}
