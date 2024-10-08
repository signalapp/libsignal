//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native';
import * as stream from 'stream';
import { LibSignalErrorBase } from './Errors';

type CallbackType = (error?: Error | null) => void;

export type ChunkSizeChoice =
  | { kind: 'everyN'; n: number }
  | { kind: 'chunksOf'; dataSize: number };

export function everyNthByte(n: number): ChunkSizeChoice {
  return { kind: 'everyN', n: n };
}

export function inferChunkSize(dataSize: number): ChunkSizeChoice {
  return { kind: 'chunksOf', dataSize: dataSize };
}

/**
 * @deprecated Use the DigestingPassThrough instead
 */
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
    encoding: BufferEncoding,
    callback: CallbackType
  ): void {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    const buffer = Buffer.from(chunk, encoding);
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

  _final(callback: CallbackType): void {
    this._digests.push(Native.IncrementalMac_Finalize(this));
    callback();
  }
}

export class DigestingPassThrough extends stream.Transform {
  private digester: DigestingWritable;

  constructor(key: Buffer, sizeChoice: ChunkSizeChoice) {
    super();
    this.digester = new DigestingWritable(key, sizeChoice);

    // We handle errors coming from write/end
    this.digester.on('error', () => {
      /* noop */
    });
  }

  getFinalDigest(): Buffer {
    return this.digester.getFinalDigest();
  }

  public override _transform(
    data: Buffer,
    enc: BufferEncoding,
    callback: CallbackType
  ): void {
    this.digester.write(data, enc, (err) => {
      if (err) {
        return callback(err);
      }
      this.push(data);
      callback();
    });
  }

  public override _final(callback: CallbackType): void {
    this.digester.end((err?: Error) => {
      if (err) {
        return callback(err);
      }

      callback();
    });
  }
}

/**
 * @deprecated Use the ValidatingPassThrough instead
 */
export class ValidatingWritable extends stream.Writable {
  _nativeHandle: Native.ValidatingMac;

  _validatedBytes = 0;

  constructor(key: Buffer, sizeChoice: ChunkSizeChoice, digest: Buffer) {
    super();
    this._nativeHandle = Native.ValidatingMac_Initialize(
      key,
      chunkSizeInBytes(sizeChoice),
      digest
    );
  }

  validatedSize(): number {
    return this._validatedBytes;
  }

  _write(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/explicit-module-boundary-types
    chunk: any,
    encoding: BufferEncoding,
    callback: CallbackType
  ): void {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    const buffer = Buffer.from(chunk, encoding);
    const validBytes = Native.ValidatingMac_Update(
      this,
      buffer,
      0,
      buffer.length
    );
    if (validBytes >= 0) {
      this._validatedBytes += validBytes;
      callback();
    } else {
      callback(makeVerificationError('Corrupted input data'));
    }
  }

  _final(callback: CallbackType): void {
    const validBytes = Native.ValidatingMac_Finalize(this);
    if (validBytes >= 0) {
      this._validatedBytes += validBytes;
      callback();
    } else {
      callback(makeVerificationError('Corrupted input data (finalize)'));
    }
  }
}

export class ValidatingPassThrough extends stream.Transform {
  private validator: ValidatingWritable;
  private buffer = new Array<Buffer>();

  constructor(key: Buffer, sizeChoice: ChunkSizeChoice, digest: Buffer) {
    super();
    this.validator = new ValidatingWritable(key, sizeChoice, digest);

    // We handle errors coming from write/end
    this.validator.on('error', () => {
      /* noop */
    });
  }

  public override _transform(
    data: Buffer,
    enc: BufferEncoding,
    callback: CallbackType
  ): void {
    const start = this.validator.validatedSize();
    this.validator.write(data, enc, (err) => {
      if (err) {
        return callback(err);
      }

      this.buffer.push(data);

      const end = this.validator.validatedSize();
      const readySize = end - start;

      // Fully buffer
      if (readySize === 0) {
        return callback(null);
      }

      const { buffer } = this;
      this.buffer = [];
      let validated = 0;
      for (const chunk of buffer) {
        validated += chunk.byteLength;

        // Buffered chunk is fully validated - push it without slicing
        if (validated <= readySize) {
          this.push(chunk);
          continue;
        }

        // Validation boundary lies within the chunk, split it
        const notValidated = validated - readySize;
        this.push(chunk.subarray(0, -notValidated));
        this.buffer.push(chunk.subarray(-notValidated));

        // Technically this chunk must be the last chunk so we could break,
        // but for consistency keep looping.
      }
      callback(null);
    });
  }

  public override _final(callback: CallbackType): void {
    const start = this.validator.validatedSize();
    this.validator.end((err?: Error) => {
      if (err) {
        return callback(err);
      }

      const end = this.validator.validatedSize();
      const readySize = end - start;
      const buffer = Buffer.concat(this.buffer);
      this.buffer = [];
      if (buffer.byteLength !== readySize) {
        return callback(new Error('Stream not fully processed'));
      }
      this.push(buffer);

      callback(null);
    });
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
