//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { InputStream } from '../io';

export class ErrorInputStream extends InputStream {
  public static Error = class extends Error {};

  read(_amount: number): Promise<Buffer> {
    throw new ErrorInputStream.Error();
  }
  skip(_amount: number): Promise<void> {
    throw new ErrorInputStream.Error();
  }
}

export class Uint8ArrayInputStream extends InputStream {
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
