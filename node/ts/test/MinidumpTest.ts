//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/* eslint-disable @typescript-eslint/require-await */

import * as Minidump from '../Minidump';

import * as fs from 'node:fs';
import * as path from 'node:path';
import { assert } from 'chai';

const GOOD_DUMP = fs.readFileSync(
  path.join(__dirname, '../../ts/test/minidump.dmp')
);

describe('Minidump', () => {
  it('parses good minidump', () => {
    type Dump = {
      system_info: {
        cpu_arch: string;
        cpu_count: number;
        cpu_info: unknown;
        cpu_microcode_version: unknown;
        os: string;
        os_ver: string;
      };
    };
    const json = Minidump.toJSONString(GOOD_DUMP);
    const dump = JSON.parse(json) as Dump;

    assert.deepEqual(dump.system_info, {
      cpu_arch: 'arm64',
      cpu_count: 12,
      cpu_info: null,
      cpu_microcode_version: null,
      os: 'Mac OS X',
      os_ver: '14.2.1 23C71',
    });
  });

  it('throws on bad minidump', () => {
    assert.throws(() => {
      Minidump.toJSONString(Buffer.alloc(1024));
    }, /Failed to parse minidump: HeaderMismatch/);
  });
});
