//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect } from 'chai';
import * as util from './util';
import { Aci, Pni } from '../Address';
import * as Native from '../../Native';

util.initLogger();
config.truncateThreshold = 0;

describe('cdsi lookup', () => {
  const e164Both = '+18005551011';
  const e164Pni = '+18005551012';

  const aciUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
  const pniUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

  const aci: string = Aci.fromUuid(aciUuid).getServiceIdString();
  const pni: string = Pni.fromUuid(pniUuid).getServiceIdString();

  describe('response conversion', () => {
    it('converts to native', () => {
      const expected = new Map([
        [e164Both, { aci: aci, pni: pni }],
        [e164Pni, { aci: undefined, pni: pni }],
      ]);

      expect(Native.TESTING_CdsiLookupResponseConvert()).deep.equals(expected);
    });
  });
});
